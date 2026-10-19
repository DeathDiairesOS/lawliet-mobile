import SwiftUI
import AppKit
import CoreFoundation

private enum MVTViewError: LocalizedError {
    case invalid
    var errorDescription: String? { "The MVT response was incomplete or did not match this case and selection." }
}
private enum MVTValue {
    static func text(_ value: Any?) -> String { value as? String ?? "Not recorded" }
    static func count(_ value: Any?) throws -> Int {
        guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), let i = Int(n.stringValue), i >= 0 else { throw MVTViewError.invalid }
        return i
    }
    static func object(_ value: Any, caseID: String? = nil, evidence: String? = nil) throws -> [String: Any] {
        guard let row = value as? [String: Any], try count(row["schema_version"]) == 1 else { throw MVTViewError.invalid }
        if let caseID, row["case_id"] as? String != caseID { throw MVTViewError.invalid }
        if let evidence, row["evidence_id"] as? String != evidence { throw MVTViewError.invalid }
        return row
    }
    static func json(_ value: Any?) -> String {
        guard let value, let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed]), let text = String(data: data, encoding: .utf8) else { return "Unavailable" }
        return text
    }
}
private struct MVTBundle: Identifiable {
    let id: String; let label: String; let records: Int
    init(_ row: [String: Any]) throws {
        guard let id = row["evidence_id"] as? String, !id.isEmpty, let label = row["label"] as? String else { throw MVTViewError.invalid }
        self.id = id; self.label = label; records = try MVTValue.count(row["records"])
    }
}
private struct MVTObservation: Identifiable {
    let id: String; let title: String; let preview: String
    let summary: MVTObservationSummary
    init(_ row: [String: Any], evidence: String) throws {
        guard let id = row["id"] as? String, !id.isEmpty, row["evidence_id"] as? String == evidence,
              let title = row["title"] as? String, let preview = row["preview"] as? String, preview.count <= 400 else { throw MVTViewError.invalid }
        self.id = id; self.title = title; self.preview = preview
        summary = MVTObservationSummary(row["display"])
    }
}

struct MVTReviewView: View {
    @ObservedObject var m: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var bundles: [MVTBundle] = []
    @State private var evidence = ""
    @State private var preview: [String: Any]?
    @State private var previewPath = ""
    @State private var bindConfirmed = false
    @State private var summary: [String: Any]?
    @State private var observations: [MVTObservation] = []
    @State private var selected: String?
    @State private var detail: [String: Any]?
    @State private var query = ""
    @State private var appliedQuery = ""
    @State private var offset = 0
    @State private var total = 0
    @State private var more = false
    @State private var busy = false
    @State private var error = ""
    @State private var notice = ""
    @State private var note = ""
    @State private var examiner = ""
    @State private var token = UUID()
    @State private var detailToken = UUID()
    @State private var changedCasePath: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("MVT evidence review").font(.system(size: 18, weight: .semibold))
                    Text("Case: " + m.caseName).font(.caption).foregroundStyle(LawlietTheme.secondary)
                }
                Spacer()
                Button("Choose retained output…") { choose() }.disabled(busy || m.busy || m.caseID.isEmpty)
                Button("Refresh") { reload() }.disabled(busy || m.busy)
                Button("Close") { close() }.disabled(busy).keyboardShortcut(.cancelAction)
            }
            Text("Review retained Android MVT observations. No tool, model or device is started here. Empty results cannot exclude compromise.")
                .font(.caption).foregroundStyle(LawlietTheme.secondary)
            Text("Counts are output observations; the same match may appear in multiple reports. Upstream levels are tool labels, not LAWLIET verdicts.")
                .font(.caption).foregroundStyle(LawlietTheme.secondary)
            if let preview {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Import preview · " + MVTValue.text(preview["upstream_case_id"])).fontWeight(.semibold)
                    Text(previewPath).font(.caption).textSelection(.enabled).lineLimit(2)
                    Text("\(preview["records"] as? Int ?? 0) reviewable records · \(preview["files"] as? Int ?? 0) retained files · MVT \(MVTValue.text(preview["version"]))")
                    Text("Source case “\(MVTValue.text(preview["upstream_case_id"]))” will be associated with LAWLIET case “\(m.caseID)”. The source bundle is copied and hashed.").font(.caption)
                    Toggle("I confirm this source belongs in the selected case", isOn: $bindConfirmed)
                    HStack {
                        Button("Import reviewed output") { importBundle() }.disabled(busy || !bindConfirmed)
                        Button("Cancel preview") { self.preview = nil; previewPath = ""; bindConfirmed = false }.disabled(busy)
                    }
                }.padding(10).background(LawlietTheme.panel).cornerRadius(7)
            }
            HStack {
                Picker("Imported output", selection: $evidence) {
                    Text("Select imported MVT output").tag("")
                    ForEach(bundles) { Text($0.label + " · \($0.records) records").tag($0.id) }
                }.disabled(busy).accessibilityLabel("Imported MVT output")
                TextField("Search MVT record values", text: $query).onSubmit { loadPage(0) }.disabled(evidence.isEmpty || busy)
                Button("Search") { loadPage(0) }.disabled(evidence.isEmpty || busy)
            }
            if busy { ProgressView("Loading retained evidence…").controlSize(.small) }
            if !error.isEmpty { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            if !notice.isEmpty { Text(notice).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled) }
            if let summary { summaryView(summary) }
            HSplitView {
                VStack(alignment: .leading, spacing: 5) {
                    if observations.isEmpty {
                        Text(evidence.isEmpty ? "Choose retained output or select a previously imported bundle." : "No matching indexed observations. Review execution errors and module counts above.")
                            .foregroundStyle(LawlietTheme.secondary).padding(12)
                        Spacer()
                    } else {
                        List(selection: $selected) {
                            ForEach(observations) { row in
                                VStack(alignment: .leading, spacing: 4) {
                                    if row.summary.available {
                                        Text(row.summary.message ?? row.title).fontWeight(.medium).lineLimit(2)
                                        if !row.summary.context.isEmpty { Text(row.summary.context).foregroundStyle(LawlietTheme.secondary).lineLimit(3) }
                                        if row.summary.message != nil { Text(row.title).font(.caption).foregroundStyle(LawlietTheme.secondary).lineLimit(1) }
                                    } else {
                                        Text(row.title).fontWeight(.medium).lineLimit(1)
                                        Text(row.preview).foregroundStyle(LawlietTheme.secondary).lineLimit(3)
                                    }
                                }.padding(.vertical, 3).frame(maxWidth: .infinity, alignment: .leading)
                                    .tag(row.id)
                            }
                        }
                    }
                    HStack {
                        Button("Previous") { loadPage(max(0, offset - 50)) }.disabled(busy || offset == 0 || query != appliedQuery)
                        Spacer()
                        Text("\(total == 0 ? 0 : offset + 1)–\(offset + observations.count) of \(total)").font(.caption)
                        Spacer()
                        Button("Next") { loadPage(offset + 50) }.disabled(busy || !more || query != appliedQuery)
                    }
                }.frame(minWidth: 340)
                ScrollView {
                    VStack(alignment: .leading, spacing: 9) {
                        if let detail {
                            Text("Verified retained output record").fontWeight(.semibold)
                            Text(MVTValue.text(detail["source_file"]) + " · JSON record \(detail["source_record_index"] as? Int ?? 0) (zero-based)").textSelection(.enabled)
                            Text("This verifies parser output bytes; it does not authenticate the original phone artifact or establish compromise.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                            DisclosureGroup("Source references and hashes") {
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(MVTValue.text(detail["source_ref"])).textSelection(.enabled)
                                    Text("Retained JSON SHA-256: " + MVTValue.text(detail["source_sha256"])).textSelection(.enabled)
                                    Text("Execution receipt: " + MVTValue.text(detail["receipt_source_ref"])).textSelection(.enabled)
                                    Text("Receipt SHA-256: " + MVTValue.text(detail["receipt_sha256"])).textSelection(.enabled)
                                    Button("Copy source citation") { copyCitation(detail) }
                                }.font(.system(size: 11, design: .monospaced))
                            }
                            Text("Original JSON values").fontWeight(.medium)
                            Text(MVTValue.json(detail["original"])).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                            Divider()
                            Text("Examiner finding").fontWeight(.medium)
                            TextField("Examiner label", text: $examiner)
                            TextEditor(text: $note).frame(minHeight: 65, maxHeight: 95).border(LawlietTheme.secondary.opacity(0.25))
                            Text("Separate your interpretation from the observed values. Saving does not approve a report.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                            Button("Save finding with source") { saveFinding() }
                                .disabled(busy || note.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || note.count > 20000 || examiner.count > 200)
                        } else {
                            Text("Select a record to verify its retained JSON file and execution receipt.").foregroundStyle(LawlietTheme.secondary)
                        }
                    }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                }.frame(minWidth: 360)
            }
        }.font(.system(size: 12)).controlSize(.small).padding(18)
            .frame(width: 1000, height: 760)
            .background(LawlietTheme.background).foregroundStyle(LawlietTheme.text)
            .onAppear { reload() }
            .onChange(of: evidence) { _ in loadPage(0) }
            .onChange(of: selected) { _ in loadRecord() }
            .onChange(of: m.currentCasePath) { _ in invalidate(); bundles = []; evidence = ""; preview = nil; previewPath = ""; reload() }
            .onDisappear { invalidate() }
    }

    private func summaryView(_ value: [String: Any]) -> some View {
        let receipt = value["receipt"] as? [String: Any] ?? [:]
        let errors = receipt["errors"] as? [[String: Any]] ?? []
        let issues = value["import_issues"] as? [[String: Any]] ?? []
        return VStack(alignment: .leading, spacing: 5) {
            Text("Execution: \(MVTValue.text(receipt["execution_state"])) · \(value["records"] as? Int ?? 0) imported observations · \(errors.count) execution diagnostics · \(issues.count) import issues")
            Text("Module completion unverified · IOC matching requested: \((receipt["ioc_matching_requested"] as? Bool == true) ? "Yes" : "No") · source unchanged reported: \((receipt["source_unchanged"] as? Bool == true) ? "Yes" : "No")")
                .font(.caption).foregroundStyle(LawlietTheme.secondary)
            DisclosureGroup("Execution limitations, module counts and errors") {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        Text((value["limitations"] as? [String] ?? []).joined(separator: "\n"))
                        Text(MVTValue.json(["execution_receipt": receipt, "modules": value["modules"] ?? [], "import_issues": issues]))
                            .font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }.frame(maxHeight: 140)
            }
        }.padding(8).background(LawlietTheme.panel).cornerRadius(6)
    }

    private func invalidate() {
        token = UUID(); detailToken = UUID(); busy = false; detail = nil; summary = nil
        observations = []; selected = nil; error = ""; notice = ""; note = ""; changedCasePath = nil
    }
    private func close() {
        guard !busy else { return }
        let path = m.currentCasePath
        let refresh = changedCasePath == path && !m.busy
        invalidate(); dismiss()
        if refresh {
            m.perform("Refreshing case after MVT review…") {
                guard m.currentCasePath == path else { return }
                try await m.loadCase()
            }
        }
    }
    private func run(_ operation: @escaping (String, String, UUID) async throws -> Void) {
        let id = UUID(), caseID = m.caseID, path = m.currentCasePath
        token = id; error = ""; notice = ""; busy = true
        Task { @MainActor in
            do {
                guard valid(path, id) else { return }
                try await operation(caseID, path, id)
            }
            catch { if token == id && m.currentCasePath == path { self.error = error.localizedDescription } }
            if token == id && m.currentCasePath == path { busy = false }
        }
    }
    private func valid(_ path: String, _ id: UUID) -> Bool { token == id && m.currentCasePath == path }
    private func reload(select: String? = nil) {
        guard !m.caseID.isEmpty else { return }
        run { caseID, path, id in
            let response = try MVTValue.object(await m.request("mvt-list", ["case": caseID]), caseID: caseID)
            guard valid(path, id) else { return }
            guard let rows = response["bundles"] as? [[String: Any]], rows.count <= 200 else { throw MVTViewError.invalid }
            bundles = try rows.map(MVTBundle.init)
            if let select { evidence = select }
            else if !bundles.contains(where: { $0.id == evidence }) { evidence = bundles.first?.id ?? "" }
            else if !evidence.isEmpty { loadPage(0) }
            if response["truncated"] as? Bool == true { notice = "Showing the 200 most recent imported MVT runs." }
        }
    }
    private func choose() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = true; panel.canChooseFiles = false
        panel.message = "Select one retained run_mvt_android output folder containing its retention manifest and execution receipt."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let selectedPath = url.path; preview = nil; bindConfirmed = false
        run { caseID, path, id in
            let reply = try MVTValue.object(await m.request("mvt-preview", ["case": caseID, "path": selectedPath]))
            guard valid(path, id) else { return }
            guard reply["manifest_sha256"] is String, reply["upstream_case_id"] is String, reply["receipt"] is [String: Any] else { throw MVTViewError.invalid }
            _ = try MVTValue.count(reply["records"]); _ = try MVTValue.count(reply["files"])
            previewPath = selectedPath; preview = reply
        }
    }
    private func importBundle() {
        guard let preview, bindConfirmed, let hash = preview["manifest_sha256"] as? String, let upstream = preview["upstream_case_id"] as? String else { return }
        let source = previewPath
        run { caseID, path, id in
            let reply = try MVTValue.object(await m.request("mvt-import", ["case": caseID, "path": source, "expected_manifest_sha256": hash, "expected_upstream_case_id": upstream]), caseID: caseID)
            guard valid(path, id), let eid = reply["evidence_id"] as? String else { return }
            changedCasePath = path
            self.preview = nil; previewPath = ""; bindConfirmed = false; reload(select: eid)
        }
    }
    private func loadPage(_ start: Int) {
        detailToken = UUID(); detail = nil; selected = nil; note = ""; summary = nil; observations = []
        guard !evidence.isEmpty else { return }
        let eid = evidence, search = query
        run { caseID, path, id in
            let reply = try MVTValue.object(await m.request("mvt-review", ["case": caseID, "evidence": eid, "query": search, "offset": start, "limit": 50]), caseID: caseID, evidence: eid)
            guard valid(path, id), evidence == eid else { return }
            guard let rows = reply["records"] as? [[String: Any]], rows.count <= 50,
                  let summaryValue = reply["summary"] as? [String: Any], let hasMore = reply["has_more"] as? Bool else { throw MVTViewError.invalid }
            let count = try MVTValue.count(reply["total"]), position = try MVTValue.count(reply["offset"])
            guard position == start, rows.count <= count else { throw MVTViewError.invalid }
            observations = try rows.map { try MVTObservation($0, evidence: eid) }
            total = count; offset = start; more = hasMore; appliedQuery = search; summary = summaryValue
        }
    }
    private func loadRecord() {
        detailToken = UUID(); detail = nil; note = ""
        guard let aid = selected, !evidence.isEmpty else { return }
        let id = detailToken, eid = evidence, caseID = m.caseID, path = m.currentCasePath
        Task { @MainActor in
            do {
                let reply = try MVTValue.object(await m.request("mvt-record", ["case": caseID, "evidence": eid, "artifact_id": aid]), caseID: caseID, evidence: eid)
                guard detailToken == id, m.currentCasePath == path, selected == aid, evidence == eid else { return }
                guard reply["artifact_id"] as? String == aid, reply["source_verified"] as? Bool == true else { throw MVTViewError.invalid }
                _ = try MVTValue.count(reply["source_record_index"]); detail = reply
            } catch { if detailToken == id && m.currentCasePath == path { self.error = error.localizedDescription } }
        }
    }
    private func copyCitation(_ detail: [String: Any]) {
        let citation = MVTValue.text(detail["source_ref"]) + "\nRetained MVT JSON SHA-256: " + MVTValue.text(detail["source_sha256"]) + "\nExecution receipt: " + MVTValue.text(detail["receipt_source_ref"]) + "\nReceipt SHA-256: " + MVTValue.text(detail["receipt_sha256"])
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(citation, forType: .string)
    }
    private func saveFinding() {
        guard detail != nil, let aid = selected else { return }
        let eid = evidence, savedNote = note, savedExaminer = examiner
        run { caseID, path, id in
            let verified = try MVTValue.object(await m.request("mvt-record", ["case": caseID, "evidence": eid, "artifact_id": aid]), caseID: caseID, evidence: eid)
            guard valid(path, id), selected == aid, verified["source_verified"] as? Bool == true else { return }
            _ = try await m.request("finding-add", ["case": caseID, "artifact_id": aid, "note": savedNote, "examiner": savedExaminer])
            guard valid(path, id) else { return }
            changedCasePath = path
            note = ""; notice = "Finding saved with its retained-source snapshot. Review it in Saved findings before reporting."
        }
    }
}
