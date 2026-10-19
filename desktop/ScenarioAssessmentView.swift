import SwiftUI
import AppKit
import CoreFoundation

private enum ScenarioAssessmentError: LocalizedError {
    case invalid
    var errorDescription: String? { "The assessment response was incomplete or did not match the selected case, evidence and question. No assessment was loaded." }
}

private struct CustomerScenario: Identifiable {
    let id: String
    let label: String
    static let all = [
        CustomerScenario(id: "messages", label: "Review messages and communications"),
        CustomerScenario(id: "whatsapp", label: "Review WhatsApp evidence"),
        CustomerScenario(id: "signal", label: "Review Signal evidence"),
        CustomerScenario(id: "files", label: "Find files and media"),
        CustomerScenario(id: "incident", label: "Reconstruct an incident"),
        CustomerScenario(id: "deleted", label: "Assess deleted-data recovery")
    ]
}

// A read-only summary of stored records. Counts are neither acquisition coverage nor findings.
private struct CustomerAssessment {
    let objective: String
    let status: String
    let scope: String
    let requirements: [[String: Any]]
    let inventory: [String: Int]
    let runs: [[String: Any]]
    let runTotal: Int
    let runsTruncated: Bool
    let gaps: [[String: Any]]
    let gapCount: Int
    let gapsTruncated: Bool
    let stateCounts: [String: Int]
    let axisCounts: [String: Int]
    let nextActions: [[String: Any]]
    let limitations: [String]

    static func count(_ value: Any?) throws -> Int {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              let result = Int(number.stringValue), result >= 0 else { throw ScenarioAssessmentError.invalid }
        return result
    }
    static func counts(_ value: Any?) throws -> [String: Int] {
        guard let values = value as? [String: Any] else { throw ScenarioAssessmentError.invalid }
        return try values.mapValues { try count($0) }
    }
    static func requiredText(_ value: Any?) throws -> String {
        guard let text = value as? String, !text.isEmpty else { throw ScenarioAssessmentError.invalid }
        return text
    }
    static func text(_ row: [String: Any], _ key: String, fallback: String = "Not recorded") -> String {
        guard let value = row[key] as? String, !value.isEmpty else { return fallback }
        return value
    }
    static func nullableText(_ value: Any?) -> Bool { value is String || value is NSNull }
    static func json(_ value: Any) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return "Unavailable" }
        return text
    }
    init(_ result: [String: Any], caseID: String, evidenceID: String, scenario: String) throws {
        guard try Self.count(result["schema_version"]) == 1,
              result["case_id"] as? String == caseID,
              result["evidence_id"] as? String == evidenceID,
              result["scenario"] as? String == scenario,
              result["run"] is NSNull,
              let requirements = result["requirements"] as? [[String: Any]], requirements.count <= 100,
              let inventory = result["inventory"] as? [String: Any],
              let analysis = result["analysis_runs"] as? [String: Any],
              let runs = analysis["items"] as? [[String: Any]], runs.count <= 1000,
              let runsTruncated = analysis["truncated"] as? Bool,
              let coverage = result["coverage"] as? [String: Any],
              let gaps = coverage["gaps"] as? [[String: Any]], gaps.count <= 1000,
              let gapsTruncated = coverage["truncated"] as? Bool,
              let nextActions = result["next_actions"] as? [[String: Any]], nextActions.count <= 100,
              let limitations = result["limitations"] as? [String], limitations.count <= 256 else { throw ScenarioAssessmentError.invalid }
        objective = try Self.requiredText(result["objective"])
        scope = try Self.requiredText(result["assessment_scope"])
        status = try Self.requiredText(result["status"])
        guard ["records_available_for_review", "no_relevant_indexed_records"].contains(status) else { throw ScenarioAssessmentError.invalid }
        var requirementIDs = Set<String>()
        for row in requirements {
            let identifier = try Self.requiredText(row["id"])
            guard requirementIDs.insert(identifier).inserted,
                  let provenance = row["provenance"] as? [String: Any],
                  let samples = row["samples"] as? [[String: Any]], samples.count <= 100,
                  row["samples_truncated"] is Bool,
                  Self.nullableText(row["first_utc"]), Self.nullableText(row["last_utc"]) else { throw ScenarioAssessmentError.invalid }
            _ = try Self.requiredText(row["label"])
            let records = try Self.count(row["record_count"])
            let dated = try Self.count(row["dated_count"])
            let undated = try Self.count(row["undated_count"])
            guard dated <= records, undated == records - dated, samples.count <= records else { throw ScenarioAssessmentError.invalid }
            for key in ["with_source_reference", "with_recorded_file_hash", "with_retained_report_reference", "without_source_reference"] {
                guard try Self.count(provenance[key]) <= records else { throw ScenarioAssessmentError.invalid }
            }
            for sample in samples {
                _ = try Self.requiredText(sample["artifact_id"])
                guard sample["evidence_id"] as? String == evidenceID else { throw ScenarioAssessmentError.invalid }
                for key in ["source_ref", "parser", "logical_path", "source_sha256"] {
                    guard Self.nullableText(sample[key]) else { throw ScenarioAssessmentError.invalid }
                }
                if !(sample["file_id"] is NSNull) { _ = try Self.count(sample["file_id"]) }
            }
        }
        var inventoryCounts: [String: Int] = [:]
        for key in ["files", "bytes", "hashes_recorded"] { inventoryCounts[key] = try Self.count(inventory[key]) }
        guard inventoryCounts["hashes_recorded"]! <= inventoryCounts["files"]! else { throw ScenarioAssessmentError.invalid }
        runTotal = try Self.count(analysis["total"])
        gapCount = try Self.count(coverage["gap_count"])
        guard runs.count <= runTotal, gaps.count <= gapCount else { throw ScenarioAssessmentError.invalid }
        for run in runs {
            for key in ["id", "engine", "status"] { _ = try Self.requiredText(run[key]) }
            _ = try Self.count(run["records"])
        }
        for action in nextActions { _ = try Self.requiredText(action["label"]) }
        self.requirements = requirements; self.inventory = inventoryCounts
        self.runs = runs; self.runsTruncated = runsTruncated
        self.gaps = gaps; self.gapsTruncated = gapsTruncated
        self.stateCounts = try Self.counts(coverage["state_counts"])
        self.axisCounts = try Self.counts(coverage["axis_counts"])
        self.nextActions = nextActions; self.limitations = limitations
    }
}

struct ScenarioAssessmentView: View {
    @ObservedObject var m: AppModel
    let initialEvidence: String
    @Environment(\.dismiss) private var dismiss
    @State private var evidence = ""
    @State private var scenario = "messages"
    @State private var assessment: CustomerAssessment?
    @State private var loading = false
    @State private var error = ""
    @State private var requestID = UUID()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Assess customer question").font(.system(size: 18, weight: .semibold))
                    Text(m.caseName).font(.caption).foregroundStyle(LawlietTheme.secondary)
                }
                Spacer()
                Button("Close") { invalidate(); dismiss() }.keyboardShortcut(.cancelAction)
            }
            Text("Review the indexed evidence available for a question. This assessment does not collect data, run parsers or answer the investigation.")
                .font(.caption).foregroundStyle(LawlietTheme.secondary)
            HStack(alignment: .bottom, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Evidence").font(.caption)
                    Picker("Evidence", selection: $evidence) {
                        Text("Select imported evidence").tag("")
                        ForEach(m.evidenceItems) { Text($0.label).tag($0.id) }
                    }.labelsHidden().accessibilityLabel("Evidence for customer question")
                }.frame(maxWidth: .infinity)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Question").font(.caption)
                    Picker("Question", selection: $scenario) { ForEach(CustomerScenario.all) { Text($0.label).tag($0.id) } }
                        .labelsHidden().accessibilityLabel("Customer question")
                }.frame(maxWidth: .infinity)
                Button("Assess") { assess() }.disabled(loading || m.busy || m.caseID.isEmpty || !m.evidenceItems.contains(where: { $0.id == evidence }))
            }
            Text("Scope: one evidence source, across its indexed analysis runs.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            Divider()
            if loading {
                VStack(spacing: 10) { ProgressView(); Text("Assessing indexed evidence…") }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if !error.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Assessment unavailable", systemImage: "exclamationmark.triangle").fontWeight(.semibold)
                    Text(error).textSelection(.enabled)
                    Text("Review the selection and choose Assess to retry.").foregroundStyle(LawlietTheme.secondary)
                    Spacer()
                }.frame(maxWidth: .infinity, alignment: .leading)
            } else if let assessment = assessment {
                assessmentResults(assessment)
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    Text(m.evidenceItems.isEmpty ? "Import evidence into this case to assess a question." : "Select evidence and a question, then choose Assess.")
                    Text("The result will show relevant record counts, source references, recorded gaps and suggested next steps.").foregroundStyle(LawlietTheme.secondary)
                    Spacer()
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }.font(.system(size: 12)).controlSize(.small).padding(20)
            .frame(width: 900, height: 650)
            .background(LawlietTheme.background).foregroundStyle(LawlietTheme.text)
            .onAppear { if m.evidenceItems.contains(where: { $0.id == initialEvidence }) { evidence = initialEvidence } }
            .onChange(of: evidence) { _ in invalidate() }
            .onChange(of: scenario) { _ in invalidate() }
            .onChange(of: m.caseID) { _ in invalidate(); evidence = "" }
            .onChange(of: m.workspace) { _ in invalidate(); evidence = "" }
            .onChange(of: m.evidenceItems.map { $0.id }) { ids in if !ids.contains(evidence) { invalidate(); evidence = "" } }
            .onDisappear { invalidate() }
    }

    private func invalidate() { requestID = UUID(); assessment = nil; error = ""; loading = false }
    private func assess() {
        guard !loading, !m.busy, !m.caseID.isEmpty, m.evidenceItems.contains(where: { $0.id == evidence }) else { return }
        let ticket = UUID(), caseID = m.caseID, workspace = m.workspace, evidenceID = evidence, question = scenario
        requestID = ticket; assessment = nil; error = ""; loading = true
        Task { @MainActor in
            guard requestID == ticket, m.caseID == caseID, m.workspace == workspace, evidence == evidenceID, scenario == question else { return }
            do {
                let result = try await m.request("scenario-assessment", ["case": caseID, "evidence": evidenceID, "scenario": question])
                guard requestID == ticket, m.caseID == caseID, m.workspace == workspace, evidence == evidenceID, scenario == question else { return }
                guard let reply = result as? [String: Any] else { throw ScenarioAssessmentError.invalid }
                assessment = try CustomerAssessment(reply, caseID: caseID, evidenceID: evidenceID, scenario: question)
            } catch {
                guard requestID == ticket, m.caseID == caseID, m.workspace == workspace, evidence == evidenceID, scenario == question else { return }
                assessment = nil; self.error = error.localizedDescription
            }
            if requestID == ticket { loading = false }
        }
    }

    @ViewBuilder private func assessmentResults(_ result: CustomerAssessment) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(result.status == "records_available_for_review" ? "Indexed records available for review" : "No relevant indexed records found").font(.system(size: 15, weight: .semibold))
                    Text(result.objective).textSelection(.enabled)
                    Text("Record availability does not establish that the question is answered. Missing indexed records do not establish that the data was absent from the phone.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                }
                HStack(spacing: 24) {
                    metric("Imported files", result.inventory["files"] ?? 0)
                    metric("Recorded file hashes", result.inventory["hashes_recorded"] ?? 0)
                    metric("Analysis runs", result.runTotal)
                    metric("Recorded gaps", result.gapCount)
                }
                Text("Recorded hashes describe the stored inventory; this assessment does not reverify file bytes.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                ForEach(result.requirements.indices, id: \.self) { index in requirementCard(result.requirements[index]) }
                if !result.gaps.isEmpty {
                    DisclosureGroup("Recorded gaps · \(result.gaps.count) shown of \(result.gapCount)") {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(result.gaps.indices, id: \.self) { index in
                                let gap = result.gaps[index]
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(CustomerAssessment.text(gap, "state").replacingOccurrences(of: "-", with: " ")).fontWeight(.medium)
                                    Text(CustomerAssessment.text(gap, "reason_code").replacingOccurrences(of: "_", with: " ")).textSelection(.enabled)
                                    Text(["axis", "source", "category", "reference"].compactMap { gap[$0] as? String }.filter { !$0.isEmpty }.joined(separator: " · ")).font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)
                                    Text("Impact on selected records: " + CustomerAssessment.text(gap, "impact_on_selected_records", fallback: "unknown")).font(.caption).foregroundStyle(LawlietTheme.secondary)
                                }
                            }
                            if result.gapsTruncated { Text("Only a bounded selection of recorded gaps is shown.").font(.caption) }
                        }.padding(.top, 6)
                    }
                }
                if !result.nextActions.isEmpty {
                    Text("Suggested next steps").fontWeight(.semibold)
                    ForEach(result.nextActions.indices, id: \.self) { index in
                        Label(CustomerAssessment.text(result.nextActions[index], "label"), systemImage: "arrow.right.circle").textSelection(.enabled)
                    }
                    Text("These are suggestions for examiner review; no action is started here.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                }
                DisclosureGroup("Analysis history · \(result.runs.count) shown of \(result.runTotal)") {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(result.runs.indices, id: \.self) { index in
                            let run = result.runs[index]
                            Text("\(CustomerAssessment.text(run, "engine")) · \(CustomerAssessment.text(run, "status"))\n\(CustomerAssessment.text(run, "id"))\nRetained run counter: \(run["records"] as? Int ?? 0) (may count newly inserted rows)").font(.caption).textSelection(.enabled)
                        }
                        if result.runsTruncated { Text("Only a bounded selection of runs is shown.").font(.caption) }
                    }.padding(.top, 6)
                }
                DisclosureGroup("Assessment scope and limitations") {
                    VStack(alignment: .leading, spacing: 7) {
                        Text(result.scope).textSelection(.enabled)
                        ForEach(result.limitations.indices, id: \.self) { Text(result.limitations[$0]).textSelection(.enabled) }
                        Text("Recorded coverage by state\n" + result.stateCounts.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: " · ")).textSelection(.enabled)
                        Text("Recorded coverage by axis\n" + result.axisCounts.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: " · ")).textSelection(.enabled)
                    }.font(.caption).foregroundStyle(LawlietTheme.secondary).padding(.top, 6)
                }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(.trailing, 8)
        }
    }

    private func metric(_ title: String, _ value: Int) -> some View {
        VStack(alignment: .leading, spacing: 3) { Text(title).font(.caption).foregroundStyle(LawlietTheme.secondary); Text(value.formatted()).font(.system(size: 15, weight: .semibold)).monospacedDigit() }
    }
    @ViewBuilder private func requirementCard(_ row: [String: Any]) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack { Text(CustomerAssessment.text(row, "label")).fontWeight(.semibold); Spacer(); Text("\(row["record_count"] as? Int ?? 0) indexed records").monospacedDigit() }
            Text("\(row["dated_count"] as? Int ?? 0) dated · \(row["undated_count"] as? Int ?? 0) undated").font(.caption)
            if let first = row["first_utc"] as? String, let last = row["last_utc"] as? String {
                Text("Indexed UTC range: \(first) → \(last)").font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)
            }
            if let provenance = row["provenance"] as? [String: Any] {
                Text("Source reference: \(provenance["with_source_reference"] as? Int ?? 0) · Recorded file hash: \(provenance["with_recorded_file_hash"] as? Int ?? 0) · Retained report reference: \(provenance["with_retained_report_reference"] as? Int ?? 0) · Without source reference: \(provenance["without_source_reference"] as? Int ?? 0)").font(.caption).foregroundStyle(LawlietTheme.secondary)
            }
            if let samples = row["samples"] as? [[String: Any]], !samples.isEmpty {
                DisclosureGroup("Supporting record references · \(samples.count) samples") {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(samples.indices, id: \.self) { index in
                            let sample = samples[index]
                            VStack(alignment: .leading, spacing: 4) {
                                Text(CustomerAssessment.text(sample, "artifact_id")).fontWeight(.medium)
                                Text("Reference type: " + CustomerAssessment.text(sample, "source_kind").replacingOccurrences(of: "-", with: " "))
                                Text("Parser: " + CustomerAssessment.text(sample, "parser"))
                                Text("Source: " + CustomerAssessment.text(sample, "source_ref"))
                                Text("File: " + CustomerAssessment.text(sample, "logical_path"))
                                Text("Recorded SHA-256: " + CustomerAssessment.text(sample, "source_sha256"))
                                if let omitted = sample["omitted_fields"] as? [String], !omitted.isEmpty { Text("Unavailable reference fields: " + omitted.joined(separator: ", ")) }
                                Button("Copy reference") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(CustomerAssessment.json(sample), forType: .string) }.controlSize(.mini)
                            }.font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                            Divider()
                        }
                        if row["samples_truncated"] as? Bool == true { Text("This sample does not include every matching record.").font(.caption) }
                    }.padding(.top, 6)
                }
            }
        }.padding(12).background(LawlietTheme.panel).cornerRadius(6)
    }
}
