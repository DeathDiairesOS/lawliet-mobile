import SwiftUI
import AppKit

enum AgentCollectionError: LocalizedError {
    case invalid
    var errorDescription: String? { "The collection response is incomplete or belongs to another case. Refresh from the intended case." }
}

enum AgentCollectionScope {
    static let profiles = ["sms-provider", "contacts-provider", "files", "triage", "trash-photos", "messages"]
    static let sharedFolders = ["DCIM", "Pictures", "Download", "Documents", "Movies", "Music"]
    static let storageLimits = [64 * 1024 * 1024, 1024 * 1024 * 1024, 5 * 1024 * 1024 * 1024, 20 * 1024 * 1024 * 1024]

    static func paths(folders: Set<String>, custom: String) -> [String] {
        let selected = sharedFolders.filter { folders.contains($0) }.map { "/sdcard/" + $0 }
        let entered = custom.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        var seen = Set<String>()
        return (selected + entered).filter { seen.insert($0).inserted }
    }

    static func pathIssue(_ paths: [String]) -> String? {
        guard !paths.isEmpty else { return "Select a folder or enter an explicit shared-storage path." }
        guard paths.count <= 10 else { return "Select at most 10 shared-storage paths." }
        for path in paths {
            let components = path.split(separator: "/", omittingEmptySubsequences: false)
            if path.count > 512 || !(path.hasPrefix("/sdcard/") || path.hasPrefix("/storage/emulated/0/")) ||
                path == "/sdcard/" || path == "/storage/emulated/0/" ||
                components.dropFirst().contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) ||
                path.range(of: "^[\\p{L}\\p{N}_ /().@+\\-]+$", options: .regularExpression) == nil {
                return "Use an explicit /sdcard/ or /storage/emulated/0/ item, without wildcards or traversal: \(path)"
            }
        }
        return nil
    }

    static func bytes(_ value: Int) -> String {
        for (size, unit) in [(1024 * 1024 * 1024, "GiB"), (1024 * 1024, "MiB"), (1024, "KiB")] where value >= size {
            return value % size == 0 ? "\(value / size) \(unit)" : String(format: "%.1f %@", Double(value) / Double(size), unit)
        }
        return "\(value) bytes"
    }
}

/// Backend responses are bound to a case before they may update the collection panel.
struct AgentCollectionPlan: Identifiable {
    static let statuses: Set<String> = ["authorized", "running", "complete", "partial", "failed", "interrupted"]
    let id: String
    let status: String
    let objective: String
    let serial: String
    let profiles: [String]
    let steps: [[String: Any]]
    let limitations: [String]
    let error: String
    let request: String
    let launchInstructions: String
    let endpointConfigured: Bool
    let endpointNote: String
    let outcome: String
    let pulls: [String]
    let maxBytes: Int?
    let maxRecords: Int?
    let timeout: Int?
    var terminal: Bool { !["authorized", "running"].contains(status) }
    var label: String { status == "authorized" ? "Ready for agent" : status == "complete" ? "Collection and parsing complete" : status.replacingOccurrences(of: "_", with: " ").capitalized }

    init(_ value: Any, caseID: String, casePath: String, expectedID: String? = nil) throws {
        guard let row = value as? [String: Any],
              row["case_id"] as? String == caseID, row["case_path"] as? String == casePath,
              let id = row["id"] as? String, !id.isEmpty,
              expectedID == nil || expectedID == id,
              let status = row["status"] as? String, Self.statuses.contains(status),
              let objective = row["objective"] as? String,
              let serial = row["serial"] as? String, !serial.isEmpty,
              let profiles = row["profiles"] as? [String], !profiles.isEmpty,
              profiles.allSatisfy({ AgentCollectionScope.profiles.contains($0) }),
              let steps = row["steps"] as? [[String: Any]] else { throw AgentCollectionError.invalid }
        self.id = id; self.status = status; self.objective = objective; self.serial = serial
        self.profiles = profiles; self.steps = steps
        limitations = row["limitations"] as? [String] ?? []
        error = row["error"] as? String ?? ""
        request = row["handoff_request"] as? String ?? ""
        launchInstructions = row["launch_instructions"] as? String ?? ""
        endpointConfigured = row["endpoint_configured"] as? Bool ?? false
        endpointNote = row["endpoint_note"] as? String ?? ""
        outcome = row["outcome"] as? String ?? "not_run"
        pulls = row["pulls"] as? [String] ?? []
        maxBytes = row["max_bytes"] as? Int
        maxRecords = row["max_records"] as? Int
        timeout = row["timeout"] as? Int
    }

    static func profileLabel(_ profile: String) -> String {
        switch profile {
        case "sms-provider": return "SMS provider"
        case "contacts-provider": return "Contacts provider"
        case "files": return "Selected shared files"
        case "triage": return "System diagnostics"
        case "trash-photos": return "Accessible Samsung Trash"
        case "messages": return "Legacy telephony backup"
        default: return profile
        }
    }
}

struct AgentCollectionView: View {
    @ObservedObject var m: AppModel
    @State private var objective = ""
    @State private var serial = ""
    @State private var examiner = ""
    @State private var sms = true
    @State private var contacts = true
    @State private var files = false
    @State private var triage = false
    @State private var trashPhotos = false
    @State private var messages = false
    @State private var sharedFolders: Set<String> = []
    @State private var pulls = ""
    @State private var maxBytes = 1024 * 1024 * 1024
    @State private var timeout = 180
    @State private var androidUser = ""
    @State private var authorized = false
    @State private var working = false
    @State private var plans: [AgentCollectionPlan] = []
    @State private var selected = ""
    @State private var plan: AgentCollectionPlan?
    @State private var error = ""
    @State private var notice = ""
    @State private var generation = UUID()
    @State private var refreshedTerminal = ""

    private var profiles: [String] { [(sms, "sms-provider"), (contacts, "contacts-provider"), (files, "files"), (triage, "triage"), (trashPhotos, "trash-photos"), (messages, "messages")].filter { $0.0 }.map { $0.1 } }
    private var selectedPaths: [String] { files ? AgentCollectionScope.paths(folders: sharedFolders, custom: pulls) : [] }
    private var pathIssue: String? { files ? AgentCollectionScope.pathIssue(selectedPaths) : nil }
    private var canCreate: Bool {
        !working && !m.busy && !m.caseID.isEmpty && authorized && !profiles.isEmpty &&
        !objective.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
        !serial.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
        !examiner.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
        pathIssue == nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Collect → parse → review").font(.headline)
            Text("Authorize a bounded Android collection. Codex uses Mulder to run the existing LAWLIET collectors; acquired evidence is preserved, parsed and added to this case automatically.")
                .font(.caption).foregroundStyle(LawlietTheme.secondary)
            if !plans.isEmpty {
                Picker("Collection", selection: $selected) {
                    Text("New collection").tag("")
                    ForEach(plans) { Text($0.objective.prefix(70) + " · " + $0.label).tag($0.id) }
                }.disabled(working || m.busy)
            }
            if let plan {
                planView(plan)
            } else if !selected.isEmpty {
                Text("Loading the selected collection…").foregroundStyle(LawlietTheme.secondary)
            } else {
                form
            }
            if working { ProgressView().controlSize(.small) }
            if !error.isEmpty { Text(error).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            if !notice.isEmpty { Text(notice).font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled) }
        }
        .task(id: m.currentCasePath) {
            let token = UUID(), path = m.currentCasePath
            generation = token; plans = []; selected = ""; plan = nil; error = ""; notice = ""; working = false; refreshedTerminal = ""
            objective = m.managementValue("objective"); examiner = m.managementValue("examiner")
            serial = ""; pulls = ""; androidUser = ""; authorized = false
            sms = true; contacts = true; files = false; triage = false; trashPhotos = false; messages = false
            sharedFolders = []; maxBytes = 1024 * 1024 * 1024; timeout = 180
            await refresh(list: true, path: path, token: token)
            while !Task.isCancelled && generation == token && m.currentCasePath == path {
                do { try await Task.sleep(nanoseconds: 3_000_000_000) } catch { break }
                if plan?.terminal == false { await refresh(list: false, path: path, token: token) }
            }
        }
        .onDisappear { generation = UUID() }
        .onChange(of: selected) { value in
            plan = nil; error = ""; notice = ""
            guard !value.isEmpty else { authorized = false; return }
            let path = m.currentCasePath, token = generation
            Task { await refresh(list: false, path: path, token: token) }
        }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("Investigation objective", text: $objective).accessibilityLabel("Collection objective")
            HStack {
                TextField("Exact Android serial", text: $serial).accessibilityLabel("Authorized Android serial")
                TextField("Examiner", text: $examiner).accessibilityLabel("Collection examiner")
            }
            HStack {
                Toggle("SMS", isOn: $sms)
                Toggle("Contacts", isOn: $contacts)
                Toggle("Shared files", isOn: $files)
                Toggle("Diagnostics", isOn: $triage)
            }
            if files {
                HStack(spacing: 6) {
                    ForEach(AgentCollectionScope.sharedFolders, id: \.self) { folder in
                        Toggle(folder, isOn: Binding(get: { sharedFolders.contains(folder) }, set: { enabled in
                            if enabled { sharedFolders.insert(folder) } else { sharedFolders.remove(folder) }
                        })).toggleStyle(.button).controlSize(.small)
                    }
                }
                Text("Selected folders use /sdcard/. Add other explicit shared paths below, one per line.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                TextEditor(text: $pulls).font(.system(size: 11, design: .monospaced)).frame(height: 48)
                    .border(.gray.opacity(0.3)).accessibilityLabel("Authorized shared file paths")
                if let issue = pathIssue { Text(issue).font(.caption).foregroundStyle(.orange) }
            }
            if triage {
                Text("Retains system logs, service diagnostics and a bug report. Raw diagnostic files remain reviewable even when their contents are not indexed.")
                    .font(.caption).foregroundStyle(LawlietTheme.secondary)
            }
            DisclosureGroup("Additional collection methods") {
                VStack(alignment: .leading, spacing: 5) {
                    Toggle("Accessible Samsung Trash photos", isOn: $trashPhotos)
                    Toggle("Legacy telephony backup · requires device confirmation", isOn: $messages)
                    Text("Trash collection reads only accessible retained items. Legacy backup support varies by Android version and can be denied or unavailable; approve the phone prompt during collection. Neither method establishes deleted-data recovery.")
                        .font(.caption).foregroundStyle(LawlietTheme.secondary)
                }
            }
            DisclosureGroup("Collection limits") {
                VStack(alignment: .leading, spacing: 5) {
                    TextField("Android user ID (blank uses device default)", text: $androidUser)
                    HStack {
                        Picker("File / diagnostic cap", selection: $maxBytes) {
                            ForEach(AgentCollectionScope.storageLimits, id: \.self) { Text(AgentCollectionScope.bytes($0)).tag($0) }
                        }
                        Picker("Command timeout", selection: $timeout) {
                            ForEach([60, 180, 300, 600, 900], id: \.self) { Text("\($0) seconds").tag($0) }
                        }
                    }
                    Text("Per profile: 1,000 provider records; providers are capped at 64 MiB. File and diagnostic limits apply separately to each selected method. Polled storage limits can overshoot. Denials, limits and parser failures remain visible.")
                        .font(.caption).foregroundStyle(LawlietTheme.secondary)
                }
            }
            Text("Scope: \(profiles.map(AgentCollectionPlan.profileLabel).joined(separator: ", ")) · \(AgentCollectionScope.bytes(maxBytes)) per file/diagnostic profile · \(timeout)s per command.")
                .font(.caption).textSelection(.enabled)
            if !selectedPaths.isEmpty {
                Text(selectedPaths.joined(separator: "\n")).font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
            }
            Text("ADB reads and bug reports can create device logs. Only selected methods are authorized; rooting, app installation, security-setting changes and private app storage are outside this plan.")
                .font(.caption).foregroundStyle(LawlietTheme.secondary)
            Toggle("I authorize these reads on this exact device for this case", isOn: $authorized)
            HStack {
                Button("Authorize collection") { create() }.disabled(!canCreate)
                Text("Saves scope locally; the agent starts execution.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            }
        }.disabled(working || m.busy)
    }

    private func planView(_ value: AgentCollectionPlan) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                if value.status == "running" { ProgressView().controlSize(.small) }
                Text(value.status == "authorized" && !value.endpointConfigured ? "Scope authorized · connection setup needed" : value.label).fontWeight(.semibold)
                Spacer()
                Button("Refresh") {
                    let path = m.currentCasePath, token = generation
                    Task { await refresh(list: false, path: path, token: token) }
                }.disabled(working || m.busy)
                Button("New collection") { selected = "" }.disabled(working || m.busy)
            }
            Text(value.objective).textSelection(.enabled)
            Text("Device: \(value.serial) · \(value.profiles.map(AgentCollectionPlan.profileLabel).joined(separator: ", "))")
                .font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)
            if let bytes = value.maxBytes, let timeout = value.timeout {
                Text("Saved limits: \(AgentCollectionScope.bytes(bytes)) per file/diagnostic profile · providers up to 64 MiB / \(value.maxRecords ?? 1000) records · \(timeout)s per command")
                    .font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)
            }
            if !value.pulls.isEmpty {
                DisclosureGroup("Selected shared paths · \(value.pulls.count)") {
                    Text(value.pulls.joined(separator: "\n")).font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                }
            }
            if !value.steps.isEmpty {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(value.steps.indices, id: \.self) { i in
                        let step = value.steps[i]
                        HStack(alignment: .top) {
                            Text(AgentCollectionPlan.profileLabel(step["profile"] as? String ?? "Collection"))
                            Spacer()
                            Text((step["status"] as? String ?? "Unknown").replacingOccurrences(of: "_", with: " ").capitalized)
                            if let count = step["records"] as? Int, !["pending", "running"].contains(step["status"] as? String ?? "") {
                                Text("\(count.formatted()) indexed records").foregroundStyle(LawlietTheme.secondary)
                            }
                            if let sourceID = step["source_id"] as? String,
                               m.sources.contains(where: { $0.id == sourceID && $0.hasResults && !$0.isCaseWide }) {
                                Button("View records") { m.dialog = nil; m.reviewSource(sourceID) }
                                    .disabled(working || m.busy || !value.terminal)
                                    .help("Open only this retained collection source")
                            }
                        }.font(.caption)
                        stepCoverage(step)
                        if let failure = step["error"] as? String, !failure.isEmpty {
                            Text(failure).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
                        }
                    }
                }.padding(8).background(LawlietTheme.panel).cornerRadius(6)
            }
            if !value.error.isEmpty { Text(value.error).font(.caption).foregroundStyle(.orange).textSelection(.enabled) }
            if value.terminal && value.outcome == "no_records" {
                Text("No records were indexed. Retained files may still contain unparsed evidence. Check collection coverage and processing; this does not establish that the phone contains no relevant data.")
                    .font(.caption).foregroundStyle(.orange)
            }
            if !value.limitations.isEmpty {
                DisclosureGroup("Collection limitations · \(value.limitations.count)") {
                    Text(value.limitations.joined(separator: "\n")).font(.caption).textSelection(.enabled)
                }
            }
            if !value.terminal {
                if !value.endpointConfigured && !value.endpointNote.isEmpty {
                    Text(value.endpointNote).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
                }
                Text("Paste the prepared request into the intended Codex chat. It checks this case binding, runs only this authorized plan, then examines the indexed results. This panel monitors the retained status; it does not launch a chat.")
                    .font(.caption).foregroundStyle(LawlietTheme.secondary)
                HStack {
                    Button("Copy agent request") { copy(value.request); notice = "Request copied. Review your Codex data policy before pasting; collection has not been started by this panel." }
                        .disabled(value.request.isEmpty || working)
                    Text("Plan \(value.id.prefix(12))").font(.caption).foregroundStyle(LawlietTheme.secondary)
                }
                Text("The connected model may receive tool results. Local collection authorization does not grant permission for an external upload.")
                    .font(.caption).foregroundStyle(LawlietTheme.secondary)
                DisclosureGroup("Connection setup and prepared request") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(value.launchInstructions.isEmpty ? "No connection instructions were returned. Do not use a server bound to another case." : value.launchInstructions)
                            .font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                        Text(value.request.isEmpty ? "No agent request is available." : value.request)
                            .font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                    }
                }
            }
            HStack {
                Button(value.steps.compactMap { $0["source_id"] as? String }.count > 1 ? "Open case results" : "Open results") {
                    openResults(value)
                }.disabled(working || m.busy || !value.terminal)
                Button("Evidence & processing") { m.dialog = nil; m.mode = "Sources" }.disabled(working || m.busy)
            }
            if value.terminal {
                Text("Results are already retained in this case. A completed collection is limited to the selected methods and available permissions; it does not establish whole-phone coverage.")
                    .font(.caption).foregroundStyle(LawlietTheme.secondary)
            }
        }
    }

    @ViewBuilder private func stepCoverage(_ step: [String: Any]) -> some View {
        if let files = step["collected_files"] as? Int, let bytes = step["collected_bytes"] as? Int {
            Text("\(files.formatted()) collected payload files · \(AgentCollectionScope.bytes(bytes))")
                .font(.caption).foregroundStyle(LawlietTheme.secondary)
        }
        if let files = step["retained_files"] as? Int, let bytes = step["retained_bytes"] as? Int {
            Text("\(files.formatted()) retained files including logs · \(AgentCollectionScope.bytes(bytes))")
                .font(.caption).foregroundStyle(LawlietTheme.secondary)
        }
        if let coverage = step["coverage"] as? [[String: Any]], !coverage.isEmpty {
            DisclosureGroup("Collection coverage · \(step["coverage_total"] as? Int ?? coverage.count)") {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(coverage.indices, id: \.self) { i in
                        let item = coverage[i]
                        Text((item["source"] as? String ?? "Source") + " · " + (item["state"] as? String ?? "Unknown").replacingOccurrences(of: "_", with: " "))
                            .textSelection(.enabled)
                        if let files = item["files"] as? Int, let bytes = item["bytes"] as? Int {
                            Text("\(files.formatted()) collected files · \(AgentCollectionScope.bytes(bytes))").foregroundStyle(LawlietTheme.secondary)
                        }
                        if let records = item["records"] as? Int {
                            Text("\(records.formatted()) reported records").foregroundStyle(LawlietTheme.secondary)
                        }
                        if let detail = item["detail"] as? String, !detail.isEmpty {
                            Text(detail).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)
                        }
                    }
                    if step["coverage_truncated"] as? Bool == true {
                        Text("Showing \(coverage.count) prioritized entries. Full coverage is retained with the collection.").foregroundStyle(LawlietTheme.secondary)
                    }
                    if let manifest = step["coverage_manifest"] as? String, !manifest.isEmpty {
                        Text("Evidence reference: \(manifest)").font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                    }
                }.font(.caption)
            }.font(.caption)
        }
        if step["profile"] as? String == "triage", !["pending", "running"].contains(step["status"] as? String ?? "") {
            Text("Diagnostics are retained as raw evidence; the indexed count does not describe all log contents.")
                .font(.caption).foregroundStyle(LawlietTheme.secondary)
        }
    }

    private func create() {
        guard canCreate else { return }
        let path = m.currentCasePath, caseID = m.caseID, token = generation
        var config: [String: Any] = ["objective": objective, "serial": serial.trimmingCharacters(in: .whitespacesAndNewlines),
            "examiner": examiner, "profiles": profiles, "pulls": selectedPaths,
            "max_records": 1000, "max_bytes": maxBytes, "timeout": timeout, "authorized": true]
        let user = androidUser.trimmingCharacters(in: .whitespacesAndNewlines)
        if !user.isEmpty {
            guard let id = Int(user), id >= 0 else { error = "Android user ID must be a non-negative integer or blank."; return }
            guard id == 0 || (!files && !trashPhotos) else { error = "Shared files and Samsung Trash use owner-user paths. Choose user 0, or use a separate provider-only plan."; return }
            config["android_user"] = id
        }
        working = true; error = ""; notice = ""
        Task {
            do {
                let response = try await m.request("agent-collection-create", ["case": caseID, "config": config])
                guard valid(path, token) else { return }
                let result = try AgentCollectionPlan(response, caseID: caseID, casePath: path)
                plans.append(result); selected = result.id; plan = result
                notice = "Collection scope saved. Copy the agent request to start through Mulder."
            } catch { if valid(path, token) { self.error = error.localizedDescription } }
            if valid(path, token) { working = false }
        }
    }

    private func refresh(list: Bool, path: String, token: UUID) async {
        guard valid(path, token), !working, !m.busy else { return }
        let caseID = m.caseID
        working = true
        defer { if valid(path, token) { working = false } }
        do {
            if list {
                let response = try await m.request("agent-collection-list", ["case": caseID])
                guard valid(path, token) else { return }
                guard let rows = response as? [[String: Any]] else { throw AgentCollectionError.invalid }
                plans = try rows.map { try AgentCollectionPlan($0, caseID: caseID, casePath: path) }
                if selected.isEmpty { selected = plans.first?.id ?? "" }
            }
            guard !selected.isEmpty else { return }
            let id = selected
            let response = try await m.request("agent-collection-status", ["case": caseID, "plan_id": id])
            guard valid(path, token), selected == id else { return }
            let result = try AgentCollectionPlan(response, caseID: caseID, casePath: path, expectedID: id)
            plan = result
            if let i = plans.firstIndex(where: { $0.id == id }) { plans[i] = result }
            error = ""
            refreshCaseIfComplete(result, path: path, token: token)
        } catch { if valid(path, token) { self.error = error.localizedDescription } }
    }

    private func refreshCaseIfComplete(_ result: AgentCollectionPlan, path: String, token: UUID) {
        let key = result.id + ":" + result.status
        guard result.terminal, refreshedTerminal != key, !m.busy else { return }
        m.perform("Loading collected evidence…") {
            guard valid(path, token) else { return }
            try await m.loadCase()
            if valid(path, token) { refreshedTerminal = key }
        }
    }

    private func openResults(_ result: AgentCollectionPlan) {
        let sourceIDs = result.steps.compactMap { $0["source_id"] as? String }
        m.dialog = nil
        if sourceIDs.count > 1, let source = m.sources.first(where: { $0.isCaseWide && $0.hasResults }) {
            m.reviewSource(source.id)
        } else if let source = m.sources.first(where: { sourceIDs.contains($0.id) && $0.hasResults && !$0.isCaseWide }) {
            m.reviewSource(source.id)
        } else { m.mode = "Sources" }
    }
    private func valid(_ path: String, _ token: UUID) -> Bool { generation == token && m.currentCasePath == path }
    private func copy(_ text: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string) }
}
