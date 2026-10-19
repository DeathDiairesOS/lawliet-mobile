import SwiftUI

// The view is compiled against the same small surface it uses in the real app.
// No subprocess, physical device, model or application window is opened.
struct CollectionCheckSource {
    let id: String
    let hasResults: Bool
    let isCaseWide: Bool
}
@MainActor final class AppModel: ObservableObject {
    var currentCasePath = "/synthetic/cases/CASE-1"
    var caseID = "CASE-1"
    var busy = false
    var dialog: String?
    var mode = "Sources"
    var sources: [CollectionCheckSource] = []
    func managementValue(_ key: String) -> String { "" }
    func request(_ action: String, _ values: [String: Any]) async throws -> Any { [:] }
    func perform(_ message: String, _ job: @escaping @MainActor () async throws -> Void) { }
    func loadCase() async throws { }
    func reviewSource(_ id: String) { }
}

@main struct AgentCollectionViewCheck {
    static func main() throws {
        var row: [String: Any] = ["id": "plan-1", "case_id": "CASE-1", "case_path": "/synthetic/cases/CASE-1",
            "status": "authorized", "objective": "Find the seeded message", "serial": "TEST-ANDROID",
            "profiles": ["sms-provider"], "steps": [["profile": "sms-provider", "status": "pending", "records": 0]],
            "handoff_request": "Retained request text", "launch_instructions": "Retained setup instructions"]
        func decode(_ row: [String: Any], expected: String? = "plan-1") throws -> AgentCollectionPlan {
            try AgentCollectionPlan(row, caseID: "CASE-1", casePath: "/synthetic/cases/CASE-1", expectedID: expected)
        }
        func reject(_ row: [String: Any], expected: String? = "plan-1") {
            do { _ = try decode(row, expected: expected); fatalError("Accepted a mismatched or incomplete response") }
            catch AgentCollectionError.invalid { }
            catch { fatalError("Unexpected error: \(error)") }
        }
        let authorized = try decode(row)
        precondition(!authorized.terminal && authorized.request == "Retained request text")
        precondition(authorized.launchInstructions == "Retained setup instructions")
        print("passed: authorized scope retains exact handoff without marking execution complete")

        for (key, value) in [("case_id", "CASE-2"), ("case_path", "/other/cases/CASE-1"), ("id", "plan-2")] {
            var changed = row; changed[key] = value; reject(changed)
        }
        reject(row, expected: "another-plan")
        print("passed: case path, case identifier and selected plan must all match")

        for key in ["id", "case_id", "case_path", "status", "objective", "serial", "profiles", "steps"] {
            var changed = row; changed.removeValue(forKey: key); reject(changed)
        }
        var changed = row; changed["status"] = "almost_done"; reject(changed)
        changed = row; changed["profiles"] = ["root-device"]; reject(changed)
        changed = row; changed["profiles"] = [String](); reject(changed)
        print("passed: incomplete or unsupported responses cannot become trusted UI state")

        for status in ["complete", "partial", "failed", "interrupted"] {
            row["status"] = status; row["error"] = "Provider denied access"
            row["outcome"] = "no_records"; row["limitations"] = ["No private application storage collected"]
            let result = try decode(row)
            precondition(result.terminal && result.status == status && result.outcome == "no_records")
            precondition(result.error == "Provider denied access" && result.limitations.count == 1)
        }
        row["status"] = "running"
        let running = try decode(row)
        precondition(!running.terminal)
        print("passed: failures, partial outcomes and empty results retain their true status")

        row["endpoint_configured"] = false; row["endpoint_note"] = "Configure the case-bound endpoint first"
        let setup = try decode(row)
        precondition(!setup.endpointConfigured && setup.endpointNote == "Configure the case-bound endpoint first")
        print("passed: missing endpoint remains explicit")

        row["profiles"] = AgentCollectionScope.profiles
        row["pulls"] = ["/sdcard/DCIM", "/sdcard/Documents"]
        row["max_bytes"] = 5 * 1024 * 1024 * 1024
        row["max_records"] = 1000
        row["timeout"] = 300
        row["steps"] = [["profile": "triage", "status": "complete", "records": 449,
            "retained_files": 9, "retained_bytes": 8192,
            "coverage": [["source": "bugreport", "state": "collected", "files": 1, "bytes": 4096]],
            "coverage_total": 1, "coverage_truncated": false, "coverage_manifest": "acquisition/coverage.json"]]
        let expanded = try decode(row)
        precondition(expanded.profiles.count == 6 && expanded.pulls == ["/sdcard/DCIM", "/sdcard/Documents"])
        precondition(expanded.maxBytes == 5 * 1024 * 1024 * 1024 && expanded.timeout == 300 && expanded.maxRecords == 1000)
        precondition(expanded.steps[0]["retained_files"] as? Int == 9 && expanded.steps[0]["records"] as? Int == 449)
        precondition(AgentCollectionPlan.profileLabel("triage") == "System diagnostics")
        precondition(AgentCollectionPlan.profileLabel("messages") == "Legacy telephony backup")
        precondition(AgentCollectionPlan.profileLabel("trash-photos") == "Accessible Samsung Trash")
        print("passed: six methods retain exact scope, caps, coverage and distinct indexed / file counts")

        let paths = AgentCollectionScope.paths(folders: ["DCIM", "Documents"], custom: " /sdcard/DCIM\n/storage/emulated/0/Pictures\n\n")
        precondition(paths == ["/sdcard/DCIM", "/sdcard/Documents", "/storage/emulated/0/Pictures"])
        precondition(AgentCollectionScope.pathIssue(paths) == nil)
        for invalid in ["/sdcard/", "/storage/emulated/0/", "/sdcard/../private", "/sdcard/DCIM/*", "/data/data/app", "/sdcard//DCIM", "/sdcard/DCIM/", "/sdcard/./DCIM"] {
            precondition(AgentCollectionScope.pathIssue([invalid]) != nil, invalid)
        }
        precondition(AgentCollectionScope.pathIssue([]) != nil)
        precondition(AgentCollectionScope.pathIssue((1...11).map { "/sdcard/item\($0)" }) != nil)
        precondition(AgentCollectionScope.bytes(64 * 1024 * 1024) == "64 MiB")
        precondition(AgentCollectionScope.bytes(20 * 1024 * 1024 * 1024) == "20 GiB")
        precondition(AgentCollectionScope.storageLimits.max() == 20 * 1024 * 1024 * 1024)
        print("passed: folder selection is explicit, deduplicated, bounded and rejects unsafe paths")
    }
}
