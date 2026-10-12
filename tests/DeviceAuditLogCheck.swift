import Foundation
@main struct DeviceAuditLogCheck {
    static func main() throws {
        let root=URL(fileURLWithPath:CommandLine.arguments[1]);let url=root.appendingPathComponent("audit.jsonl")
        let first="{\"at\":\"2026-10-12T06:00:00+00:00\",\"event\":\"adb.command\",\"argv\":[\"adb\",\"devices\"]}\n"
        try (first+"not json\n{\"at\":").write(to:url,atomically:true,encoding:.utf8)
        let before=try Data(contentsOf:url)
        let parsed=try DeviceAuditSnapshot.load(url)
        precondition(parsed.events.count==2 && parsed.pendingLine)
        precondition(parsed.events[0].event=="adb.command" && parsed.events[0].details.contains("devices"))
        precondition(parsed.events[1].malformed && parsed.events[1].raw=="not json")
        let after=try Data(contentsOf:url);precondition(after==before)
        print("passed: parsed details, malformed lines, incomplete writes and read-only access")
        try (first+first+first).write(to:url,atomically:true,encoding:.utf8)
        let full=try DeviceAuditSnapshot.load(url)
        let tail=try DeviceAuditSnapshot.load(url,maxBytes:first.utf8.count+5,maxEvents:1)
        precondition(tail.limited && tail.events.count==1 && tail.events[0].id==full.events[2].id)
        precondition(Set(full.events.map{$0.id}).count==3)
        print("passed: bounded tail and stable event identity")
        try "".write(to:url,atomically:true,encoding:.utf8)
        let empty=try DeviceAuditSnapshot.load(url)
        precondition(empty.events.isEmpty && !empty.pendingLine)
        let link=root.appendingPathComponent("link.jsonl")
        try FileManager.default.createSymbolicLink(at:link,withDestinationURL:url)
        do {_ = try DeviceAuditSnapshot.load(link);fatalError("Symlink accepted")} catch {}
        print("passed: empty logs and symlink rejection")
    }
}
