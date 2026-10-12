import Foundation
import CryptoKit

actor PreviewProbe {
    var calls=[String](),active=0,maximum=0
    var hold=false;var gate:CheckedContinuation<Void,Never>?
    let receipts:[String:VerifiedPreviewReceipt]
    init(_ receipts:[String:VerifiedPreviewReceipt],hold:Bool=false){self.receipts=receipts;self.hold=hold}
    func load(_ key:InlineMediaKey) async throws -> VerifiedPreviewReceipt {
        active+=1;maximum=max(maximum,active);calls.append(key.artifactID)
        if hold {hold=false;await withCheckedContinuation{gate=$0}}
        try await Task.sleep(nanoseconds:5_000_000)
        active-=1
        return receipts[key.caseID]!
    }
    func release(){gate?.resume();gate=nil}
    func count()->Int {calls.count}
}

@main struct Check {
    @MainActor static func main() async throws {
        let root=URL(fileURLWithPath:CommandLine.arguments[1]),asset=URL(fileURLWithPath:CommandLine.arguments[2])
        let data=try Data(contentsOf:asset),hash=SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()
        var receipts=[String:VerifiedPreviewReceipt]()
        for id in ["A","B"] {
            let dir=root.appendingPathComponent(id+"/previews");try FileManager.default.createDirectory(at:dir,withIntermediateDirectories:true)
            let file=dir.appendingPathComponent(hash+".png");try data.write(to:file)
            receipts[id]=try VerifiedPreviewReceipt(["path":file.path,"mime":"image/png","sha256":hash,"bytes":data.count])
        }
        func expectCount(_ probe:PreviewProbe,_ value:Int) async {let count=await probe.count();precondition(count==value)}
        func key(_ id:String,_ artifact:String)->InlineMediaKey {InlineMediaKey(workspace:root.path,caseID:id,artifactID:artifact,fingerprint:hash,expectedHash:hash)}
        let a=key("A","one"),b=key("A","two")
        let probe=PreviewProbe(receipts),cache=InlineMediaCache(loader:{try await probe.load($0)})
        cache.setScope(a.casePath);cache.attach(a);cache.attach(a);cache.attach(b)
        await cache.waitUntilIdle()
        await expectCount(probe,2)
        let maximum=await probe.maximum;precondition(maximum==1)
        guard case .ready(let image)?=cache.states[a] else {fatalError("image not rendered")}
        precondition(image.image.width<=256 && image.image.height<=256)
        cache.detach(a);cache.attach(a);await cache.waitUntilIdle();await expectCount(probe,2)
        print("deduplicated requests, serial execution, bounded image decode and cache reuse")

        let pausedProbe=PreviewProbe(receipts),paused=InlineMediaCache(loader:{try await pausedProbe.load($0)})
        paused.pause(true);paused.attach(a);paused.attach(b);paused.detach(b)
        await expectCount(pausedProbe,0);paused.pause(false);await paused.waitUntilIdle()
        await expectCount(pausedProbe,1);precondition(paused.states[b]==nil)
        print("foreground pause and unseen queued-image cancellation")

        let held=PreviewProbe(receipts,hold:true),scoped=InlineMediaCache(loader:{try await held.load($0)})
        scoped.setScope(a.casePath);scoped.attach(a)
        for _ in 0..<100 {if await held.count()>0 {break};try await Task.sleep(nanoseconds:1_000_000)}
        await expectCount(held,1)
        let other=key("B","one");scoped.setScope(other.casePath);scoped.attach(other);await held.release();await scoped.waitUntilIdle()
        precondition(scoped.states[a]==nil)
        guard case .ready?=scoped.states[other] else {fatalError("new case did not render")}
        print("late old-case preview cannot replace new-case image")

        let brokenFile=URL(fileURLWithPath:receipts["A"]!.path);try Data(repeating:0,count:data.count).write(to:brokenFile)
        let retry=InlineMediaCache(loader:{try await probe.load($0)});retry.attach(a);await retry.waitUntilIdle()
        guard case .failed(let message)?=retry.states[a] else {fatalError("changed copy accepted")}
        precondition(message.contains("SHA-256"));try data.write(to:brokenFile);retry.retry(a);await retry.waitUntilIdle()
        guard case .ready?=retry.states[a] else {fatalError("retry failed")}
        print("changed preview copy refused; explicit retry works")

        let tiny=InlineMediaCache(itemLimit:0,byteLimit:0,loader:{try await probe.load($0)})
        tiny.attach(a);await tiny.waitUntilIdle();tiny.detach(a);precondition(tiny.states[a]==nil)
        do {let outside=try VerifiedPreviewReceipt(["path":asset.path,"mime":"image/png","sha256":hash,"bytes":data.count]);_ = try InlineMediaCache.decode(outside,key:a);fatalError("outside path accepted")} catch {}
        do {var mismatch=a;mismatch=InlineMediaKey(workspace:a.workspace,caseID:a.caseID,artifactID:a.artifactID,fingerprint:a.fingerprint,expectedHash:String(repeating:"0",count:64));_ = try InlineMediaCache.decode(receipts["A"]!,key:mismatch);fatalError("wrong source hash accepted")} catch {}
        let unsafe=root.appendingPathComponent("UNSAFE"),outside=root.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at:unsafe,withIntermediateDirectories:true);try FileManager.default.createDirectory(at:outside,withIntermediateDirectories:true)
        try FileManager.default.createSymbolicLink(at:unsafe.appendingPathComponent("previews"),withDestinationURL:outside)
        let unsafeKey=key("UNSAFE","unsafe")
        do {try InlineMediaCache.validatePreviewDirectory(unsafeKey);fatalError("symlinked preview directory accepted")} catch {}
        print("cache eviction, case-path containment, unsafe working directory refusal and source-hash matching")
    }
}
