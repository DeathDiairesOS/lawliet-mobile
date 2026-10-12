import Foundation
import CryptoKit

enum DraftReviewError: LocalizedError {
    case invalid(String)
    var errorDescription:String? {if case let .invalid(message)=self {return message};return nil}
}

struct DraftCitation: Identifiable {
    let id:String
    let values:[String:Any]
    var snapshot:[String:Any] {values["snapshot"] as? [String:Any] ?? [:]}
    var locator:[String:Any] {values["source_locator"] as? [String:Any] ?? [:]}
    func text(_ key:String)->String {values[key] as? String ?? "Unavailable"}
    func source(_ key:String)->String {locator[key] as? String ?? "Unavailable"}
    var timestamp:String {snapshot["timestamp"] as? String ?? "Undated / timezone unknown"}
    var raw:String {String(data:(try? JSONSerialization.data(withJSONObject:values,options:[.prettyPrinted,.sortedKeys])) ?? Data(),encoding:.utf8) ?? ""}
}
struct DraftEntry: Identifiable {
    let id:String;let kind:String;let text:String;let artifactIDs:[String]
}

/// A read-only snapshot of one supported report bundle. Hashes establish local
/// bundle consistency only: case audit/source integrity and approval are separate.
struct DraftReview {
    let id:String;let investigationID:String;let caseID:String;let objective:String
    let path:String;let manifestHash:String;let report:String
    let entries:[DraftEntry];let citations:[DraftCitation];let limitations:[String]
    static let allowedFiles:Set<String>=["report.txt","investigation.json","investigation.json.receipt.json","technical-annex.json","exhibits.jsonl"]
    static func hash(_ data:Data)->String {SHA256.hash(data:data).map{String(format:"%02x",$0)}.joined()}
    static func load(_ folder:URL,expectedCase:String)throws->DraftReview {
        func fail(_ message:String)throws->Never {throw DraftReviewError.invalid(message)}
        let fm=FileManager.default
        // Reject symlinked paths rather than following a report link into evidence.
        var component=folder
        while component.path != "/" {
            let attributes=try fm.attributesOfItem(atPath:component.path)
            if attributes[.type] as? FileAttributeType == .typeSymbolicLink {try fail("Choose a report folder without symbolic links.")}
            component=component.deletingLastPathComponent()
        }
        func read(_ name:String,max:Int=32*1024*1024)throws->Data {
            let url=folder.appendingPathComponent(name)
            let attr=try fm.attributesOfItem(atPath:url.path)
            guard attr[.type] as? FileAttributeType == .typeRegular,
                  let count=attr[.size] as? NSNumber,count.intValue<=max else {try fail("Unsupported or oversized report file: \(name)")}
            let handle=try FileHandle(forReadingFrom:url);defer {try? handle.close()}
            let data=try handle.read(upToCount:max+1) ?? Data()
            guard data.count<=max else {try fail("Report file grew while reading: \(name)")}
            return data
        }
        func object(_ data:Data)throws->[String:Any] {
            guard let value=try JSONSerialization.jsonObject(with:data) as? [String:Any] else {try fail("Invalid report structure.")}
            return value
        }
        let manifestBytes=try read("manifest.json",max:1024*1024)
        let manifest=try object(manifestBytes)
        guard manifest["format"] as? String == "ancalor-customer-bundle-v1",
              manifest["review_status"] as? String == "draft_unreviewed",
              let id=manifest["draft_id"] as? String,id.count==32,id.allSatisfy({"0123456789abcdef".contains($0)}),
              let iid=manifest["investigation_id"] as? String,
              let files=manifest["files"] as? [[String:Any]],files.count==allowedFiles.count else {try fail("Unsupported customer-draft schema. Original files remain unchanged.")}
        var contents:[String:Data]=[:];var total=0
        for file in files {
            guard let name=file["path"] as? String,allowedFiles.contains(name),contents[name]==nil,
                  let expectedHash=file["sha256"] as? String,expectedHash.count==64,
                  let bytes=file["bytes"] as? Int,bytes>=0 else {try fail("Unsafe or duplicated manifest entry.")}
            let data=try read(name);total+=data.count
            guard total<=64*1024*1024,data.count==bytes,hash(data)==expectedHash else {try fail("Draft file integrity mismatch or bundle too large: \(name)")}
            contents[name]=data
        }
        guard Set(try fm.contentsOfDirectory(atPath:folder.path)) == allowedFiles.union(["manifest.json"]) else {try fail("Report folder contains missing or unmanifested files.")}
        let investigation=try object(contents["investigation.json"]!)
        let annex=try object(contents["technical-annex.json"]!)
        guard investigation["format"] as? String == "ancalor-investigation-report-v1",
              let caseID=investigation["case_id"] as? String,caseID==expectedCase,
              annex["format"] as? String == "ancalor-customer-annex-v1",
              annex["investigation_id"] as? String == iid,
              annex["review_status"] as? String == "draft_unreviewed",
              let objective=annex["objective"] as? String,
              let rawEntries=annex["entries"] as? [[String:Any]],rawEntries.count<=10000,
              let rawCitations=annex["citations"] as? [[String:Any]],rawCitations.count<=10000,
              let limitations=annex["limitations"] as? [String],
              let counts=manifest["counts"] as? [String:Any],counts["entries"] as? Int == rawEntries.count,
              counts["unique_cited_artifacts"] as? Int == rawCitations.count else {try fail("Report does not match this case or the supported annex schema.")}
        var citationIDs=Set<String>()
        let citations=try rawCitations.map {value -> DraftCitation in
            guard let aid=value["artifact_id"] as? String,!aid.isEmpty,citationIDs.insert(aid).inserted,
                  value["snapshot"] is [String:Any],value["source_locator"] is [String:Any] else {try fail("Invalid or duplicated citation.")}
            return DraftCitation(id:aid,values:value)
        }
        var entryIDs=Set<String>()
        let entries=try rawEntries.map {value -> DraftEntry in
            guard let eid=value["entry_id"] as? String,entryIDs.insert(eid).inserted,
                  let kind=value["kind"] as? String,["task","observation","interpretation","hypothesis","question"].contains(kind),
                  let text=value["text"] as? String,let refs=value["artifact_ids"] as? [String],
                  refs.allSatisfy({citationIDs.contains($0)}) else {try fail("Invalid entry or unresolved citation reference.")}
            return DraftEntry(id:eid,kind:kind,text:text,artifactIDs:refs)
        }
        guard let reportBytes=contents["report.txt"],reportBytes.count<=1024*1024,
              let report=String(data:reportBytes,encoding:.utf8) else {try fail("Readable report is unavailable or exceeds the 1 MiB preview limit.")}
        return DraftReview(id:id,investigationID:iid,caseID:caseID,objective:objective,path:folder.path,
                           manifestHash:hash(manifestBytes),report:report,entries:entries,citations:citations,limitations:limitations)
    }
}
