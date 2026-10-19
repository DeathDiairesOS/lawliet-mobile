import Foundation

@main struct ReportReviewBindingCheck {
    static func main()throws {
        let mode=CommandLine.arguments[1]
        let binding=try ReportReviewBinding(workspace:"/fixture/cases",caseID:"CASE-A",id:String(repeating:"a",count:32),kind:"original",manifestHash:String(repeating:"b",count:64))
        func rejects(_ action:()throws->Void) {do {try action();fatalError("Unsafe request accepted")} catch {}}
        if mode=="explicit-approval" {
            rejects {_ = try binding.request("approve")}
            rejects {_ = try binding.request("approve",reviewer:"Test",declaration:"Reviewed",acknowledged:false)}
            let value=try binding.request("approve",reviewer:"Synthetic examiner",declaration:"Synthetic exact-byte declaration",acknowledged:true)
            precondition(value["reviewer"] as? String=="Synthetic examiner")
            precondition(value["expected_manifest_sha256"] as? String==binding.manifestHash)
            precondition(value["workspace"] as? String==binding.workspace)
        } else if mode=="response-binding" {
            let good:[String:Any]=["schema_version":1,"case_id":binding.caseID,"bundle_id":binding.id,"kind":binding.kind,"manifest_sha256":binding.manifestHash,"source_integrity_checked":true,"approval":NSNull()]
            let status=try ReportReviewVerification(good,binding:binding);precondition(!status.approved)
            for key in ["case_id","bundle_id","kind","manifest_sha256"] {var bad=good;bad[key]="foreign";rejects {_ = try ReportReviewVerification(bad,binding:binding)}}
            var bad=good;bad.removeValue(forKey:"approval");rejects {_ = try ReportReviewVerification(bad,binding:binding)}
        } else if mode=="derivative" {
            let derived=try ReportReviewBinding(workspace:binding.workspace,caseID:binding.caseID,id:binding.id,kind:"redacted",manifestHash:binding.manifestHash)
            let value=try derived.request("release",path:"/fixture/export")
            precondition(value["action"] as? String=="customer-report-redacted-release" && value["derivative_id"] as? String==binding.id && value["draft_id"]==nil)
            rejects {_ = try derived.request("redact",literals:"secret")}
            let redaction=try binding.request("redact",literals:"秘密😀\n exact spaces ")
            precondition(redaction["literals"] as? [String]==["秘密😀"," exact spaces "])
            rejects {_ = try binding.request("redact",literals:"same\nsame")}
        } else {fatalError("Unknown test")}
        print("passed: \(mode)")
    }
}
