import Foundation

struct ReportReviewBinding:Equatable {
    let workspace:String;let caseID:String;let id:String;let kind:String;let manifestHash:String
    init(workspace:String,caseID:String,id:String,kind:String,manifestHash:String)throws {
        guard workspace.hasPrefix("/"),!workspace.contains("\0"),
              caseID.range(of:"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$",options:.regularExpression) != nil,
              id.range(of:"^[a-f0-9]{32}$",options:.regularExpression) != nil,
              manifestHash.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil,
              ["original","redacted"].contains(kind) else {throw DraftReviewError.invalid("Invalid report review binding.")}
        self.workspace=workspace;self.caseID=caseID;self.id=id;self.kind=kind;self.manifestHash=manifestHash
    }
    var identifierKey:String {kind=="redacted" ? "derivative_id":"draft_id"}
    func request(_ operation:String,reviewer:String="",declaration:String="",acknowledged:Bool=false,path:String="",literals:String="")throws->[String:Any] {
        var value:[String:Any]=["workspace":workspace,"case":caseID,"expected_manifest_sha256":manifestHash]
        if operation=="review" {value["action"]="customer-report-review";value["bundle_id"]=id;value["kind"]=kind;return value}
        value[identifierKey]=id
        switch operation {
        case "approve":
            guard acknowledged,!reviewer.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,reviewer.count<=200,
                  !declaration.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,declaration.count<=4000 else {throw DraftReviewError.invalid("Enter your examiner name and approval declaration, and confirm review of this bundle.")}
            value["action"]=kind=="redacted" ? "customer-report-redacted-approve":"customer-report-approve"
            value["reviewer"]=reviewer;value["declaration"]=declaration
        case "release":
            guard path.hasPrefix("/"),!path.contains("\0") else {throw DraftReviewError.invalid("Choose an absolute local export folder.")}
            value["action"]=kind=="redacted" ? "customer-report-redacted-release":"customer-report-release";value["path"]=path
        case "redact":
            guard kind=="original" else {throw DraftReviewError.invalid("Create derivatives from the original draft.")}
            let selections=literals.components(separatedBy:.newlines).filter{!$0.isEmpty}
            guard !selections.isEmpty,selections.count<=128,Set(selections).count==selections.count,
                  selections.allSatisfy({$0.count<=512 && !$0.contains("\0")}),selections.reduce(0,{$0+$1.utf8.count})<=16384 else {throw DraftReviewError.invalid("Supply 1–128 distinct case-sensitive literals, one per line; at most 512 characters each and 16 KiB total.")}
            value["action"]="customer-report-redacted-draft";value["literals"]=selections
        default:throw DraftReviewError.invalid("Unsupported report action.")
        }
        return value
    }
}

struct ReportReviewVerification {
    let approved:Bool;let reviewer:String;let approvedAt:String
    init(_ value:[String:Any],binding:ReportReviewBinding)throws {
        guard value["schema_version"] as? Int==1,value["case_id"] as? String==binding.caseID,
              value["bundle_id"] as? String==binding.id,value["kind"] as? String==binding.kind,
              value["manifest_sha256"] as? String==binding.manifestHash,
              value["source_integrity_checked"] as? Bool==true else {throw DraftReviewError.invalid("Report verification does not match the viewed bundle.")}
        if let approval=value["approval"] as? [String:Any] {
            guard approval["manifest_sha256"] as? String==binding.manifestHash,
                  let name=approval["reviewer"] as? String,!name.isEmpty,
                  let at=approval["approved_at"] as? String,!at.isEmpty else {throw DraftReviewError.invalid("Invalid recorded approval.")}
            approved=true;reviewer=name;approvedAt=at
        } else {
            guard value["approval"] is NSNull else {throw DraftReviewError.invalid("Approval state is unavailable.")}
            approved=false;reviewer="";approvedAt=""
        }
    }
}
