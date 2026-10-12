import Foundation

struct SourceItem: Identifiable {
    static let caseWideID="all-case-sources"
    let id:String;let label:String;let evidence:String;let parser:String;let run:String?;let records:Int
    var isCaseWide:Bool {id==Self.caseWideID}
    var hasResults:Bool {isCaseWide || run != nil || !parser.isEmpty}
    var rowUnit:String {parser.hasPrefix("mulder/") ? (records==1 ? "indexed entry":"indexed entries"):(records==1 ? "row":"rows")}
    static func selectedID(in sources:[SourceItem],current:String,preferredEvidence:String?=nil)->String {
        if sources.contains(where:{$0.id==current}) {return current}
        if let evidence=preferredEvidence,let matching=sources.first(where:{$0.evidence==evidence && $0.hasResults}) {return matching.id}
        return sources.first?.id ?? ""
    }
    var queryFields:[String:Any] {
        guard !isCaseWide else {return [:]}
        var fields:[String:Any]=["evidence":evidence,"parser":parser]
        if let run=run {fields["run"]=run}
        return fields
    }
}
