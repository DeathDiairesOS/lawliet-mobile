import Foundation

@main struct SourceScopeCheck {
    static func main()throws {
        let mode=CommandLine.arguments[1]
        let source:SourceItem
        if mode=="case" {source=SourceItem(id:SourceItem.caseWideID,label:"All parsed sources in this case",evidence:"",parser:"",run:nil,records:15)}
        else if mode=="run" {source=SourceItem(id:"run",label:"Run",evidence:CommandLine.arguments[2],parser:"",run:"test-run",records:0)}
        else {source=SourceItem(id:"individual",label:"Individual",evidence:CommandLine.arguments[2],parser:CommandLine.arguments[3],run:nil,records:5)}
        precondition(source.hasResults)
        let all=SourceItem(id:SourceItem.caseWideID,label:"All",evidence:"",parser:"",run:nil,records:10)
        let imported=SourceItem(id:"new:parser",label:"New",evidence:"new",parser:"parser",run:nil,records:2)
        precondition(SourceItem.selectedID(in:[all,imported],current:"unknown-run",preferredEvidence:"new")=="new:parser")
        precondition(SourceItem.selectedID(in:[all,imported],current:all.id)==all.id)
        precondition(SourceItem.selectedID(in:[],current:"missing")=="")
        if mode=="case" {precondition(source.queryFields.isEmpty && source.isCaseWide)}
        if mode=="run" {precondition(source.queryFields["run"] as? String=="test-run" && !source.isCaseWide)}
        let data=try JSONSerialization.data(withJSONObject:source.queryFields,options:.sortedKeys)
        print(String(data:data,encoding:.utf8)!)
    }
}
