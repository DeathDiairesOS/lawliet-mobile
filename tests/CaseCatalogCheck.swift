import Foundation
@main struct Check {
    static func main() {
        let a=CaseItem(["id":"same","path":"/cases/a/same","workspace":"/cases/a","name":"First"])
        let b=CaseItem(["id":"same","path":"/cases/b/same","workspace":"/cases/b","name":"Second"])
        precondition(a.id != b.id && a.identifier==b.identifier)
        precondition(CaseCatalog.key(workspace:a.workspace,identifier:a.identifier)==a.id)
        precondition(CaseCatalog.roots(["/cases/a","/cases","/cases/b","/cases-other","/Volumes/easystore/old"])==["/cases","/cases-other"])
        precondition(CaseItem(["id":"unavailable","available":false]).needsAttention)
        precondition(CaseCatalog.initialRoots(saved:["/cases"],configured:"/cases",creation:"/cases",current:"/removed/same")==["/cases"])
        precondition(CaseCatalog.initialRoots(saved:nil,configured:"/cases",creation:"/cases",current:"/legacy/review")==["/cases","/legacy/review"])
        let history=ReportHistoryItem(["id":"draft","path":"/cases/a/same/customer-drafts/draft","available":true,"entries":1,"sources":1])
        precondition(history.available && history.entries==1)
        print("case paths isolate duplicate IDs and folder references")
    }
}
