// Compile with the production sidebar to check native-only and mixed-parser routes.
import SwiftUI

enum LawlietTheme {
    static let accent=Color.purple
    static let secondary=Color.secondary
}
enum ParsedReportsSidebar {
    static func reportTitle(_ name:String)->String {name}
}
struct SidebarSource:Identifiable {
    let id:String
    let parser:String
    let label:String
}
final class AppModel:ObservableObject {
    @Published var busy=false
    var caseID="fixture",mode="",searchMode="",query="",appFilter="",conversation="",reportFilter="",since="",until="",sortField=""
    var rangeDays=0,offset=0
    var categoryCounts:[String:Int]=[:],reportCounts:[String:Int]=[:]
    var reportNames:[String]=[],reportCategories:[String:[String]]=[:],reportGroups:[String:String]=[:]
    var sources:[SidebarSource]=[]
    func perform(_ text:String,action:@escaping () async throws->Void) {}
    func loadRecords() async throws {}
    func openParsedReport(_ name:String) {}
    func reviewSource(_ id:String) {}
    func sidebarCount(_ category:String)->Int {categoryCounts[category,default:0]}
}

@main struct UnifiedEvidenceSidebarCheck {
    static func main() {
        let counts=["apps":448,"device":1,"logs":245460,"external":12,"messages":2,"trash_photos":1,"custom_artifacts":3]
        let expected=["Applications":"apps","Device":"device","System logs":"logs","Other parsed records":"external","Custom Artifacts":"custom_artifacts","Messages":"messages"]
        for (title,category) in expected {
            precondition(EvidenceSidebarNavigation.category(for:title,counts:counts)==category,"\(title) must route to \(category)")
        }
        precondition(EvidenceSidebarNavigation.category(for:"Browser",counts:counts)==nil,"Browser must preserve its view-group route")
        precondition(EvidenceSidebarNavigation.category(for:"Trash photos",counts:counts)=="media")
        precondition(EvidenceSidebarNavigation.category(for:"All artifacts",counts:counts)==nil)
        let sections=EvidenceSidebarNavigation.sections(counts:counts)
        precondition(sections.filter{$0.category=="apps"}.count==1)
        precondition(!sections.contains{$0.category=="trash_photos"},"Trash is a Media subset, not a second artifact category")
        precondition(EvidenceSidebarNavigation.reportGroup("package_info",categories:["external"],viewGroup:nil,counts:counts)=="Applications")
        precondition(EvidenceSidebarNavigation.reportGroup("Recent Activity",categories:["external"],viewGroup:nil,counts:counts)=="Applications")
        precondition(EvidenceSidebarNavigation.reportGroup("SMS Messages",categories:["messages"],viewGroup:nil,counts:counts)=="Messages")
        precondition(EvidenceSidebarNavigation.reportGroup("Unknown browser export",categories:["external"],viewGroup:"browser",counts:counts)=="Browser")
        precondition(EvidenceSidebarNavigation.reportGroup("Custom report",categories:["custom_artifacts"],viewGroup:nil,counts:counts)=="Custom Artifacts")
        precondition(EvidenceSidebarNavigation.category(for:"Locations",counts:["location":2])=="location")
        precondition(EvidenceSidebarNavigation.category(for:"Locations",counts:["locations":2])=="locations")
        let unusual=EvidenceSidebarNavigation.sections(counts:["messages":1,"Messages":1])
        precondition(Set(unusual.map(\.title)).count==unusual.count,"Imported categories must not shadow built-in navigation")
        print("PASS: native-only navigation, mixed parser groups, dynamic categories, counts and browser/trash routes")
    }
}
