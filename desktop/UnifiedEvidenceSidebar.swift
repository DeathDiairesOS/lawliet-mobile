import SwiftUI

extension AppModel {
    func openEvidenceCategory(_ name:String) {
        guard !busy, !caseID.isEmpty else {return}
        perform("Opening case evidence…") {
            self.mode=name;self.searchMode="text";self.query="";self.appFilter="";self.conversation=""
            self.reportFilter="";self.since="";self.until="";self.rangeDays=0;self.sortField="";self.offset=0
            try await self.loadRecords()
        }
    }
}

struct UnifiedEvidenceSidebar:View {
    @ObservedObject var m:AppModel
    @State private var query=""
    @State private var expanded:Set<String>=["Apps"]
    private let accent=LawlietTheme.accent
    private let sections=[("Messages","messages","bubble.left.and.bubble.right"),("Calls","calls","phone"),("Contacts","contacts","person.crop.rectangle"),("Browser","browser","globe"),("Media","media","photo"),("Attachments","attachments","paperclip"),("Recovery","recovery","arrow.uturn.backward")]
    private func group(_ name:String)->String {
        if m.reportGroups[name]=="browser" {return "Browser"}
        if let section=sections.first(where:{m.reportCategories[name,default:[]].contains($0.1)}) {return section.0}
        let lower=name.lowercased()
        if ["installedapp","installed application","package","permission","ssa id","ssaid","dex usage","app ops","app standby"].contains(where:lower.contains) {return "Apps"}
        if ["usage stats","recent activity","graphics stats"].contains(where:lower.contains) {return "Apps"}
        if ["location","maps","gps"].contains(where:lower.contains) {return "Locations"}
        return "Other parsed reports"
    }
    private func reports(_ section:String)->[String] {
        let priority=["package_info","installed applications","installedappsgass","usage stats","recent activity"]
        return m.reportNames.filter{group($0)==section && (query.isEmpty || $0.localizedCaseInsensitiveContains(query) || ParsedReportsSidebar.reportTitle($0).localizedCaseInsensitiveContains(query))}.sorted {
            let left=priority.firstIndex(of:$0.lowercased()) ?? priority.count
            let right=priority.firstIndex(of:$1.lowercased()) ?? priority.count
            return left==right ? $0.localizedStandardCompare($1) == .orderedAscending:left<right
        }
    }
    private func reportButton(_ name:String)->some View {
        Button{m.openParsedReport(name)} label:{HStack(spacing:6){Image(systemName:"tablecells").font(.caption);Text(name==group(name) ? name+" report":ParsedReportsSidebar.reportTitle(name)).lineLimit(2).multilineTextAlignment(.leading);Spacer(minLength:1);Text("\(m.reportCounts[name,default:0].formatted()) rows").font(.caption2).foregroundStyle(LawlietTheme.secondary)}.padding(.vertical,6).padding(.horizontal,6).background(m.reportFilter==name && m.mode=="All artifacts" ? accent.opacity(0.12):.clear).cornerRadius(4)}.buttonStyle(.plain).help("\(name) · parser report rows, not additional evidence").disabled(m.busy)
    }
    private func binding(_ name:String)->Binding<Bool> {Binding(get:{!query.isEmpty || expanded.contains(name)},set:{if $0 {expanded.insert(name)} else {expanded.remove(name)}})}
    var body:some View {
        VStack(alignment:.leading,spacing:2) {
            Button{m.openEvidenceCategory("All artifacts")} label:{Label("All artifacts",systemImage:"square.grid.2x2")}.buttonStyle(.plain).padding(8).disabled(m.busy)
            Button{m.openEvidenceCategory("Timeline")} label:{Label("Timeline",systemImage:"clock")}.buttonStyle(.plain).padding(8).disabled(m.busy)
            if !m.reportNames.isEmpty {TextField("Find evidence sections…",text:$query).textFieldStyle(.roundedBorder).accessibilityLabel("Find evidence sections").padding(.vertical,4)}
            ForEach(sections,id:\.0) {section in
                let names=reports(section.0)
                if (m.categoryCounts[section.1] ?? 0)>0 && (query.isEmpty || !names.isEmpty || section.0.localizedCaseInsensitiveContains(query)) {
                    if names.isEmpty {
                        Button{m.openEvidenceCategory(section.0)} label:{HStack{Label(section.0,systemImage:section.2);Spacer();Text("\(m.sidebarCount(section.1).formatted()) \(section.1 == "media" ? "items":section.1 == "contacts" && m.investigatorView ? "entries":"records")").font(.caption2).foregroundStyle(LawlietTheme.secondary)}}.buttonStyle(.plain).padding(8).disabled(m.busy)
                    } else {
                        DisclosureGroup(isExpanded:binding(section.0)) {ForEach(names,id:\.self){reportButton($0)}} label:{
                            Button{m.openEvidenceCategory(section.0)} label:{HStack{Label(section.0,systemImage:section.2);Spacer();Text("\(m.sidebarCount(section.1).formatted()) \(section.1 == "media" ? "items":section.1 == "contacts" && m.investigatorView ? "entries":"records")").font(.caption2).foregroundStyle(LawlietTheme.secondary)}}.buttonStyle(.plain).disabled(m.busy).help("Combined \(section.0.lowercased()) view. Expand to inspect its source reports.")
                        }.padding(.vertical,5).padding(.horizontal,6)
                    }
                }
            }
            Button{m.openEvidenceCategory("Trash photos")} label:{HStack{Label("Trash photos",systemImage:"trash");Spacer();Text("\(m.categoryCounts["trash_photos",default:0].formatted()) items").font(.caption2).foregroundStyle(LawlietTheme.secondary)}}.buttonStyle(.plain).padding(8).disabled(m.busy)
            ForEach(["Apps","Locations","Other parsed reports"],id:\.self) {section in
                let names=reports(section)
                if !names.isEmpty {DisclosureGroup(section,isExpanded:binding(section)){ForEach(names,id:\.self){reportButton($0)}}.padding(.horizontal,6).padding(.vertical,5)}
            }
            let outputs=m.sources.filter{$0.parser.hasPrefix("mulder/")}
            if !outputs.isEmpty {
                DisclosureGroup("Mulder outputs",isExpanded:binding("Mulder outputs")) {
                    ForEach(outputs){source in Button{m.reviewSource(source.id)} label:{Text(source.label).lineLimit(2)}.buttonStyle(.plain).padding(6).disabled(m.busy).help("Retained tool-output windows and unreviewed AI findings; original run scope preserved.")}
                }.padding(.horizontal,6).padding(.vertical,5)
            }
        }.disabled(m.caseID.isEmpty)
    }
}
