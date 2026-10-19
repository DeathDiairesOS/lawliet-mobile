import SwiftUI

struct EvidenceSidebarSection:Identifiable {
    let title:String
    let category:String
    let symbol:String
    var id:String {category}
}

enum EvidenceSidebarNavigation {
    static func sections(counts:[String:Int])->[EvidenceSidebarSection] {
        let locationCategory=counts["locations",default:0]>0 ? "locations":"location"
        let known=[
            EvidenceSidebarSection(title:"Messages",category:"messages",symbol:"bubble.left.and.bubble.right"),
            EvidenceSidebarSection(title:"Calls",category:"calls",symbol:"phone"),
            EvidenceSidebarSection(title:"Contacts",category:"contacts",symbol:"person.crop.rectangle"),
            EvidenceSidebarSection(title:"Browser",category:"browser",symbol:"globe"),
            EvidenceSidebarSection(title:"Media",category:"media",symbol:"photo"),
            EvidenceSidebarSection(title:"Attachments",category:"attachments",symbol:"paperclip"),
            EvidenceSidebarSection(title:"Applications",category:"apps",symbol:"app.badge"),
            EvidenceSidebarSection(title:"Device",category:"device",symbol:"iphone"),
            EvidenceSidebarSection(title:"System logs",category:"logs",symbol:"text.alignleft"),
            EvidenceSidebarSection(title:"Locations",category:locationCategory,symbol:"mappin.and.ellipse"),
            EvidenceSidebarSection(title:"Recovery",category:"recovery",symbol:"arrow.uturn.backward"),
            EvidenceSidebarSection(title:"Other parsed records",category:"external",symbol:"tablecells")
        ]
        // Imported schemas may add categories. Keep those records discoverable
        // without pretending derived view groups are independent artifacts.
        let covered=Set(known.map(\.category)).union(["trash_photos"])
        let titles=Set(known.map(\.title))
        let extra=counts.keys.filter{counts[$0,default:0]>0 && !covered.contains($0)}.sorted().map {category in
            let label=category.replacingOccurrences(of:"_",with:" ").replacingOccurrences(of:"-",with:" ").capitalized
            let title=titles.contains(label) ? "\(label) (\(category))":label
            return EvidenceSidebarSection(title:title,category:category,symbol:"tablecells")
        }
        return known+extra
    }
    static func category(for mode:String,counts:[String:Int])->String? {
        if mode=="Trash photos" {return "media"}
        // Browser is the backend's cross-category browser view group.
        if mode=="Browser" {return nil}
        return sections(counts:counts).first{$0.title==mode}?.category
    }
    static func reportGroup(_ name:String,categories:[String],viewGroup:String?,counts:[String:Int])->String {
        if viewGroup=="browser" {return "Browser"}
        if let section=sections(counts:counts).first(where:{$0.category != "external" && categories.contains($0.category)}) {return section.title}
        let lower=name.lowercased()
        if ["installedapp","installed application","package","permission","ssa id","ssaid","dex usage","app ops","app standby","usage stats","recent activity","graphics stats"].contains(where:lower.contains) {return "Applications"}
        if ["location","maps","gps"].contains(where:lower.contains) {return "Locations"}
        return "Other parsed records"
    }
}

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
    @State private var expanded:Set<String>=[]
    private let accent=LawlietTheme.accent
    private var sections:[EvidenceSidebarSection] {EvidenceSidebarNavigation.sections(counts:m.categoryCounts)}
    private func group(_ name:String)->String {
        EvidenceSidebarNavigation.reportGroup(name,categories:m.reportCategories[name,default:[]],viewGroup:m.reportGroups[name],counts:m.categoryCounts)
    }
    private func reports(_ section:String)->[String] {
        let priority=["package_info","installed applications","installedappsgass","usage stats","recent activity"]
        return m.reportNames.filter{group($0)==section && (query.isEmpty || section.localizedCaseInsensitiveContains(query) || $0.localizedCaseInsensitiveContains(query) || ParsedReportsSidebar.reportTitle($0).localizedCaseInsensitiveContains(query))}.sorted {
            let left=priority.firstIndex(of:$0.lowercased()) ?? priority.count
            let right=priority.firstIndex(of:$1.lowercased()) ?? priority.count
            return left==right ? $0.localizedStandardCompare($1) == .orderedAscending:left<right
        }
    }
    private func reportButton(_ name:String)->some View {
        Button{m.openParsedReport(name)} label:{
            HStack(spacing:6){Image(systemName:"tablecells").font(.system(size:10));Text(ParsedReportsSidebar.reportTitle(name)).lineLimit(1);Spacer(minLength:2);Text(m.reportCounts[name,default:0].formatted()).font(.system(size:10)).monospacedDigit().foregroundStyle(LawlietTheme.secondary)}
                .padding(.vertical,5).padding(.horizontal,6)
                .background(m.reportFilter==name && m.mode=="All artifacts" ? accent.opacity(0.12):.clear).cornerRadius(4)
        }.buttonStyle(.plain).help("\(name) · \(m.reportCounts[name,default:0].formatted()) parser report rows, not additional evidence").disabled(m.busy)
    }
    private func binding(_ name:String)->Binding<Bool> {Binding(get:{!query.isEmpty || expanded.contains(name)},set:{if $0 {expanded.insert(name)} else {expanded.remove(name)}})}
    private func categoryLabel(_ section:EvidenceSidebarSection,reportCount:Int)->some View {
        HStack(spacing:6){
            Image(systemName:section.symbol).frame(width:16)
            Text(section.title).lineLimit(1)
            Spacer(minLength:2)
            if m.categoryCounts[section.category,default:0]>0 {
                Text(m.sidebarCount(section.category).formatted()).monospacedDigit().foregroundStyle(LawlietTheme.secondary)
            } else if reportCount>0 {
                Text("\(reportCount) \(reportCount==1 ? "report":"reports")").foregroundStyle(LawlietTheme.secondary)
            }
        }.font(.system(size:12)).padding(.vertical,6).padding(.horizontal,6)
            .background(m.mode==section.title && m.reportFilter.isEmpty ? accent.opacity(0.12):.clear).cornerRadius(4)
    }
    private func categoryButton(_ section:EvidenceSidebarSection,reportCount:Int)->some View {
        Button{m.openEvidenceCategory(section.title)} label:{categoryLabel(section,reportCount:reportCount)}.buttonStyle(.plain).disabled(m.busy)
            .help("\(section.title) · \(m.sidebarCount(section.category).formatted()) indexed \(section.category=="media" ? "items":"records") in the selected scope. Expanded reports retain their own row counts.")
    }
    var body:some View {
        VStack(alignment:.leading,spacing:2) {
            Button{m.openEvidenceCategory("All artifacts")} label:{Label("All artifacts",systemImage:"square.grid.2x2").frame(maxWidth:.infinity,alignment:.leading).padding(7).background(m.mode=="All artifacts" && m.reportFilter.isEmpty ? accent.opacity(0.12):.clear).cornerRadius(4)}.buttonStyle(.plain).disabled(m.busy)
            Button{m.openEvidenceCategory("Timeline")} label:{Label("Timeline",systemImage:"clock").frame(maxWidth:.infinity,alignment:.leading).padding(7).background(m.mode=="Timeline" ? accent.opacity(0.12):.clear).cornerRadius(4)}.buttonStyle(.plain).disabled(m.busy)
            if !m.categoryCounts.isEmpty || !m.reportNames.isEmpty {TextField("Find sections or reports…",text:$query).textFieldStyle(.roundedBorder).accessibilityLabel("Find evidence sections").padding(.vertical,4)}
            ForEach(sections) {section in
                let names=reports(section.title)
                let hasRecords=m.categoryCounts[section.category,default:0]>0
                if (hasRecords || !names.isEmpty) && (query.isEmpty || !names.isEmpty || section.title.localizedCaseInsensitiveContains(query)) {
                    if names.isEmpty {categoryButton(section,reportCount:0)} else {
                        DisclosureGroup(isExpanded:binding(section.title)) {ForEach(names,id:\.self){reportButton($0)}} label:{
                            if hasRecords {categoryButton(section,reportCount:names.count)} else {categoryLabel(section,reportCount:names.count)}
                        }.padding(.horizontal,2)
                    }
                }
            }
            if m.categoryCounts["trash_photos",default:0]>0 && (query.isEmpty || "Trash photos".localizedCaseInsensitiveContains(query)) {
                Button{m.openEvidenceCategory("Trash photos")} label:{HStack(spacing:6){Label("Trash photos",systemImage:"trash");Spacer();Text(m.categoryCounts["trash_photos",default:0].formatted()).monospacedDigit().foregroundStyle(LawlietTheme.secondary)}.padding(6).background(m.mode=="Trash photos" ? accent.opacity(0.12):.clear).cornerRadius(4)}.buttonStyle(.plain).disabled(m.busy).help("Recorded Trash acquisitions · subset of Media")
            }
            let outputs=m.sources.filter{$0.parser.hasPrefix("mulder/")}
            if !outputs.isEmpty && (query.isEmpty || "Mulder outputs".localizedCaseInsensitiveContains(query) || outputs.contains{$0.label.localizedCaseInsensitiveContains(query)}) {
                DisclosureGroup("Mulder outputs",isExpanded:binding("Mulder outputs")) {
                    ForEach(outputs.filter{query.isEmpty || "Mulder outputs".localizedCaseInsensitiveContains(query) || $0.label.localizedCaseInsensitiveContains(query)}){source in Button{m.reviewSource(source.id)} label:{Text(source.label).lineLimit(2)}.buttonStyle(.plain).padding(6).disabled(m.busy).help("Retained tool-output windows and unreviewed AI findings; original run scope preserved.")}
                }.padding(.horizontal,6).padding(.vertical,5)
            }
        }.disabled(m.caseID.isEmpty)
    }
}
