import SwiftUI

extension AppModel {
    var reviewTitle:String {
        guard mode=="All artifacts", !reportFilter.isEmpty else {return mode}
        return ParsedReportsSidebar.reportTitle(reportFilter)
    }
    func openParsedReport(_ name:String) {
        guard !busy, reportNames.contains(name) else {return}
        perform("Opening parsed report…") {
            self.mode="All artifacts";self.searchMode="text";self.query=""
            self.appFilter="";self.conversation="";self.since="";self.until="";self.rangeDays=0
            self.sortField="";self.sortMode="text";self.sortAscending=true;self.offset=0
            self.reportFilter=name
            try await self.loadRecords()
        }
    }
}

struct ParsedReportsSidebar:View {
    @ObservedObject var m:AppModel
    @State private var query=""
    private let accent=LawlietTheme.accent
    static func reportTitle(_ name:String)->String {
        switch name.lowercased() {
        case "installedappsgass":return "APK hashes"
        case "package_info":return "Installed apps"
        case "packagegplinks":return "App store links"
        case "discordchats":return "Discord messages"
        default:return name
        }
    }
    private var names:[String] {
        let priority=["installedappsgass","installed applications","package_info","usage stats","recent activity"]
        return m.reportNames.filter {query.isEmpty || $0.localizedCaseInsensitiveContains(query) || Self.reportTitle($0).localizedCaseInsensitiveContains(query)}.sorted {
            let left=priority.firstIndex(of:$0.lowercased()) ?? priority.count
            let right=priority.firstIndex(of:$1.lowercased()) ?? priority.count
            return left==right ? $0.localizedStandardCompare($1) == .orderedAscending:left<right
        }
    }
    var body:some View {
        if !m.reportNames.isEmpty {
            Divider().padding(.vertical,6)
            HStack {Text("PARSED REPORTS").font(.system(size:9,weight:.medium));Spacer();Text("\(m.reportNames.count)").font(.caption2)}.foregroundStyle(LawlietTheme.secondary).padding(.horizontal,8)
            TextField("Find apps, usage, locations…",text:$query).textFieldStyle(.roundedBorder).padding(.horizontal,4).accessibilityLabel("Find parsed reports")
            ForEach(names,id:\.self) {name in
                Button {m.openParsedReport(name)} label:{
                    HStack(spacing:8) {
                        Image(systemName:"tablecells").frame(width:16)
                        Text(Self.reportTitle(name)).lineLimit(2).multilineTextAlignment(.leading)
                        Spacer(minLength:2)
                        Text(m.reportCounts[name,default:0].formatted()).font(.system(size:10)).foregroundStyle(LawlietTheme.secondary)
                    }.padding(.horizontal,8).padding(.vertical,7)
                        .background(m.mode=="All artifacts" && m.reportFilter==name ? accent.opacity(0.12):.clear).cornerRadius(5)
                }.buttonStyle(.plain).disabled(m.busy || m.caseID.isEmpty)
                    .help("\(name) · \(m.reportCounts[name,default:0]) parsed rows in the selected scope")
            }
            if names.isEmpty {Text("No report names match.").font(.caption).foregroundStyle(LawlietTheme.secondary).padding(8)}
        }
    }
}
