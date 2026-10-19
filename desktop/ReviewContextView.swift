import SwiftUI
import AppKit

extension AppModel {
    func openRetainedCase() {
        guard !busy else {return}
        let panel=NSOpenPanel();panel.canChooseDirectories=true;panel.canChooseFiles=false
        panel.directoryURL=URL(fileURLWithPath:workspace)
        panel.prompt="Open case";panel.message="Choose an existing Lawliet case folder containing case.sqlite. Mulder review outputs can be opened directly; no evidence is imported or parsed."
        guard panel.runModal() == .OK,let url=panel.url else {return}
        let folder=url.resolvingSymlinksInPath()
        guard FileManager.default.fileExists(atPath:folder.appendingPathComponent("case.sqlite").path) else {
            notice="Select the case folder containing case.sqlite. To browse a folder of cases, use Change workspace.";showNotice=true;return
        }
        catalogRoots=CaseCatalog.roots(catalogRoots+[folder.path]);saveCatalogPreferences()
        workspace=folder.deletingLastPathComponent().path;caseID=folder.lastPathComponent;sourceID="";mode="Case overview"
        caseQuery="";caseQueueStatus="Active";caseQueueSort="Recent"
        UserDefaults.standard.set(workspace,forKey:"workspace")
        refreshCases()
    }
    var reviewNeedsApply: Bool { source != nil && displayedReview != ReviewContext(recordParams()) }
    func reviewSource(_ identifier: String) {
        guard !busy else { return }
        perform("Opening retained parser results…") {
            self.sourceID=identifier;self.mode="All artifacts";self.query=""
            try await self.loadSource()
        }
    }
    func searchEntireSource() {
        guard !busy else { return }
        mode="All artifacts";appFilter="";conversation="";reportFilter=""
        since="";until="";rangeDays=0;sortField="";sortMode="text";sortAscending=true
        search()
    }
    func removeReviewFilter(_ key: String) {
        guard !busy && !reviewNeedsApply else { return }
        switch key {
        case "category", "view_group": mode="All artifacts"
        case "query", "phone_query": query=""
        case "report": reportFilter="";sortField=""
        case "app": appFilter="";conversation=""
        case "conversation": conversation=""
        case "dates": since="";until="";rangeDays=0
        case "sort": sortField="";sortMode="text";sortAscending=true
        default: return
        }
        search()
    }
}

struct ReviewContextView: View {
    @ObservedObject var m: AppModel
    private var applied: ReviewContext { m.displayedReview ?? ReviewContext([:]) }
    private var adverseHistory: String {
        let states=[("partial","partial"),("failed","failed"),("interrupted","interrupted"),("cancelled","cancelled"),("needs review","needing review")]
        return states.compactMap { state,label in
            let count=m.runItems.filter{$0.status.trimmingCharacters(in:.whitespacesAndNewlines).lowercased()==state}.count
            return count>0 ? "\(count) \(label)":nil
        }.joined(separator:", ")
    }
    private func label(_ filter: ReviewFilter) -> String {
        if filter.id=="conversation", let id=applied.values["conversation"], let thread=m.threads.first(where:{$0.id==id}) {
            return "Conversation: \(thread.label)"
        }
        return filter.label
    }
    var body: some View {
        VStack(alignment:.leading,spacing:6) {
            HStack {
                Text(m.source?.isCaseWide==true ? "Searches indexed fields across all parsed sources in this case":"Searches parsed fields in this source").font(.caption).foregroundStyle(LawlietTheme.secondary)
                Spacer()
                if applied.restrictions || ReviewContext(m.recordParams()).restrictions {
                    Button(m.source?.isCaseWide==true ? "Search entire case":"Search entire source"){m.searchEntireSource()}.disabled(m.busy)
                }
            }
            if !adverseHistory.isEmpty {
                HStack(alignment:.top,spacing:8) {
                    Image(systemName:"exclamationmark.triangle").foregroundStyle(.orange)
                    Text("Case analysis history: \(adverseHistory). Results and source exports cover indexed records; zero matches do not establish absence of evidence.")
                        .font(.caption).foregroundStyle(LawlietTheme.secondary).fixedSize(horizontal:false,vertical:true)
                    Spacer(minLength:0)
                    Button("Processing history"){m.mode="Sources"}.disabled(m.busy)
                    Button("Coverage & review"){m.mode="Coverage"}.disabled(m.busy)
                }
            }
            if !applied.activeFilters.isEmpty {
                ScrollView(.horizontal) {
                    HStack(spacing:6) {
                        ForEach(applied.activeFilters) { filter in
                            Button {m.removeReviewFilter(filter.id)} label:{HStack(spacing:4){Text(label(filter)).lineLimit(1);Image(systemName:"xmark").font(.system(size:9))}}
                                .buttonStyle(.bordered).help(label(filter)).disabled(m.busy || m.reviewNeedsApply)
                        }
                    }
                }
            }
            if !m.reviewError.isEmpty && !m.busy {
                VStack(alignment:.leading,spacing:3) {
                    Text("Review request failed").font(.caption).fontWeight(.semibold)
                    Text(m.displayedReview == nil ? "No completed result is available. Retry the search.":"Showing the last completed results. Retry the search or page request.").font(.caption)
                    Text(m.reviewError).font(.caption).textSelection(.enabled)
                }.foregroundStyle(.orange).fixedSize(horizontal:false,vertical:true)
            }
            if m.reviewNeedsApply && !m.busy {
                HStack {
                    Text("Search changed · visible rows use the previously applied criteria.").font(.caption).foregroundStyle(.orange)
                    Spacer();Button("Apply search"){m.search()}
                }
            }
            if m.investigatorView && m.mode=="Contacts" {
                Text("Showing \(m.investigatorSummary["basis"] as? String ?? "source") entries · \(m.contactSummary["source_entries",default:0]) source contact entries · \(m.contactSummary["report_entries",default:0]) report entries available. Entries are not independently verified people.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            } else if m.investigatorView && m.mode=="Messages" {
                Text("\(m.investigatorSummary["matching_entries"] as? Int ?? m.rows.count) review entries · \(m.investigatorSummary["source_records"] as? Int ?? m.rows.count) source observations. Matching Discord representations are expandable; other source records remain separate.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            } else {
                Text("Counts describe indexed records and can include repeated source observations. Expand a section to inspect its source reports.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            }
            if m.source?.parser.hasPrefix("mulder/")==true {
                Text("Indexed entries can be tool-output windows or AI findings. They are not message counts or proof of phone coverage.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            }
        }.font(.system(size:11)).padding(.horizontal,16).padding(.top,7)
    }
}
