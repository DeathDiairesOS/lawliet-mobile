import SwiftUI
import AppKit

struct DraftReviewView:View {
    @ObservedObject var m:AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft:DraftReview?
    @State private var loading=false
    @State private var error=""
    @State private var query=""
    @State private var selection:String?
    @State private var offset=0
    @State private var tab="Entries"
    private var matching:[DraftEntry] {draft?.entries.filter{query.isEmpty || $0.text.localizedCaseInsensitiveContains(query) || $0.kind.localizedCaseInsensitiveContains(query)} ?? []}
    private var page:[DraftEntry] {Array(matching.dropFirst(offset).prefix(50))}
    private var selected:DraftEntry? {draft?.entries.first{$0.id==selection}}
    private func choose() {
        let panel=NSOpenPanel();panel.canChooseDirectories=true;panel.canChooseFiles=false;panel.allowsMultipleSelection=false
        panel.directoryURL=URL(fileURLWithPath:m.workspace).appendingPathComponent(m.caseID).appendingPathComponent("customer-drafts")
        panel.message="Choose an existing Lawliet customer-draft bundle containing manifest.json. This view reads files only."
        guard panel.runModal() == .OK,let url=panel.url else {return}
        load(url)
    }
    private func load(_ url:URL) {
        let expectedCase=m.caseID,expectedPath=m.currentCasePath
        draft=nil;error="";loading=true;selection=nil;offset=0;query=""
        Task {
            do {
                let snapshot=try await Task.detached(priority:.userInitiated) {try DraftReview.load(url,expectedCase:expectedCase)}.value
                guard m.caseID==expectedCase && m.currentCasePath==expectedPath else {loading=false;return}
                draft=snapshot;selection=snapshot.entries.first?.id
            } catch {self.error=error.localizedDescription}
            loading=false
        }
    }
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            HStack {Text("Draft report review").font(.system(size:18,weight:.semibold));Spacer();Button("Report history"){m.dialog = .reportHistory}.disabled(loading);Button("Open draft folder…"){choose()}.disabled(loading);Button("Close"){dismiss()}.keyboardShortcut(.cancelAction)}
            Text("INTERNAL DRAFT · UNREVIEWED · UNREDACTED").font(.system(size:11,weight:.semibold)).foregroundStyle(.orange)
            Text("Case: \(m.caseID). Local manifest checks do not verify the case audit, retained source bytes, examiner identity or approval. This view does not approve or release reports.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            if loading {ProgressView("Checking report bundle…").frame(maxWidth:.infinity,maxHeight:.infinity)}
            else if !error.isEmpty {VStack(alignment:.leading,spacing:10){Label("Draft unavailable",systemImage:"exclamationmark.triangle");Text(error).textSelection(.enabled)}.frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading)}
            else if let draft=draft {
                Text(draft.objective).font(.headline).textSelection(.enabled)
                HStack {Text("\(draft.entries.count) \(draft.entries.count==1 ? "entry":"entries") · \(draft.citations.count) unique cited \(draft.citations.count==1 ? "snapshot":"snapshots")").font(.caption);Spacer();Picker("View",selection:$tab){Text("Entries & sources").tag("Entries");Text("Readable report").tag("Report");Text("Limitations").tag("Limitations")}.pickerStyle(.segmented).frame(width:400)}
                if tab=="Report" {ScrollView{Text(draft.report).font(.system(size:12,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading).padding(12)}}
                else if tab=="Limitations" {ScrollView{VStack(alignment:.leading,spacing:12){ForEach(Array(draft.limitations.enumerated()),id:\.offset){_,text in Text(text).textSelection(.enabled)};Divider();Text("Bundle SHA-256: \(draft.manifestHash)").font(.caption).textSelection(.enabled);Text(draft.path).font(.caption).textSelection(.enabled)}}}
                else {
                    TextField("Search draft entries",text:$query).onChange(of:query){_ in offset=0;selection=nil}
                    HSplitView {
                        Table(page,selection:$selection){TableColumn("Type"){Text($0.kind.capitalized)}.width(min:90,ideal:100,max:110);TableColumn("Entry"){Text($0.text).lineLimit(3)}.width(min:180,ideal:240,max:270);TableColumn("Sources"){Text(String($0.artifactIDs.count))}.width(60)}.frame(minWidth:450)
                        ScrollView {
                            VStack(alignment:.leading,spacing:12) {
                                if let entry=selected {
                                    Text(entry.kind.uppercased()).font(.caption).foregroundStyle(LawlietTheme.secondary)
                                    Text(entry.text).textSelection(.enabled)
                                    if entry.artifactIDs.isEmpty {Text("No cited artifact. Treat this as an open question or unsupported statement requiring review.").foregroundStyle(.orange)}
                                    ForEach(draft.citations.filter{entry.artifactIDs.contains($0.id)}) {citation in
                                        Divider();Text("SOURCE SNAPSHOT").font(.caption).foregroundStyle(LawlietTheme.secondary)
                                        Text(citation.snapshot["title"] as? String ?? citation.id).font(.headline).textSelection(.enabled)
                                        Text(citation.snapshot["body"] as? String ?? "No body in snapshot").textSelection(.enabled)
                                        detail("Timestamp",citation.timestamp)
                                        detail("Original timestamp",citation.snapshot["timestamp_raw"] as? String ?? "Unavailable")
                                        detail("Source file",citation.source("retained_logical_path"))
                                        detail("Record locator",citation.source("record_table_key_or_offset"))
                                        detail("Recorded source SHA-256",citation.source("recorded_source_sha256"))
                                        detail("Parser",citation.text("parser"));detail("Source tier",citation.text("source_tier"))
                                        detail("Parser-run linkage",citation.text("parser_run_link_state"));detail("Attachment state",citation.text("attachment_state"))
                                        Text("Indexed snapshot only. Attachments and external assets are not opened or fetched.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                                        DisclosureGroup("Original citation fields"){Text(citation.raw).font(.system(size:10,design:.monospaced)).textSelection(.enabled)}
                                    }
                                } else {Text(matching.isEmpty ? "No draft entries match this search.":"Select an entry to inspect its sources.").foregroundStyle(LawlietTheme.secondary)}
                            }.padding(12).frame(maxWidth:.infinity,alignment:.leading)
                        }.frame(minWidth:300,idealWidth:420)
                    }
                    HStack {Button("Previous"){offset=max(0,offset-50);selection=nil}.disabled(offset==0);Spacer();Text("\(matching.count) matching entries · page \(offset/50+1)").font(.caption);Spacer();Button("Next"){offset+=50;selection=nil}.disabled(offset+50>=matching.count)}
                }
            } else {VStack(alignment:.leading,spacing:12){Text("Open an existing source-linked report draft.").font(.headline);Text("To create a draft, open Saved findings and choose Prepare draft from selected findings. This uses the existing investigation ledger and preserves your notes as unreviewed interpretations.").foregroundStyle(LawlietTheme.secondary)}.frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading)}
        }.font(.system(size:12)).controlSize(.small).padding(20).frame(width:1000,height:650)
        .task {if !m.draftPath.isEmpty {load(URL(fileURLWithPath:m.draftPath))}}
    }
    private func detail(_ title:String,_ value:String)->some View {VStack(alignment:.leading,spacing:3){Text(title).font(.caption).foregroundStyle(LawlietTheme.secondary);Text(value).font(.system(size:11)).textSelection(.enabled)}}
}
