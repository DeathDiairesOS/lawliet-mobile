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
    @State private var showRelease=false
    @State private var loadID=UUID()
    private var matching:[DraftEntry] {draft?.entries.filter{query.isEmpty || $0.text.localizedCaseInsensitiveContains(query) || $0.kind.localizedCaseInsensitiveContains(query)} ?? []}
    private var page:[DraftEntry] {Array(matching.dropFirst(offset).prefix(50))}
    private var selected:DraftEntry? {draft?.entries.first{$0.id==selection}}
    private func choose() {
        let panel=NSOpenPanel();panel.canChooseDirectories=true;panel.canChooseFiles=false;panel.allowsMultipleSelection=false
        panel.directoryURL=URL(fileURLWithPath:m.workspace).appendingPathComponent(m.caseID).appendingPathComponent("customer-drafts")
        panel.message="Choose an original or selected-literal derivative bundle containing manifest.json. Opening it does not approve or export it."
        guard panel.runModal() == .OK,let url=panel.url else {return}
        load(url)
    }
    private func load(_ url:URL) {
        let expectedCase=m.caseID,expectedPath=m.currentCasePath,token=UUID();loadID=token
        draft=nil;error="";loading=true;selection=nil;offset=0;query=""
        Task {
            do {
                let snapshot=try await Task.detached(priority:.userInitiated) {try DraftReview.load(url,expectedCase:expectedCase)}.value
                guard loadID==token,m.caseID==expectedCase && m.currentCasePath==expectedPath else {return}
                draft=snapshot;selection=snapshot.entries.first?.id;tab=snapshot.examination == nil ? "Entries":"Examination";m.draftPath=url.path
            } catch {if loadID==token {self.error=error.localizedDescription}}
            if loadID==token {loading=false}
        }
    }
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            HStack {Text("Report review").font(.system(size:18,weight:.semibold));Spacer();Button("Report history"){m.dialog = .reportHistory}.disabled(loading);Button("Open draft folder…"){choose()}.disabled(loading);Button("Review & export…"){showRelease=true}.disabled(loading || draft==nil);Button("Close"){dismiss()}.keyboardShortcut(.cancelAction)}
            Text(draft?.kind=="redacted" ? "SELECTED-LITERAL DERIVATIVE · REFERENCES ONLY":"ORIGINAL DRAFT · UNREDACTED").font(.system(size:11,weight:.semibold)).foregroundStyle(.orange)
            Text("Case: \(m.caseID). Opening checks bundle hashes. Review & export rechecks the case audit and retained sources, then requires a separate examiner declaration. Approval is never inferred from these draft labels.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            if loading {ProgressView("Checking report bundle…").frame(maxWidth:.infinity,maxHeight:.infinity)}
            else if !error.isEmpty {VStack(alignment:.leading,spacing:10){Label("Draft unavailable",systemImage:"exclamationmark.triangle");Text(error).textSelection(.enabled)}.frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading)}
            else if let draft=draft {
                Text(draft.objective).font(.headline).textSelection(.enabled)
                HStack {Text("\(draft.entries.count) \(draft.entries.count==1 ? "entry":"entries") · \(draft.citations.count) unique cited \(draft.citations.count==1 ? "snapshot":"snapshots")").font(.caption);Spacer();Picker("View",selection:$tab){if draft.examination != nil {Text("Examination").tag("Examination")};Text("Entries & sources").tag("Entries");Text("Readable report").tag("Report");Text("Limitations").tag("Limitations")}.pickerStyle(.segmented).frame(width:draft.examination == nil ? 400:540)}
                if tab=="Report" {ScrollView{Text(draft.report).font(.system(size:12,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading).padding(12)}}
                else if tab=="Limitations" {ScrollView{VStack(alignment:.leading,spacing:12){ForEach(Array(draft.limitations.enumerated()),id:\.offset){_,text in Text(text).textSelection(.enabled)};Divider();Text("Bundle SHA-256: \(draft.manifestHash)").font(.caption).textSelection(.enabled);Text(draft.path).font(.caption).textSelection(.enabled)}}}
                else if tab=="Examination",let examination=draft.examination {
                    ScrollView {VStack(alignment:.leading,spacing:12) {
                        Text(examination.label+" · unreviewed examination").font(.headline)
                        Text("This outcome applies only to the recorded evidence and searches. It does not establish absence from the original device or prove a device is free of compromise.").foregroundStyle(.orange)
                        detail("Examiner label",examination.examiner);detail("Examination scope",examination.scope)
                        detail("Limitations & missing evidence",examination.limitations)
                        Divider();Text("RECORDED SEARCHES").font(.caption).foregroundStyle(LawlietTheme.secondary)
                        if examination.queries.isEmpty {Text("No indexed searches were performed in this examination. See the limitations for the reason.")}
                        ForEach(examination.queries){query in
                            VStack(alignment:.leading,spacing:4){Text(query.text).fontWeight(.medium);Text("\(query.returnedRecords) returned records\(query.hasMore ? " · more matches exist":"")").font(.caption);Text("Action: "+query.id).font(.system(size:10,design:.monospaced)).foregroundStyle(LawlietTheme.secondary)}
                        }
                        DisclosureGroup("Scope, processing snapshot & query provenance"){Text(examination.raw).font(.system(size:10,design:.monospaced)).textSelection(.enabled)}
                    }.textSelection(.enabled).padding(12).frame(maxWidth:.infinity,alignment:.leading)}
                } else {
                    TextField("Search draft entries",text:$query).onChange(of:query){_ in offset=0;selection=nil}
                    HSplitView {
                        Table(page,selection:$selection){TableColumn("Type"){Text($0.kind.capitalized)}.width(min:90,ideal:100,max:110);TableColumn("Entry"){Text($0.text).lineLimit(3)}.width(min:180,ideal:240,max:270);TableColumn("Cited records"){Text(String($0.artifactIDs.count)).help("Distinct cited artifact records; matching source representations may describe the same event.")}.width(90)}.frame(minWidth:450)
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
            } else {VStack(alignment:.leading,spacing:12){Text("Open or prepare an examination draft.").font(.headline);Text("Use saved findings for source-linked interpretations, or record a scoped examination when the result is inconclusive or searches return no indexed matches.").foregroundStyle(LawlietTheme.secondary);HStack {Button("From saved findings…"){m.dialog = .draftPreparation};Button("Scoped examination…"){m.dialog = .examinationPreparation}}.disabled(m.busy)}.frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading)}
        }.font(.system(size:12)).controlSize(.small).padding(20).frame(width:1000,height:650)
        .task {if !m.draftPath.isEmpty {load(URL(fileURLWithPath:m.draftPath))}}
        .onChange(of:m.currentCasePath){_ in loadID=UUID();draft=nil;loading=false;showRelease=false;error="Case changed. Reopen a report from the intended case."}
        .sheet(isPresented:$showRelease){if let draft=draft {ReportReleaseView(m:m,draft:draft){path in load(URL(fileURLWithPath:path))}}}
    }
    private func detail(_ title:String,_ value:String)->some View {VStack(alignment:.leading,spacing:3){Text(title).font(.caption).foregroundStyle(LawlietTheme.secondary);Text(value).font(.system(size:11)).textSelection(.enabled)}}
}
