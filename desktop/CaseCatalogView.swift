import SwiftUI
import AppKit

extension AppModel {
    var currentCasePath:String {CaseCatalog.key(workspace:workspace,identifier:caseID)}
    func saveCatalogPreferences() {
        catalogRoots=CaseCatalog.roots(catalogRoots)
        UserDefaults.standard.set(catalogRoots,forKey:"catalog.roots")
        UserDefaults.standard.set(creationWorkspace,forKey:"catalog.creationWorkspace")
    }
    func addCatalogFolder() {
        guard !busy else {return}
        let p=NSOpenPanel();p.canChooseDirectories=true;p.canChooseFiles=false;p.prompt="Add case folder"
        p.message="Discover Lawliet case databases in this folder and nested analysis folders. Evidence is not imported, moved or parsed."
        guard p.runModal() == .OK,let url=p.url else {return}
        catalogRoots=CaseCatalog.roots(catalogRoots+[url.resolvingSymlinksInPath().path]);saveCatalogPreferences();refreshCases()
    }
    func chooseCreationFolder() {
        guard !busy else {return}
        let p=NSOpenPanel();p.canChooseDirectories=true;p.canChooseFiles=false;p.prompt="Use for new cases"
        p.message="New cases will be created here. Existing cases and evidence stay where they are."
        guard p.runModal() == .OK,let url=p.url else {return}
        creationWorkspace=url.resolvingSymlinksInPath().path;catalogRoots=CaseCatalog.roots(catalogRoots+[creationWorkspace]);saveCatalogPreferences();refreshCases()
    }
}

struct CaseFoldersView:View {
    @ObservedObject var m:AppModel
    @Environment(\.dismiss) private var dismiss
    var body:some View {
        VStack(alignment:.leading,spacing:14) {
            HStack{Text("Case folders").font(.system(size:18,weight:.semibold));Spacer();Button("Close"){dismiss()}.keyboardShortcut(.cancelAction)}
            Text("The catalog stores references. Removing a folder from this list does not delete cases or evidence.").foregroundStyle(LawlietTheme.secondary)
            ScrollView {VStack(alignment:.leading,spacing:10) {
                ForEach(m.catalogRoots,id:\.self){path in
                    HStack{Text(path).font(.system(size:11)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading);Spacer();Button("Remove reference"){
                        m.catalogRoots.removeAll{$0==path};m.saveCatalogPreferences();m.refreshCases()
                    }.buttonStyle(.borderless).accessibilityLabel("Remove reference "+path).disabled(m.busy || m.catalogRoots.count==1 || path==m.creationWorkspace).help(path==m.creationWorkspace ? "Choose another new-case folder before removing this reference.":"Remove only this catalog reference")}
                }
            }}.frame(height:160)
            HStack{Button("Add case folder…"){m.addCatalogFolder()};Spacer()}
            Divider();Text("New cases are created in").font(.caption).foregroundStyle(LawlietTheme.secondary);Text(m.creationWorkspace).font(.system(size:11)).textSelection(.enabled)
            Button("Change new-case folder…"){m.chooseCreationFolder()}.disabled(m.busy)
            Text("Discovery skips evidence/working directories, symlinks and hidden folders. Limits and unavailable cases are shown in the queue; this is not a full disk search.").font(.caption).foregroundStyle(LawlietTheme.secondary)
        }.padding(20).frame(width:730,height:470).font(.system(size:12)).controlSize(.small)
    }
}

struct ReportHistoryView:View {
    @ObservedObject var m:AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var items=[ReportHistoryItem]()
    @State private var loading=false;@State private var error="";@State private var total=0;@State private var offset=0;@State private var more=false
    @State private var selection:String?
    private var selected:ReportHistoryItem? {items.first{$0.id==selection}}
    private func reload(_ next:Int=0) {
        loading=true;error="";selection=nil
        let identity=m.currentCasePath
        Task {
            do {
                let r=try await m.request("report-history",["case":m.caseID,"offset":next]) as? [String:Any] ?? [:]
                guard identity==m.currentCasePath,r["schema_version"] as? Int==1,r["case_path"] as? String==identity,r["offset"] as? Int==next,let count=r["total"] as? Int,let rows=r["items"] as? [[String:Any]],rows.count<=50 else {throw DraftReviewError.invalid("Report history response does not match this case/page.")}
                items=rows.map(ReportHistoryItem.init);total=count;offset=next;more=r["has_more"] as? Bool ?? false
            } catch {items=[];self.error=error.localizedDescription}
            loading=false
        }
    }
    private func open(_ item:ReportHistoryItem) {guard item.available else {return};m.draftPath=item.path;m.dialog = .draftReview}
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            HStack{Text("Report history").font(.system(size:18,weight:.semibold));Spacer();Button("Refresh"){reload()}.disabled(loading);Button("Open draft folder…"){m.draftPath="";m.dialog = .draftReview};Button("Close"){dismiss()}.keyboardShortcut(.cancelAction)}
            Text("\(m.caseName) · \(m.caseID)").font(.caption).foregroundStyle(LawlietTheme.secondary)
            Text("Internal drafts remain unreviewed and unredacted. Opening a draft checks its bundle; listing it does not verify evidence or approve release.").foregroundStyle(LawlietTheme.secondary)
            if loading {ProgressView("Loading case drafts…").frame(maxWidth:.infinity,maxHeight:.infinity)}
            else if !error.isEmpty {Text(error).foregroundStyle(.orange).textSelection(.enabled).frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading)}
            else if items.isEmpty {VStack(spacing:10){Text("No saved drafts").font(.headline);Text("Prepare a draft from Saved findings. It will appear here without choosing a folder.").foregroundStyle(LawlietTheme.secondary)}.frame(maxWidth:.infinity,maxHeight:.infinity)}
            else {
                Table(items,selection:$selection) {
                    TableColumn("Draft") {r in VStack(alignment:.leading,spacing:3){Text(r.id).font(.system(size:11,design:.monospaced));Text(r.available ? "Unreviewed draft":"Unavailable").font(.caption).foregroundStyle(r.available ? Color.secondary:Color.orange)}}.width(min:220,ideal:270)
                    TableColumn("Entries"){Text($0.available ? String($0.entries):"—")}.width(55)
                    TableColumn("Sources"){Text($0.available ? String($0.sources):"—")}.width(55)
                    TableColumn("File modified"){r in Text(r.modified.map{$0.formatted(date:.abbreviated,time:.shortened)} ?? "Unavailable").font(.caption)}.width(min:140,ideal:180)
                }.contextMenu(forSelectionType:String.self){ids in if let row=items.first(where:{ids.contains($0.id)}) {Button("Review draft"){open(row)}.disabled(!row.available)}} primaryAction:{ids in if let row=items.first(where:{ids.contains($0.id)}) {open(row)}}
                if let row=selected {Text(row.error.isEmpty ? "Investigation: \(row.investigation)\n\(row.path)":row.error).font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)}
            }
            HStack{Button("Previous"){reload(max(0,offset-50))}.disabled(loading || offset==0);Text("\(total) \(total==1 ? "draft":"drafts") · page \(offset/50+1)").font(.caption).foregroundStyle(LawlietTheme.secondary);Button("Next"){reload(offset+50)}.disabled(loading || !more);Spacer();Button("Review draft"){if let row=selected {open(row)}}.disabled(loading || selected?.available != true)}
        }.padding(20).frame(width:800,height:470).font(.system(size:12)).controlSize(.small).task{reload()}
    }
}
