import SwiftUI
import AppKit
import AVKit
import ImageIO
import UniformTypeIdentifiers

enum DesktopDialog: String, Identifiable {case deviceInteraction, whatsapp, discord, signal, acquire, analyze, recovery, attachments, validation, findingNote, findings, investigationEngine, draftReview, draftPreparation, examinationPreparation, caseFolders, reportHistory, mvtReview; var id:String {rawValue}}
struct DeviceItem: Identifiable {let id:String;let platform:String;let status:String}
struct SQLiteItem: Identifiable {let id:Int;let path:String}
struct EvidenceItem: Identifiable { let id: String; let label: String; let platform: String; let imported: String }
struct RunItem: Identifiable { let id: String; let engine: String; let status: String; let records: Int; let summary: String; let detail: String }
struct ReportField: Identifiable {let id:String;let value:String}
struct Artifact: Identifiable {
    let investigatorKind:String;let investigatorNote:String;let observations:[InvestigatorObservation];let originLabel:String
    let id: String; let title: String; let body: String; let timestamp: String; let app: String; let reviewNote:String
    let sender: String; let direction: String; let category: String; let raw: String
    let sourceRef: String; let sourceHash: String; let sourceFile:String; let parser: String; let taskSnapshot:Bool; let reportFields:[ReportField]
    let mediaObservationCount:Int
    let trashSource:Bool
    let autoImagePreview:Bool;let mediaAvailable:Bool
    var dateLabel: String {ReviewContext.dateLabel(timestamp)}
    var kindLabel:String {trashSource ? "MEDIA · TRASH COPY" : category=="recovery" ? "RECOVERY CANDIDATE" : parser.hasPrefix("mulder/") ? (category=="agent_findings" ? "AI FINDING":"TOOL OUTPUT WINDOW") : investigatorKind.isEmpty ? app.uppercased():investigatorKind.replacingOccurrences(of:"-",with:" ").uppercased()}
    init(_ r: [String:Any]) {
        id=r["id"] as? String ?? UUID().uuidString; title=r["display_title"] as? String ?? r["title"] as? String ?? ""
        let presentation=r["investigator_view"] as? [String:Any] ?? [:]
        investigatorKind=presentation["kind"] as? String ?? "";investigatorNote=presentation["note"] as? String ?? ""
        observations=(presentation["observations"] as? [[String:Any]] ?? []).map(InvestigatorObservation.init)
        reviewNote=r["review_note"] as? String ?? ""
        body=r["display_body"] as? String ?? r["body"] as? String ?? ""; timestamp=r["timestamp"] as? String ?? "Undated"
        category=r["category"] as? String ?? ""
        sourceRef=r["source_ref"] as? String ?? "";sourceHash=r["source_sha256"] as? String ?? "Unavailable";sourceFile=r["logical_path"] as? String ?? "Unavailable";parser=r["parser"] as? String ?? ""
        let data=r["data"] as? [String:Any] ?? [:]
        originLabel=parser.hasPrefix("native/") ? "Source evidence · "+URL(fileURLWithPath:sourceFile).lastPathComponent : "Parser report · "+(data["_leapp_report_name"] as? String ?? parser)
        taskSnapshot=["aleapp","import/leapp"].contains(parser) && data["_leapp_report_name"] as? String == "Recent Activity" && !(data["_leapp_fields"] as? [String:String] ?? [:])["Snapshot Image",default:""].isEmpty
        let upstream=data["_leapp_fields"] as? [String:String]
        let fields: [String:Any]=upstream.map { $0.mapValues { $0 as Any } } ?? data
        var orderedKeys:[String]=[];var seen=Set<String>()
        if upstream != nil, let columns=data["_leapp_columns"] as? [String] {
            for key in columns where fields[key] != nil && seen.insert(key).inserted {orderedKeys.append(key)}
        }
        for key in fields.keys.sorted() where seen.insert(key).inserted {orderedKeys.append(key)}
        let byteMedia=data["media"] as? [String:Any] ?? data["attachment"] as? [String:Any] ?? [:]
        mediaAvailable=byteMedia["status"] as? String == "available"
        let imageMime=byteMedia["mime"] as? String ?? data["MIMEType"] as? String ?? ""
        let byteSize=byteMedia["bytes"] as? Int ?? r["size"] as? Int ?? 0
        autoImagePreview=taskSnapshot || ((byteMedia["status"] as? String=="available" || (parser=="exiftool" && r["file_id"] is Int)) && imageMime.hasPrefix("image/") && byteSize<=64*1024*1024)
        let mediaItem=r["media_item"] as? [String:Any]
        mediaObservationCount=mediaItem?["observation_count"] as? Int ?? 0
        trashSource=(mediaItem?["source_contexts"] as? [[String:Any]] ?? []).contains {$0["source_kind"] as? String == "trash"}
        let mediaObservations=mediaItem?["observations"] as? [[String:Any]] ?? []
        let mediaMetadata=mediaObservations.first(where:{$0["parser"] as? String == "exiftool"})?["data"] as? [String:Any]
        let readable=(r["display_fields"] as? [[String:String]])?.map{ReportField(id:$0["name"] ?? "",value:$0["value"] ?? "")}
        reportFields=readable ?? mediaMetadata.map {metadata in
            metadata.keys.sorted().compactMap {key in
                guard let value=metadata[key] else {return nil}
                return ReportField(id:key,value:String(describing:value))
            }
        } ?? (data["_leapp_report_name"] == nil ? [] : orderedKeys.compactMap {key in
            guard upstream != nil || key != "_leapp_report_name", let value=fields[key] as? String else {return nil}
            return ReportField(id:key,value:value)
        })
        let m=data["message"] as? [String:Any] ?? [:]
        app=m["app"] as? String ?? category; sender=m["sender"] as? String ?? ""
        direction=m["direction"] as? String ?? ""
        raw=String(data:(try? JSONSerialization.data(withJSONObject:r,options:[.prettyPrinted,.sortedKeys])) ?? Data(),encoding:.utf8) ?? ""
    }
}
// AppKit supplies native column resizing, keyboard selection and two-axis scrolling.
// Column clicks request source-wide ordering from the backend before pagination.
struct ReportTable: NSViewRepresentable {
    let rows:[Artifact]
    @Binding var selection:String?
    let sortField:String;let ascending:Bool;let onSort:(String,Bool)->Void
    func makeCoordinator() -> Coordinator {Coordinator(self)}
    func makeNSView(context:Context) -> NSScrollView {
        let scroll=NSScrollView()
        let table=NSTableView()
        table.delegate=context.coordinator;table.dataSource=context.coordinator
        table.usesAlternatingRowBackgroundColors=true;table.rowHeight=36
        table.allowsMultipleSelection=false;table.allowsEmptySelection=true
        table.columnAutoresizingStyle = .noColumnAutoresizing
        table.headerView=NSTableHeaderView()
        scroll.hasHorizontalScroller=true;scroll.hasVerticalScroller=true
        scroll.autohidesScrollers=false;scroll.documentView=table
        return scroll
    }
    func updateNSView(_ scroll:NSScrollView,context:Context) {
        guard let table=scroll.documentView as? NSTableView else {return}
        let c=context.coordinator;c.parent=self;c.updating=true
        var seen=Set<String>()
        let columns=rows.flatMap {$0.reportFields.map(\.id)}.filter {seen.insert($0).inserted}
        let columnsChanged=table.tableColumns.map({$0.identifier.rawValue}) != columns
        if columnsChanged {
            for column in table.tableColumns {table.removeTableColumn(column)}
            for name in columns {
                let column=NSTableColumn(identifier:NSUserInterfaceItemIdentifier(name))
                column.title=name;column.width=210;column.minWidth=90
                column.sortDescriptorPrototype=NSSortDescriptor(key:name,ascending:true)
                table.addTableColumn(column)
            }
        }
        table.sortDescriptors=sortField.isEmpty ? [] : [NSSortDescriptor(key:sortField,ascending:ascending)]
        table.reloadData()
        if columnsChanged {scroll.contentView.scroll(to:.zero);scroll.reflectScrolledClipView(scroll.contentView)}
        if let index=rows.firstIndex(where:{$0.id==selection}) {
            table.selectRowIndexes(IndexSet(integer:index),byExtendingSelection:false)
        } else {table.deselectAll(nil)}
        c.updating=false
    }
    final class Coordinator:NSObject,NSTableViewDataSource,NSTableViewDelegate {
        var parent:ReportTable;var updating=false
        init(_ parent:ReportTable) {self.parent=parent}
        func numberOfRows(in tableView:NSTableView) -> Int {parent.rows.count}
        func tableView(_ tableView:NSTableView,viewFor tableColumn:NSTableColumn?,row:Int) -> NSView? {
            guard parent.rows.indices.contains(row),let column=tableColumn else {return nil}
            let id=NSUserInterfaceItemIdentifier("report-cell")
            let cell=(tableView.makeView(withIdentifier:id,owner:self) as? NSTableCellView) ?? NSTableCellView()
            if cell.textField == nil {
                cell.identifier=id
                let text=NSTextField(labelWithString:"")
                text.translatesAutoresizingMaskIntoConstraints=false
                text.font=NSFont.systemFont(ofSize:12);text.maximumNumberOfLines=2
                text.lineBreakMode = .byTruncatingTail
                cell.addSubview(text);cell.textField=text
                NSLayoutConstraint.activate([text.leadingAnchor.constraint(equalTo:cell.leadingAnchor,constant:6),text.trailingAnchor.constraint(equalTo:cell.trailingAnchor,constant:-6),text.centerYAnchor.constraint(equalTo:cell.centerYAnchor)])
            }
            let value=parent.rows[row].reportFields.first(where:{$0.id==column.identifier.rawValue})?.value
            cell.textField?.stringValue=value.map {$0.isEmpty ? "[Empty in source]" : $0} ?? "[Field absent]"
            cell.toolTip=value
            return cell
        }
        func tableView(_ tableView:NSTableView,sortDescriptorsDidChange oldDescriptors:[NSSortDescriptor]) {
            guard !updating,let descriptor=tableView.sortDescriptors.first,let key=descriptor.key else {return}
            parent.onSort(key,descriptor.ascending)
        }
        func tableViewSelectionDidChange(_ notification:Notification) {
            guard !updating,let table=notification.object as? NSTableView else {return}
            parent.selection=parent.rows.indices.contains(table.selectedRow) ? parent.rows[table.selectedRow].id : nil
        }
    }
}
struct ConversationItem: Identifiable { let id: String; let label: String; let app: String; let count: Int; let reports: String }

struct FindingItem: Identifiable {
    let id:String;let note:String;let examiner:String;let created:String;let artifact:Artifact
    init(_ value:[String:Any]) {
        id=value["id"] as? String ?? "";note=value["note"] as? String ?? ""
        examiner=value["examiner"] as? String ?? "";created=value["created_at"] as? String ?? ""
        artifact=Artifact(value["snapshot"] as? [String:Any] ?? [:])
    }
}

@MainActor final class AppModel: ObservableObject {
    @Published var displayedReview:ReviewContext? { didSet { if displayedReview == nil {displayedOffset=0;reviewError=""} } }
    @Published private(set) var displayedOffset=0
    @Published private(set) var reviewError=""
    @Published var caseListError=""
    @Published var caseProfile:[String:Any]=[:]
    @Published var caseTasks:[CaseTaskItem]=[];@Published var caseActivity:[CaseActivityItem]=[]
    @Published var caseTaskOffset=0;@Published var caseTasksMore=false;@Published var openTaskCount=0
    @Published var caseQuery="";@Published var caseQueueStatus="Active";@Published var caseQueueSort="Recent"
    @Published var findings:[FindingItem]=[];@Published var findingOffset=0;@Published var findingTotal=0;@Published var findingsMore=false
    @Published var draftPath=""
    @Published var findingArtifactID="";@Published var findingTitle="";@Published var findingNote="";@Published var findingExaminer=""
    @Published var cases: [CaseItem]=[]; @Published var sources: [SourceItem]=[]
    @Published var rows: [Artifact]=[]; @Published var threads: [ConversationItem]=[]
    @Published var evidenceItems: [EvidenceItem]=[]; @Published var runItems: [RunItem]=[]
    @Published var verification="Not checked this session"
    @Published var validationTitle="Source validation"; @Published var validationText=""; @Published var validationPath=""
    @Published var validationReturn:DesktopDialog?
    @Published var dialog:DesktopDialog?; @Published var selectedPath=""
    @Published var signalIntake:[String:Any]=[:]
    @Published var devices:[DeviceItem]=[]; @Published var sqliteFiles:[SQLiteItem]=[]; @Published var freeGiB:Double=0
    @Published var relatedAttachments:[Artifact]=[]
    lazy var inlineMedia=InlineMediaCache {key in
        let result=try await Self.bridge(["workspace":key.workspace,"action":"preview","case":key.caseID,"artifact_id":key.artifactID]) as? [String:Any] ?? [:]
        return try VerifiedPreviewReceipt(result)
    }
    func imageKey(_ row:Artifact,compact:Bool=false)->InlineMediaKey {
        InlineMediaKey(workspace:workspace,caseID:caseID,artifactID:row.id,fingerprint:row.sourceHash+"|"+row.sourceRef+"|"+row.parser,expectedHash:row.taskSnapshot || row.sourceHash=="Unavailable" ? "":row.sourceHash,pixelSize:compact ? 256:800)
    }
    @Published var previewPath=""; @Published var previewMime=""; @Published var previewShown=false
    @Published var since=""; @Published var until=""
    @Published var categoryCounts:[String:Int]=[:]; @Published var reportNames:[String]=[]; @Published var reportCounts:[String:Int]=[:]
    @Published var reportCategories:[String:[String]]=[:]
    @Published var reportGroups:[String:String]=[:]
    @Published var investigatorView=true;@Published var contactBasis="auto"
    @Published var contactSummary:[String:Int]=[:];@Published var investigatorSummary:[String:Any]=[:]
    func sidebarCount(_ category:String)->Int {
        guard category=="contacts",investigatorView else {return categoryCounts[category,default:0]}
        switch contactBasis {case "source":return contactSummary["source_entries",default:0];case "reports":return contactSummary["report_entries",default:0];case "all":return contactSummary["source_entries",default:0]+contactSummary["report_entries",default:0];default:return contactSummary["default_entries"] ?? categoryCounts[category,default:0]}
    }
    @Published var reportFilter=""; @Published var dateAnchor="latest"; @Published var rangeDays=0; @Published var undated=0
    @Published var caseID=""; @Published var sourceID=""; @Published var conversation=""
    @Published var sortMode="text";@Published var sortField="";@Published var sortAscending=true
    @Published var searchMode="text";@Published var query=""; @Published var appFilter=""; @Published var mode="Cases"
    @Published var busy=false; @Published var status="Opening workspace…"; @Published var notice=""
    @Published var showNotice=false; @Published var offset=0; @Published var hasMore=false
    @Published var selected: String?; @Published var coverage=""; @Published var incomplete=false
    @Published var catalogRoots=[String]()
    @Published var catalogWarnings=[String]();@Published var catalogPartial=false
    @Published var creationWorkspace:String
    @Published var workspace: String
    init() {
        let configured=Bundle.main.object(forInfoDictionaryKey:"LawlietWorkspace") as? String ?? ""
        let preferred=UserDefaults.standard.string(forKey:"workspace") ?? configured
        // This workspace moved off the failed drive. Do not touch that stale path.
        let saved=preferred.hasPrefix("/Volumes/easystore/") ? configured:preferred
        workspace=saved.isEmpty ? "":URL(fileURLWithPath:saved).resolvingSymlinksInPath().path
        let storedCreation=UserDefaults.standard.string(forKey:"catalog.creationWorkspace") ?? configured
        creationWorkspace=storedCreation.hasPrefix("/Volumes/easystore/") ? configured:storedCreation
        catalogRoots=CaseCatalog.initialRoots(saved:UserDefaults.standard.stringArray(forKey:"catalog.roots"),configured:configured,creation:creationWorkspace,current:workspace)
    }
    var source: SourceItem? { sources.first { $0.id == sourceID } }
    var selectedArtifact: Artifact? { rows.first { $0.id == selected } }
    var appNames: [String] { Array(Set(threads.map{$0.app})).sorted() }
    func params() -> [String:Any] {
        var p:[String:Any]=["case":caseID]
        if let s=source {p.merge(s.queryFields){_,new in new}}
        return p
    }
    func recordParams() -> [String:Any] {
        var p=params();p[searchMode == "phone" ? "phone_query":"query"]=query;p["report"]=reportFilter
        if investigatorView {p["presentation"]="investigator";if mode=="Contacts" {p["contact_basis"]=contactBasis}}
        if !sortField.isEmpty {p["sort_mode"]=sortMode;p["sort_field"]=sortField;p["sort_direction"]=sortAscending ? "asc":"desc"}
        if mode=="Messages" {p["app"]=appFilter;p["conversation"]=conversation}
        if mode == "Trash photos" {p["media_state"]="trash"}
        if mode == "Browser" {p["view_group"]="browser"}
        if let category=EvidenceSidebarNavigation.category(for:mode,counts:categoryCounts) {p["category"]=category};p["since"]=since;p["until"]=until;return p
    }
    nonisolated static func bridge(_ p:[String:Any]) async throws -> Any {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos:.userInitiated).async {
                do {
                    guard let python=Bundle.main.object(forInfoDictionaryKey:"LawlietPython") as? String,
                          let resources=Bundle.main.resourceURL else {throw NSError(domain:"Lawliet",code:1,userInfo:[NSLocalizedDescriptionKey:"Application configuration is missing."])}
                    var env=ProcessInfo.processInfo.environment;env["PYTHONPATH"]=resources.path;env["PYTHONDONTWRITEBYTECODE"]="1"
                    let isCatalog=["catalog","report-history"].contains(p["action"] as? String ?? "")
                    let isListing=isCatalog || p["action"] as? String == "cases"
                    let arguments=isCatalog ? [resources.appendingPathComponent("catalog_backend.py").path]:["-m","lawliet_mobile.app_backend"]
                    let reply=try BackendProcess.run(executable:URL(fileURLWithPath:python),arguments:arguments,environment:env,inputData:JSONSerialization.data(withJSONObject:p),listingTimeout:isListing ? 30:nil)
                    if isListing && reply.signalled {
                        throw NSError(domain:"Lawliet",code:4,userInfo:[NSLocalizedDescriptionKey:"Case listing stopped before completing. Check any macOS folder-access prompt, then use Change workspace to select your case folder again. No acquisition or parsing was started."])
                    }
                    continuation.resume(returning:try reply.decode())
                } catch {continuation.resume(throwing:error)}
            }
        }
    }
    func request(_ action:String,_ values:[String:Any]=[:]) async throws -> Any {
        var p=values;p["workspace"]=workspace;p["action"]=action;return try await Self.bridge(p)
    }
    func perform(_ message:String,onError:((Error)->Void)?=nil,_ job:@escaping @MainActor () async throws -> Void) {
        guard !busy else {return};busy=true;status=message;inlineMedia.pause(true)
        Task {await inlineMedia.waitUntilIdle();do {try await job();status=caseListError.isEmpty ? "Case workspace · Ready":"Workspace needs attention"} catch {if let onError=onError {onError(error)} else {notice=error.localizedDescription;showNotice=true};status="Operation needs attention"};busy=false;inlineMedia.pause(false)}
    }
    func refreshCases() {
        perform("Opening cases…") {try await self.loadCases()}
    }
    func loadCases() async throws {
        try await reloadCaseList()
        if caseID.isEmpty {caseID=UserDefaults.standard.string(forKey:"selectedCase:"+workspace) ?? ""}
        if caseID.isEmpty {mode="Cases";return}
        if !cases.contains(where:{$0.id==currentCasePath && $0.available}) {
            let inventory=cases,folderDialog=dialog == .caseFolders;invalidateWorkspaceView();cases=inventory;workspace=creationWorkspace;UserDefaults.standard.set(workspace,forKey:"workspace");if folderDialog {dialog = .caseFolders};return
        }
        try await loadCase()
    }
    func loadCase(preferredEvidence:String?=nil) async throws {
        draftPath=""
        findings=[];findingTotal=0;findingOffset=0;findingsMore=false;findingArtifactID="";findingTitle="";findingNote=""
        validationReturn=nil
        displayedReview=nil
        rows=[];threads=[];selected=nil;searchMode="text";conversation="";query="";appFilter="";since="";until="";offset=0;sources=[]
        caseProfile=[:];caseTasks=[];caseActivity=[];caseTaskOffset=0;openTaskCount=0;caseTasksMore=false
        evidenceItems=[];runItems=[];categoryCounts=[:];reportNames=[];reportCounts=[:];reportCategories=[:];reportGroups=[:];incomplete=false;coverage="";verification="Not checked this session"
        guard !caseID.isEmpty else {mode="Cases";return}
        UserDefaults.standard.set(caseID,forKey:"selectedCase:"+workspace)
        UserDefaults.standard.set(workspace,forKey:"workspace")
        try await loadCaseManagement()
        let result=try await request("overview",["case":caseID]) as? [String:Any] ?? [:]
        sources=(result["sources"] as? [[String:Any]] ?? []).map { SourceItem(id:$0["id"] as? String ?? "",label:$0["label"] as? String ?? "",evidence:$0["evidence"] as? String ?? "",parser:$0["parser"] as? String ?? "",run:$0["run"] as? String,records:$0["records"] as? Int ?? 0) }
        evidenceItems=(result["evidence"] as? [[String:Any]] ?? []).map { EvidenceItem(id:$0["id"] as? String ?? "",label:$0["label"] as? String ?? "",platform:$0["platform"] as? String ?? "unknown",imported:$0["imported_at"] as? String ?? "") }
        if sources.count>1 && sources.contains(where:{$0.hasResults}) {
            let stats=try await request("source-stats",["case":caseID]) as? [String:Any] ?? [:]
            guard let count=stats["total"] as? Int else {throw DraftReviewError.invalid("Case-wide record count is unavailable.")}
            sources.insert(SourceItem(id:SourceItem.caseWideID,label:"All parsed sources in this case",evidence:"",parser:"",run:nil,records:count),at:0)
        }
        let c=result["coverage"] as? [String:Any] ?? [:]
        runItems=(c["analysis_runs"] as? [[String:Any]] ?? []).map { row in
            let raw=row["detail"] as? String ?? "{}"
            let detail=(try? JSONSerialization.jsonObject(with:Data(raw.utf8))) as? [String:Any] ?? [:]
            let diagnostics=detail["diagnostics"] as? [String:Any] ?? [:]
            let failures=diagnostics["failed_artifacts"] as? [String] ?? []
            let errors=diagnostics["error_lines"] as? [String] ?? []
            let reports=detail["reports"] as? [[String:Any]] ?? []
            let missing=diagnostics["missing_input_notices"] as? Int ?? 0
            let status=row["status"] as? String ?? ""
            var summary=reports.isEmpty ? "" : "\(reports.count) TSV reports indexed. "
            if !failures.isEmpty || !errors.isEmpty { summary += "Engine reported failures or errors. " }
            if missing > 0 { summary += "\(missing) missing-input notices; these do not establish absence on the phone. " }
            if let error=detail["error"] as? String {summary += error}
            return RunItem(id:row["id"] as? String ?? "",engine:row["engine"] as? String ?? "",status:status == "complete" && (!failures.isEmpty || !errors.isEmpty) ? "Needs review" : status,records:row["records"] as? Int ?? 0,summary:summary,detail:raw)
        }
        verification="Not checked this session"
        coverage=String(data:try JSONSerialization.data(withJSONObject:result,options:[.prettyPrinted,.sortedKeys]),encoding:.utf8) ?? ""
        incomplete=(c["collection_attempts"] as? [[String:Any]] ?? []).contains { ($0["status"] as? String) != "complete" }
        sourceID=SourceItem.selectedID(in:sources,current:sourceID,preferredEvidence:preferredEvidence)
        try await loadSource()
    }
    func loadSource() async throws {
        displayedReview=nil;contactSummary=[:];investigatorSummary=[:];contactBasis="auto"
        rows=[];threads=[];selected=nil;searchMode="text";conversation="";offset=0;appFilter="";reportFilter="";sortField="";sortMode="text";since="";until="";rangeDays=0;categoryCounts=[:];reportNames=[];reportCounts=[:];reportCategories=[:];reportGroups=[:]
        guard source != nil else {return}
        let stats=try await request("source-stats",params()) as? [String:Any] ?? [:]
        categoryCounts=stats["categories"] as? [String:Int] ?? [:]
        contactSummary=stats["contact_entries"] as? [String:Int] ?? [:]
        for (group,count) in stats["view_groups"] as? [String:Int] ?? [:] {categoryCounts[group]=count}
        reportNames=(stats["reports"] as? [[String:Any]] ?? []).compactMap{$0["name"] as? String}
        reportCounts=Dictionary(uniqueKeysWithValues:(stats["reports"] as? [[String:Any]] ?? []).compactMap {r in guard let name=r["name"] as? String else {return nil};return (name,r["records"] as? Int ?? 0)})
        reportCategories=Dictionary(uniqueKeysWithValues:(stats["reports"] as? [[String:Any]] ?? []).compactMap {r in guard let name=r["name"] as? String else {return nil};return (name,r["categories"] as? [String] ?? [])})
        reportGroups=Dictionary(uniqueKeysWithValues:(stats["reports"] as? [[String:Any]] ?? []).compactMap {r in guard let name=r["name"] as? String,let group=r["view_group"] as? String else {return nil};return (name,group)})
        undated=stats["undated"] as? Int ?? 0
        let list=try await request("conversations",params()) as? [[String:Any]] ?? []
        threads=list.map { ConversationItem(id:$0["conversation_id"] as? String ?? "",label:($0["label"] as? String).flatMap{$0.isEmpty ? nil:$0} ?? ($0["conversation"] as? String ?? "Unlinked"),app:$0["app"] as? String ?? "unknown",count:$0["records"] as? Int ?? 0,reports:($0["reports"] as? [String] ?? []).joined(separator:" · ")) }
        if threads.isEmpty && mode == "Messages" {mode="Timeline"}
        try await loadRecords()
    }
    func loadRecords() async throws {
        guard source != nil else {rows=[];return}
        let requestedOffset=offset
        var p=recordParams();let submitted=ReviewContext(p);p["offset"]=requestedOffset
        do {
            let result=try await request("records",p) as? [String:Any] ?? [:]
            rows=(result["records"] as? [[String:Any]] ?? []).map(Artifact.init)
            investigatorSummary=result["summary"] as? [String:Any] ?? [:]
            hasMore=result["has_more"] as? Bool ?? false;selected=rows.first?.id
            displayedReview=submitted;displayedOffset=requestedOffset;reviewError=""
        } catch {
            offset=displayedOffset;reviewError=error.localizedDescription
            throw error
        }
    }
    func search() {offset=0;perform("Searching the complete selected source…") {try await self.loadRecords()} }
    func searchField(_ value:String, phone:Bool=false) {
        guard !value.isEmpty else {return}
        let contactPhone=phone && mode=="Contacts" && investigatorView
        mode=contactPhone ? "Contacts":"All artifacts";searchMode=phone ? "phone":"text";query=value;appFilter="";conversation="";reportFilter=""
        sortField="";sortMode="text";since="";until="";rangeDays=0;search()
    }
    func setRange(_ days:Int) {
        if days==0 {rangeDays=0;since="";until="";search();return}
        perform("Applying date range…") {
            var p=self.params();p["days"]=days;p["anchor"]=self.dateAnchor
            let r=try await self.request("date-range",p) as? [String:Any] ?? [:]
            self.rangeDays=days;self.since=r["since"] as? String ?? "";self.until=r["until"] as? String ?? "";self.offset=0
            try await self.loadRecords()
        }
    }
    func clearFilters() {searchMode="text";query="";appFilter="";conversation="";reportFilter="";sortField="";sortMode="text";since="";until="";rangeDays=0;search()}
    var emptyReason:String {
        if !reviewError.isEmpty {return "Review request failed. No successful result is available for this request. " + reviewError}
        if reviewNeedsApply {return "The previous search returned no records. Apply your edited criteria to run a new search."}
        if source?.hasResults == false {return "No indexed artifact source is available for this evidence. Open Evidence & processing to inspect retained runs and their status."}
        if source?.records == 0 {return "No indexed records were returned for this scope. Inspect Evidence & processing and Coverage & review for unsupported data, failures or missing evidence. Zero parsed rows do not establish absence on the phone."}
        if !reportFilter.isEmpty,reportCounts[reportFilter] == 0 {
            return "This retained report contains zero indexed rows. That does not establish that the corresponding data is absent from the phone."
        }
        let cat=recordParams()["category"] as? String
        if let cat=cat,categoryCounts[cat,default:0]==0 {
            return "This source has no indexed \(mode.lowercased()) records. It may contain only messages, lack the required database, or use an unmapped report schema. Check All artifacts and the report selector. An empty view does not prove absence on the phone."
        }
        return "No records match these filters. Clear filters to include all dates and undated records in this view."
    }
    func importFolder() {
        let p=NSOpenPanel();p.canChooseDirectories=true;p.canChooseFiles=false;p.prompt="Import LEAPP output"
        p.message="Select the complete ALEAPP or iLEAPP output folder. All TSV reports are indexed together; original files are retained."
        guard p.runModal() == .OK,let url=p.url else {return}
        perform("Importing all LEAPP reports…") {
            let result=try await self.request("import",["case":self.caseID,"path":url.path,"format":"folder"]) as? [String:Any] ?? [:]
            self.sourceID=result["source_id"] as? String ?? ""
            self.mode="All artifacts";try await self.loadCase()
            self.notice="Imported \(result["records"] as? Int ?? 0) rows. Use Report to choose an upstream table; select a record to read its fields."
            self.showNotice=true
        }
    }
    func chooseWorkspace() {addCatalogFolder()}
    func importReport() {
        let panel=NSOpenPanel();panel.allowedContentTypes=[UTType(filenameExtension:"jsonl") ?? .data,UTType(filenameExtension:"tsv") ?? .tabSeparatedText];panel.message="Import Lawliet JSONL or a LEAPP TSV export. Original report bytes are retained and hashed.";panel.prompt="Import parsed data"
        guard panel.runModal() == .OK,let url=panel.url else {return}
        perform("Importing and indexing \(url.lastPathComponent)…") {
            let result=try await self.request("import",["case":self.caseID,"path":url.path,"format":url.pathExtension.lowercased()=="tsv" ? "tsv":"jsonl"]) as? [String:Any] ?? [:]
            self.sourceID=result["source_id"] as? String ?? "";self.mode="All artifacts";try await self.loadCase()
            self.notice=result["status"] as? String == "already_imported" ? "This exact report is already imported. Opened its existing source." : "Imported \(result["records"] as? Int ?? 0) records. Source claims remain linked to the imported report.";self.showNotice=true
        }
    }
    func importEvidence() {
        let p=NSOpenPanel();p.canChooseDirectories=true;p.canChooseFiles=true;p.prompt="Import evidence"
        p.message="Lawliet preserves the input and runs the applicable configured platform/export parser. Unrecognized inputs stay retained for explicit analysis. Use parsed-data import to open existing reports without rerunning tools."
        guard p.runModal() == .OK,let url=p.url else {return}
        perform("Importing evidence and running the platform parser…") {let r=try await self.request("import-evidence",["case":self.caseID,"path":url.path,"engine":"auto"]) as? [String:Any] ?? [:];self.sourceID=r["source_id"] as? String ?? "";self.mode="All artifacts";try await self.loadCase();self.notice=r["message"] as? String ?? "Processing finished. Check Sources.";self.showNotice=true}
    }
    func chooseAppBackup(_ kind:DesktopDialog) {
        let p=NSOpenPanel();p.canChooseDirectories=true;p.canChooseFiles=true
        p.message=kind == .whatsapp ? "Choose a WhatsApp text export, ZIP or export folder with its media.":kind == .discord ? "Choose the customer's supplied Discord account data package ZIP or folder.":"Choose a supplied Signal backup. LAWLIET checks the format and decoder before asking for a passphrase."
        guard p.runModal() == .OK,let url=p.url else {return};selectedPath=url.path
        if kind == .signal {signalIntake=[:];perform("Checking Signal backup format and decoder…") {self.signalIntake=try await self.request("signal-preflight",["case":self.caseID,"path":url.path]) as? [String:Any] ?? [:];self.dialog=kind}}
        else {dialog=kind}
    }
    func acquireDevices() {perform("Checking connected devices and host storage…") {
        let r=try await self.request("devices") as? [String:Any] ?? [:];self.freeGiB=r["free_gib"] as? Double ?? 0
        self.devices=(r["devices"] as? [[String:Any]] ?? []).compactMap {d in guard let serial=d["serial"] as? String else {return nil};return DeviceItem(id:serial,platform:d["platform"] as? String ?? "",status:d["status"] as? String ?? "")};self.dialog = .acquire
    }}
    func recoveryFiles() {guard let source=source else {return};perform("Finding source SQLite databases…") {
        let r=try await self.request("sqlite-files",["case":self.caseID,"evidence":source.evidence]) as? [[String:Any]] ?? []
        self.sqliteFiles=r.map{SQLiteItem(id:$0["id"] as? Int ?? 0,path:$0["logical_path"] as? String ?? "")};self.dialog = .recovery
    }}
    func showAttachments() {guard let row=selectedArtifact else {return};perform("Finding exact attachment links…") {let records=try await self.request("related-attachments",["case":self.caseID,"artifact_id":row.id]) as? [[String:Any]] ?? [];self.relatedAttachments=records.map(Artifact.init);self.dialog = .attachments}}
    func previewSelected(_ artifact:Artifact?=nil) {guard let row=artifact ?? selectedArtifact else {return};perform("Verifying media bytes…") {
        let r=try await self.request("preview",["case":self.caseID,"artifact_id":row.id]) as? [String:Any] ?? [:]
        self.previewPath=r["path"] as? String ?? "";self.previewMime=r["mime"] as? String ?? "";self.previewShown=true
    }}
    func assessAndroid(_ serial:String) {dialog=nil;perform("Assessing Android access; no settings changes…") {
        let r=try await self.request("assess-android",["case":self.caseID,"serial":serial]) as? [String:Any] ?? [:]
        self.validationReturn=nil;self.validationTitle="Android access assessment";self.validationPath=r["path"] as? String ?? ""
        let providers=r["providers"] as? [String:[String:Any]] ?? [:]
        let routes=r["routes"] as? [[String:Any]] ?? []
        self.validationText="Status: \(r["status"] as? String ?? "unknown")\n\(r["error"] as? String ?? "")\n"+providers.keys.sorted().map{"\($0): \(providers[$0]?["state"] as? String ?? "unresolved")"}.joined(separator:"\n")+"\n\n"+routes.map{"\($0["artifact"] as? String ?? "") — \($0["route"] as? String ?? "")\n\($0["limit"] as? String ?? "")"}.joined(separator:"\n\n")+"\n\nID-only permission probes; no permission or security setting changes. This assessment does not establish collection completeness."
        self.dialog = .validation
    }}
    func analysisPlan(_ engine:String="auto") {guard source != nil else {return};perform("Inspecting evidence; no tools will run…") {
        var p=self.params();p["profile"]=engine=="auto" ? "standard":"custom"
        if engine != "auto" {p["tools"]=[engine]}
        let r=try await self.request("analysis-plan",p) as? [String:Any] ?? [:]
        self.validationReturn = .analyze;self.validationTitle="Analysis preview";self.validationPath=""
        let counts=r["format_indicators"] as? [String:Int] ?? [:]
        let tasks=r["tasks"] as? [[String:Any]] ?? []
        let taskText=tasks.map {t in
            let file=t["file"] as? [String:Any]
            return "\(t["tool"] as? String ?? "") · \((t["state"] as? String ?? "").replacingOccurrences(of:"_",with:" "))\n\(file?["path"] as? String ?? "Selected evidence source")\n\(t["scope_note"] as? String ?? "")"
        }.joined(separator:"\n\n")
        var sections=["Preview only · no analysis started"]
        let inspected=r["inspected_files"] as? Int ?? 0
        let total=r["inventory_files"] as? Int ?? 0
        sections.append("Inspected \(inspected) of \(total) files")
        var indicators=[String]()
        for key in counts.keys.sorted() {
            let count=counts[key] ?? 0
            if count>0 {indicators.append("\(key.replacingOccurrences(of:"_",with:" ")): \(count)")}
        }
        sections.append("Format indicators\n"+indicators.joined(separator:"\n"))
        sections.append("Proposed tasks\n"+(taskText.isEmpty ? "No tasks proposed.":taskText))
        sections.append(contentsOf:r["warnings"] as? [String] ?? [])
        sections.append(contentsOf:r["limitations"] as? [String] ?? [])
        self.validationText=sections.joined(separator:"\n\n")
        self.dialog = .validation
    }}
    func appCoverage() {guard source != nil else {return};perform("Checking acquired app indicators…") {
        let r=try await self.request("app-coverage",self.params()) as? [String:Any] ?? [:]
        self.validationReturn=nil;self.validationTitle="App evidence coverage";self.validationPath=""
        let apps=r["apps"] as? [[String:Any]] ?? []
        self.validationText="Selected evidence: \(r["evidence_id"] as? String ?? "")\nParsing run: \(r["run"] as? String ?? "All indexed runs")\n\n"+apps.map {a in
            let count=a["message_rows"] as? Int ?? 0
            let files=a["candidate_files"] as? Int ?? 0
            let storage=a["candidate_files_by_storage"] as? [String:Int] ?? [:]
            let storageSummary="Private paths: \(storage["private"] ?? 0) · External data: \(storage["external_data"] ?? 0) · External media: \(storage["external_media"] ?? 0)"
            let first=a["first_message_utc"] as? String
            let last=a["last_message_utc"] as? String
            let dates=first != nil && last != nil ? "Observed dates: \(first!) to \(last!)" : "No dated messages indexed"
            return "\((a["app"] as? String ?? "App").capitalized)\n\(files) candidate files · \(count) indexed message rows\n\(storageSummary)\n\(dates)\n\(a["undated_message_rows"] as? Int ?? 0) undated message rows\n\(a["next_step"] as? String ?? "")"
        }.joined(separator:"\n\n")+"\n\nScope and limitations\n"+(r["limitations"] as? [String] ?? []).joined(separator:"\n\n")
        self.dialog = .validation
    }}
    func validateSource() {guard source != nil else {return};perform("Validating source records, inventory and hashes…") {
        let r=try await self.request("validate",self.params()) as? [String:Any] ?? [:]
        self.validationReturn=nil;self.validationTitle="Source validation";self.validationPath=r["path"] as? String ?? ""
        let checks=r["checks"] as? [[String:Any]] ?? []
        self.validationText="Status: \(r["status"] as? String ?? "unknown")\n\n"+checks.map {c in
            var lines=["\(c["check"] as? String ?? "Check"): \(c["status"] as? String ?? "unknown")"]
            for key in ["reason","note","source_rows","distinct_indexed_source_rows","plaintext_comparisons","timestamp_comparisons","timestamp_precision_loss_rows","declared_files","missing_count","exact_field_rows","mapping_review_rows","display_mismatch_rows","failure_count"] {if let value=c[key] {lines.append("\(key.replacingOccurrences(of:"_",with:" ")): \(value)")}}
            for key in ["mismatches","missing_source_row_ids","unexpected_source_row_ids"] {if let list=c[key] as? [Any] {lines.append("\(key.replacingOccurrences(of:"_",with:" ")): \(list.count)")}}
            return lines.joined(separator:"\n")
        }.joined(separator:"\n\n")+"\n\nThese checks concern acquired evidence. They do not establish complete phone acquisition. Full details are retained in the validation report."
        self.dialog = .validation
    }}
    func prepareFinding() {
        guard let record=selectedArtifact else {return}
        findingArtifactID=record.id;findingTitle=record.title;findingNote="";dialog = .findingNote
    }
    func saveFinding() {
        let values:[String:Any]=["case":caseID,"artifact_id":findingArtifactID,"note":findingNote,"examiner":findingExaminer]
        dialog=nil
        perform("Saving examiner finding…") {_ = try await self.request("finding-add",values);self.notice="Finding saved with a record snapshot. Parsed evidence is unchanged.";self.showNotice=true}
    }
    func loadFindings(offset:Int=0) {
        perform("Loading saved findings…") {
            let result=try await self.request("findings",["case":self.caseID,"offset":offset]) as? [String:Any] ?? [:]
            self.findings=(result["findings"] as? [[String:Any]] ?? []).map{FindingItem($0)}
            self.findingOffset=offset;self.findingTotal=result["total"] as? Int ?? 0;self.findingsMore=result["has_more"] as? Bool ?? false
            self.dialog = .findings
        }
    }
    func exportFindings(format:String="jsonl") {
        let panel=NSSavePanel();panel.nameFieldStringValue="lawliet-findings";panel.allowedContentTypes=format == "text" ? [.plainText]:[UTType(filenameExtension:"jsonl") ?? .data]
        panel.message="Export all saved findings in this case, including examiner notes and source references. Text is a readable summary; JSONL retains complete snapshots. Choose a new filename."
        guard panel.runModal() == .OK,let url=panel.url else {return}
        dialog=nil
        perform("Exporting saved findings…") {
            let result=try await self.request("findings-export",["case":self.caseID,"path":url.path,"format":format]) as? [String:Any] ?? [:]
            self.notice="Exported \(result["records"] as? Int ?? 0) findings. A SHA-256 receipt was saved beside the export file. Source evidence was not reverified during export.";self.showNotice=true
        }
    }
    func exportRows() {
        guard !busy && !reviewNeedsApply else {return}
        let panel=NSSavePanel();panel.nameFieldStringValue="lawliet-records.jsonl";panel.allowedContentTypes=[UTType(filenameExtension:"jsonl") ?? .data]
        guard panel.runModal() == .OK,let url=panel.url else {return}
        var p=recordParams();p["path"]=url.path
        perform("Exporting every matching row…") {let r=try await self.request("export",p) as? [String:Any] ?? [:];self.notice="Exported \(r["records"] as? Int ?? 0) matching records.";self.showNotice=true}
    }
}

struct ContentView: View {
    @AppStorage("appearance.mode") private var appearanceMode="dark"
    private var appearance:ColorScheme? {appearanceMode == "system" ? nil:(appearanceMode == "light" ? .light:.dark)}
    @StateObject private var m=AppModel()
    @State private var newCase=false
    @State private var sqliteResultScope:SQLiteResultScope?
    @State private var caseName="";@State private var newID="";@State private var examiner=""
    @State private var threadSearch=""
    private var visibleThreads:[ConversationItem] {m.threads.filter{(m.appFilter.isEmpty || $0.app == m.appFilter) && (threadSearch.isEmpty || $0.label.localizedCaseInsensitiveContains(threadSearch) || $0.reports.localizedCaseInsensitiveContains(threadSearch))}}
    @State private var reportTable=true
    @AppStorage("review.artifactLayout") private var artifactLayout="table"
    @State private var artifactColumns=ArtifactTable.defaultColumns
    private var usesArtifactTable:Bool {artifactLayout=="table" && !["Media","Trash photos","Attachments"].contains(m.mode)}
    @AppStorage("review.showFilters") private var showFilters=false
    @AppStorage("review.showInspector") private var showInspector=true
    @AppStorage("review.showSidebar") private var showSidebar=true
    @FocusState private var artifactSearchFocused:Bool
    @State private var dateOrder="dmy";@State private var zone="";@State private var secret=""
    @State private var yearCentury="";@State private var chatPath=""
    private var centuryError:String {do {_ = try ChatDateInterpretation.centuryFields(yearCentury);return ""} catch {return error.localizedDescription}}
    @State private var selectedDevice="";@State private var budget=20;@State private var profile="messages";@State private var iosProfile="ios-apps"
    @State private var acquisitionReadiness=""
    @State private var sharedPath="/sdcard/DCIM"
    @State private var engine="auto";@State private var sqliteID=0
    @State private var recoveryEngine="sqlite-dissect"
    private let sections=["All artifacts","Timeline","Messages","Calls","Contacts","Browser","Media","Trash photos","Attachments","Recovery"]
    private let icons=["Search":"magnifyingglass","All artifacts":"square.grid.2x2","Messages":"bubble.left.and.bubble.right","Calls":"phone","Contacts":"person.crop.rectangle","Browser":"globe","Media":"photo","Trash photos":"trash","Attachments":"paperclip","Timeline":"clock","Recovery":"arrow.uturn.backward","Sources":"doc.text.magnifyingglass"]
    private let accent=LawlietTheme.accent
    var body: some View {
        HStack(spacing:0) {
            if showSidebar {sidebar;Divider()}
            VStack(spacing:0) {
                if m.mode=="Cases" {CaseBrowserView(m:m,newCase:{newCase=true})}
                else if m.mode=="Capability coverage" {CapabilityCoverageView()}
                else if m.mode=="Coverage" {CoverageReviewView(m:m).id(m.workspace+":"+m.caseID)}
                else {
                header
                if m.incomplete {HStack{Image(systemName:"exclamationmark.triangle");Text("This case includes incomplete acquisition attempts. Available records do not establish a complete phone extraction.").font(.caption);Spacer()}.foregroundStyle(.orange).padding(12).background(.orange.opacity(0.07))}
                if m.source?.parser.hasPrefix("import/") == true {HStack {Image(systemName:"doc.text");Text("Imported parser report · Original device completeness is not established by this file.").font(.caption);Spacer()}.padding(10).background(LawlietTheme.panel)}
                if m.mode=="Case overview" {CaseOverviewView(m:m).id(m.currentCasePath)}
                else if m.mode=="Sources" {sourcesView}
                else if m.mode=="Evidence files" {EvidenceFilesView(m:m).id(m.currentCasePath+":"+m.sourceID)}
                else if m.source == nil {emptyState}
                else {reviewContent}
                }
                Divider()
                HStack {Button {showSidebar.toggle()} label:{Image(systemName:"sidebar.left")}.buttonStyle(.plain).accessibilityLabel(showSidebar ? "Hide navigation sidebar":"Show navigation sidebar").help("Toggle sidebar · ⌃⌘S");if !showSidebar && m.mode != "Cases" {Button("Cases"){navigate("Cases")}.buttonStyle(.plain)};if !showSidebar {Button("Coverage"){navigate("Capability coverage")}.buttonStyle(.plain).disabled(m.busy)};if !showSidebar {Button {m.dialog = .deviceInteraction} label:{Label("Connected device",systemImage:"iphone")}.buttonStyle(.plain).disabled(m.busy)};if !showSidebar {Menu {Picker("Appearance",selection:$appearanceMode){Text("Dark purple").tag("dark");Text("Light inverse").tag("light");Text("Follow system").tag("system")}} label:{Image(systemName:"circle.lefthalf.filled")}.help("Appearance").accessibilityLabel("Appearance")};if m.busy {ProgressView().controlSize(.small)};Text(m.status).font(.caption).foregroundStyle(LawlietTheme.secondary);Spacer();if !m.caseID.isEmpty {Text(m.caseID).font(.system(size:10,design:.monospaced)).textSelection(.enabled)};Text("Local workspace").font(.caption2).foregroundStyle(LawlietTheme.secondary)}.padding(.horizontal,12).padding(.vertical,7)
            }
        }.controlSize(.small).font(.system(size:12)).frame(minWidth:1100,minHeight:700).background(LawlietTheme.background).preferredColorScheme(appearance).foregroundStyle(LawlietTheme.text).tint(accent)
        .task {m.refreshCases()}
        .sheet(item:$m.dialog){dialog in
            if dialog == .deviceInteraction {DeviceInteractionView(workspace:m.workspace.isEmpty ? m.creationWorkspace:m.workspace)}
            else if dialog == .investigationEngine { EngineInvestigationView(m:m) }
            else if dialog == .draftReview { DraftReviewView(m:m) }
            else if dialog == .draftPreparation { DraftPreparationView(m:m) }
            else if dialog == .examinationPreparation { ExaminationPreparationView(m:m) }
            else if dialog == .caseFolders {CaseFoldersView(m:m)}
            else if dialog == .reportHistory {ReportHistoryView(m:m)}
            else if dialog == .mvtReview {MVTReviewView(m:m)}
            else { actionSheet(dialog) }
        }
        .onChange(of:m.selectedPath){_ in yearCentury="";secret="";chatPath="";zone=""}
        .onChange(of:m.currentCasePath){_ in yearCentury="";secret="";sqliteResultScope=nil;m.inlineMedia.setScope(m.currentCasePath)}
        .onChange(of:m.dialog){value in if value != .signal {secret=""}}
        .sheet(isPresented:$m.previewShown){MediaPreview(path:m.previewPath,mime:m.previewMime)}
        .sheet(item:$sqliteResultScope){scope in SQLiteResultReviewView(scope:scope).id(scope.id)}
        .alert("LAWLIET",isPresented:$m.showNotice){Button("OK",role:.cancel){}}message:{Text(m.notice)}
        .sheet(isPresented:$newCase){VStack(alignment:.leading,spacing:18){Text("New case").font(.system(size:18,weight:.semibold));TextField("Case ID (letters, digits, underscores or hyphens)",text:$newID);TextField("Case name",text:$caseName);TextField("Examiner",text:$examiner);Text("New case folder: \(m.creationWorkspace)").font(.caption).foregroundStyle(LawlietTheme.secondary);HStack{Button("Cancel"){newCase=false};Spacer();Button("Create case"){newCase=false;m.perform("Creating case…"){_ = try await AppModel.bridge(["action":"create","workspace":m.creationWorkspace,"id":newID,"name":caseName.isEmpty ? newID:caseName,"examiner":examiner]);m.workspace=m.creationWorkspace;m.caseID=newID;m.sourceID="";m.mode="Case overview";try await m.loadCases();newID="";caseName=""}}.disabled(newID.range(of:"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$",options:.regularExpression)==nil).keyboardShortcut(.defaultAction)}}.padding(28).frame(width:440)}
    }
    private func navigate(_ name:String) {
        m.mode=name
        if !["Cases","Case overview","Sources","Coverage","Capability coverage"].contains(name) {m.conversation="";m.reportFilter="";m.search()}
    }
    private func navigationButton(_ title:String,_ icon:String,_ mode:String) -> some View {
        Button {navigate(mode)} label:{HStack(spacing:8){Image(systemName:icon).frame(width:16);Text(title);Spacer()}.padding(.horizontal,8).padding(.vertical,7).background(m.mode==mode ? accent.opacity(0.12):.clear).cornerRadius(5)}.buttonStyle(.plain).disabled(m.busy || (!["Cases","Capability coverage"].contains(mode) && m.caseID.isEmpty))
    }
    private var sidebar:some View {
        VStack(alignment:.leading,spacing:6) {
            VStack(alignment:.center,spacing:4) {
                if let url=Bundle.main.url(forResource:"lawliet-wordmark",withExtension:"png"),let image=NSImage(contentsOf:url) {
                    Rectangle().fill(LawlietTheme.logo).frame(width:164,height:54)
                        .mask {Image(nsImage:image).resizable().scaledToFit().luminanceToAlpha()}
                        .accessibilityLabel("LAWLIET")
                } else {Text("LAWLIET").font(.system(size:16,weight:.semibold)).tracking(2)}
                Text("MOBILE FORENSICS").font(.system(size:9,weight:.medium)).tracking(1.4).foregroundStyle(LawlietTheme.secondary)
            }.frame(maxWidth:.infinity,alignment:.center).padding(.top,12).padding(.bottom,16)
            navigationButton("Cases","folder","Cases")
            navigationButton("Coverage","point.3.connected.trianglepath.dotted","Capability coverage")
            Button {m.dialog = .deviceInteraction} label:{
                HStack(spacing:8){Image(systemName:"iphone.gen3.radiowaves.left.and.right").frame(width:16);Text("Connected device");Spacer()}
                    .padding(.horizontal,8).padding(.vertical,7)
                    .background(m.dialog == .deviceInteraction ? accent.opacity(0.12):.clear).cornerRadius(5)
            }.buttonStyle(.plain).disabled(m.busy)
                .help("View a connected iPhone or Android device. No case selection required.")
            Divider().padding(.vertical,5)
            Text("CURRENT CASE").font(.system(size:9,weight:.medium)).foregroundStyle(LawlietTheme.secondary).padding(.horizontal,8)
            Picker("Case",selection:Binding(get:{m.currentCasePath},set:{m.openCase($0)})) {Text("Select a case").tag("");ForEach(m.cases.filter{$0.available}){Text($0.name).tag($0.id)}}.labelsHidden().disabled(m.busy).help(m.caseName+"\n"+m.currentCasePath)
            navigationButton("Overview","square.grid.2x2","Case overview")
            navigationButton("Evidence & processing","externaldrive","Sources")
            navigationButton("Evidence files","doc","Evidence files")
            navigationButton("Coverage & review","checklist","Coverage")
            Button {m.dialog = .investigationEngine} label:{Label("Agent investigation",systemImage:"magnifyingglass.circle")}.buttonStyle(.plain).padding(.horizontal,8).padding(.vertical,6).disabled(m.busy || m.caseID.isEmpty)
            Button {m.dialog = .mvtReview} label:{Label("MVT observations",systemImage:"shield.lefthalf.filled")}.buttonStyle(.plain).padding(.horizontal,8).padding(.vertical,6).disabled(m.busy || m.caseID.isEmpty)
            Button {m.loadFindings()} label:{Label("Saved findings",systemImage:"bookmark")}.buttonStyle(.plain).padding(.horizontal,8).padding(.vertical,6).disabled(m.busy || m.caseID.isEmpty)
            Button {m.dialog = .reportHistory} label:{Label("Report history",systemImage:"doc.text.magnifyingglass")}.buttonStyle(.plain).padding(.horizontal,8).padding(.vertical,6).disabled(m.busy || m.caseID.isEmpty)
            Divider().padding(.vertical,5)
            Text(m.source?.isCaseWide==true ? "EXAMINE CASE":"EXAMINE SOURCE").font(.system(size:9,weight:.medium)).foregroundStyle(LawlietTheme.secondary).padding(.horizontal,8)
            ScrollView {
                VStack(spacing:1) {
                    UnifiedEvidenceSidebar(m:m).id(m.currentCasePath+":"+m.sourceID)
                }
            }.frame(maxHeight:.infinity)
            Divider()
            HStack {
                Menu {Button("Complete ALEAPP / iLEAPP output folder"){m.importFolder()};Button("Parsed JSONL / LEAPP TSV"){m.importReport()};Button("Acquired evidence · import & analyze"){m.importEvidence()};Divider();Button("WhatsApp chat & media export"){m.chooseAppBackup(.whatsapp)};Button("Discord account data package"){m.chooseAppBackup(.discord)};Button("Signal encrypted backup"){m.chooseAppBackup(.signal)}} label:{Label("Import",systemImage:"square.and.arrow.down")}.disabled(m.busy || m.caseID.isEmpty)
                Menu {Button("App evidence coverage"){m.appCoverage()}.disabled(m.source == nil || m.source?.isCaseWide==true);Button("Validate selected source"){m.validateSource()}.disabled(m.source == nil || m.source?.isCaseWide==true);Button("Acquire connected phone"){m.acquireDevices()};Button("Android screen & control"){m.dialog = .deviceInteraction};Button("Analyze selected evidence"){m.dialog = .analyze}.disabled(m.source == nil || m.source?.isCaseWide==true);Button("SQLite recovery candidates"){m.recoveryFiles()}.disabled(m.source == nil || m.source?.isCaseWide==true)} label:{Label("Process",systemImage:"gearshape.2")}.disabled(m.busy || m.caseID.isEmpty)
            }.padding(.vertical,5)
            VStack(alignment:.leading,spacing:5) {
                Text("APPEARANCE").font(.system(size:9,weight:.medium)).foregroundStyle(LawlietTheme.secondary)
                Picker("Appearance",selection:$appearanceMode) {
                    Text("Dark").tag("dark");Text("Light").tag("light");Text("System").tag("system")
                }.pickerStyle(.segmented).labelsHidden().accessibilityLabel("Appearance")
                    .help("Neutral dark, light, or follow macOS appearance")
            }.padding(.horizontal,5).padding(.vertical,5)
            HStack {Label("Local workspace",systemImage:"lock.shield").font(.system(size:10)).foregroundStyle(LawlietTheme.secondary);Spacer();Menu {Button("New case"){newCase=true}.keyboardShortcut("n",modifiers:.command);Button("Open existing case…"){m.openRetainedCase()};Button("Refresh cases"){threadSearch="";m.refreshCases()}.keyboardShortcut("r",modifiers:.command);Button("Case folders…"){m.dialog = .caseFolders}} label:{Image(systemName:"ellipsis.circle")}.menuStyle(.borderlessButton).frame(width:20).help(m.workspace).disabled(m.busy)}.padding(.horizontal,5).padding(.vertical,4)
        }.font(.system(size:12)).controlSize(.small).padding(10).frame(width:210).background(LawlietTheme.panel)
    }
    @ViewBuilder func actionSheet(_ kind:DesktopDialog) -> some View {
        VStack(alignment:.leading,spacing:18) {
            if kind == .findingNote {
                Text("Save finding").font(.title2)
                Text(m.findingTitle).font(.headline).lineLimit(3)
                Text("Examiner interpretation is kept separately from the parsed record. Findings are append-only; add a new note to correct an earlier interpretation.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                TextField("Examiner label (optional)",text:$m.findingExaminer)
                Text("Finding note").font(.caption)
                TextEditor(text:$m.findingNote).frame(height:150).border(Color.gray.opacity(0.3)).accessibilityLabel("Finding note")
                Button("Save finding"){m.saveFinding()}.disabled(m.findingNote.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty || m.findingNote.count>20000 || m.findingExaminer.count>200 || m.busy)
            } else if kind == .findings {
                Text("Saved findings · \(m.findingTotal)").font(.title2)
                Text("Whole case · saved record snapshots, oldest first. Notes are examiner interpretations, not original evidence.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                HStack {Button("Prepare draft from selected findings…"){m.dialog = .draftPreparation}.disabled(m.busy || m.findingTotal==0);Button("Scoped examination draft…"){m.dialog = .examinationPreparation}.disabled(m.busy || m.evidenceItems.isEmpty)}
                ScrollView {LazyVStack(alignment:.leading,spacing:18) {
                    if m.findings.isEmpty {Text("No saved findings. Select a record and choose Save finding.").foregroundStyle(LawlietTheme.secondary)}
                    ForEach(m.findings) {finding in VStack(alignment:.leading,spacing:8) {
                        Text(finding.artifact.title).font(.headline)
                        Text(finding.note).textSelection(.enabled)
                        Text("\(finding.examiner.isEmpty ? "Unspecified examiner":finding.examiner) · \(finding.created)").font(.caption).foregroundStyle(LawlietTheme.secondary)
                        Text("Record: \(finding.artifact.dateLabel) · \(finding.artifact.parser)").font(.caption)
                        DisclosureGroup("Saved record body") {Text(finding.artifact.body).font(.callout).textSelection(.enabled)}
                        Text(finding.artifact.sourceRef).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
                        DisclosureGroup("Saved record & provenance") {Text(finding.artifact.raw).font(.system(size:11,design:.monospaced)).textSelection(.enabled)}
                        Text("Finding ID: \(finding.id)").font(.caption2).foregroundStyle(LawlietTheme.secondary)
                        Divider()
                    }}
                }.frame(maxWidth:.infinity,alignment:.leading)}.frame(height:360)
                HStack {Button("Previous"){m.loadFindings(offset:max(0,m.findingOffset-100))}.disabled(m.busy || m.findingOffset==0);Text(m.findings.isEmpty ? "0 findings":"\(m.findingOffset+1)–\(m.findingOffset+m.findings.count)").font(.caption);Button("Next"){m.loadFindings(offset:m.findingOffset+100)}.disabled(m.busy || !m.findingsMore);Spacer();Menu("Export all"){Button("Readable text report"){m.exportFindings(format:"text")};Button("Complete JSONL snapshots"){m.exportFindings()}}.disabled(m.busy || m.findingTotal==0)}
            } else if kind == .validation {
                Text(m.validationTitle).font(.title2)
                ScrollView {Text(m.validationText).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)}.frame(height:420)
                if !m.validationPath.isEmpty {Button("Reveal full validation report"){NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath:m.validationPath)])}}
            } else if kind == .whatsapp {
                Text("Import WhatsApp export").font(.title2);Text("Text, ZIP or export folder. Supplied media stays linked to its messages where filenames match. Select the date order used in the transcript; unknown local time remains undated.").font(.callout).foregroundStyle(LawlietTheme.secondary)
                Picker("Date order",selection:$dateOrder){Text("Day / month / year").tag("dmy");Text("Month / day / year").tag("mdy");Text("Year / month / day").tag("ymd")};TextField("Timezone, e.g. America/New_York",text:$zone)
                TextField("Century for two-digit years, e.g. 2000 (optional)",text:$yearCentury).accessibilityLabel("Declared year century")
                Text("Leave century blank when unknown; two-digit years stay undated. Timezone and century are independent declarations.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                DisclosureGroup("Multiple transcripts in this export?"){TextField("Relative transcript path (optional)",text:$chatPath)}
                Text("An export can omit history and media. Sender names are labels supplied in the export.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                if !centuryError.isEmpty {Text(centuryError).font(.caption).foregroundStyle(.orange)}
                Button("Import") {
                    guard let fields=try? ChatDateInterpretation.centuryFields(yearCentury) else {return}
                    var values:[String:Any]=["case":m.caseID,"path":m.selectedPath,"date_order":dateOrder,"timezone":zone,"chat_path":chatPath]
                    values.merge(fields){_,new in new}
                    m.dialog=nil;m.perform("Importing WhatsApp messages and supplied media…"){let result=try await m.request("import-chat",values) as? [String:Any] ?? [:];m.sourceID=result["run_id"] as? String ?? "";m.mode="Messages";try await m.loadCase(preferredEvidence:result["evidence_id"] as? String);m.notice="\(result["status"] as? String ?? "Unknown status") · \(result["chat_records"] as? Int ?? 0) chat records · \(result["media_records"] as? Int ?? 0) media records · \(result["undated_records"] as? Int ?? 0) undated. Review missing media and limitations in Evidence & processing.";m.showNotice=true}
                }.disabled(!centuryError.isEmpty || m.busy)
            } else if kind == .discord {
                Text("Import Discord package").font(.title2)
                Text("Indexes messages sent by the account owner from a supplied JSON or legacy CSV data package. This is not the full conversation; deleted messages are not included.").font(.callout).foregroundStyle(LawlietTheme.secondary)
                TextField("Timezone for offset-free timestamps (optional)",text:$zone)
                Text("Use an IANA zone only when established from the source. Otherwise those messages stay undated. Attachment URLs remain references; LAWLIET does not download them.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                Button("Import package"){m.dialog=nil;m.perform("Importing Discord messages…"){let result=try await m.request("import-discord",["case":m.caseID,"path":m.selectedPath,"timezone":zone]) as? [String:Any] ?? [:];m.sourceID=result["source_id"] as? String ?? "";m.mode="Messages";try await m.loadCase(preferredEvidence:result["evidence_id"] as? String);m.notice="\(result["status"] as? String ?? "Unknown status") · \(result["records"] as? Int ?? 0) indexed Discord records. Check Evidence & processing for coverage and any rejected records.";m.showNotice=true}}.disabled(m.busy)
            } else if kind == .signal {
                Text("Signal backup intake").font(.title2)
                if m.signalIntake["ready"] as? Bool == true {
                    Text("Candidate legacy Android backup. The decoder must validate its format and key. Original bytes are preserved; successful output is indexed automatically.").font(.callout).foregroundStyle(LawlietTheme.secondary)
                    SecureField("Known 30-digit passphrase",text:$secret)
                    Button("Decrypt & import"){let password=secret;secret="";m.dialog=nil;m.perform("Decrypting supplied Signal backup…"){let result=try await m.request("decrypt-signal",["case":m.caseID,"path":m.selectedPath,"passphrase":password]) as? [String:Any] ?? [:];m.sourceID="";m.mode="Messages";try await m.loadCase(preferredEvidence:result["evidence_id"] as? String);m.notice="\(result["status"] as? String ?? "Unknown status") · \(result["message_records"] as? Int ?? 0) Signal message records indexed. Review processing details for parser errors and unsupported data.";m.showNotice=true}}.disabled(secret.isEmpty || m.busy)
                } else {
                    Text(m.signalIntake["reason"] as? String ?? (m.signalIntake["tool"] as? [String:Any])?["setup"] as? String ?? "Signal decoder is unavailable.").font(.callout).textSelection(.enabled)
                    Text("No decryption ran. For an already decoded database or extraction, use Acquired evidence · import & analyze.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                }
            } else if kind == .acquire {
                Text("Acquire connected phone").font(.title2);Text("Host free space: \(m.freeGiB.formatted()) GiB. Periodic storage checks stop oversized collections and reserve room for evidence intake; temporary overshoot is possible.").foregroundStyle(LawlietTheme.secondary)
                Picker("Device",selection:$selectedDevice){Text("Choose device").tag("");ForEach(m.devices){d in Text("\(d.platform) · \(d.id) · \(d.status)").tag(d.id)}}
                if m.devices.first(where:{$0.id==selectedDevice})?.platform == "android" {
                Picker("Android scope",selection:$profile){Text("Telephony messages").tag("messages");Text("SMS · readable provider").tag("sms-provider");Text("Contacts · readable provider").tag("contacts-provider");Text("Gallery Trash · accessible photos").tag("trash-photos");Text("Logical triage + telephony").tag("logical");Text("Shared files · explicit folder").tag("files");Text("Private apps · existing root required").tag("private-apps")}
                if profile=="sms-provider" {Text("Reads up to 1,000 SMS records from the current Android user where permitted, with a 64 MiB budget. Queries are not a transaction-wide snapshot. MMS, RCS and private app messages are outside this scope.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                if profile=="trash-photos" {Text("Reads up to 1,000 entries under Samsung shared-storage Trash and copies recognized photos with matching before/after hashes. Other apps and permanently deleted files are outside this scope. No restore or delete is performed.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                if profile=="contacts-provider" {Text("Names, phone numbers and email addresses from readable contacts. Limited to 1,000 contacts and 64 MiB; live queries are not an atomic snapshot.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                if profile=="files" {TextField("Android shared folder",text:$sharedPath);Text("Only this folder is requested. Private app storage remains outside shared-file access.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                Button("Assess Android access"){m.assessAndroid(selectedDevice)}.disabled(m.busy)
                }
                if ["contacts-provider","sms-provider"].contains(profile) && m.devices.first(where:{$0.id==selectedDevice})?.platform=="android" {Text("Provider export budget: 64 MiB").font(.caption)} else if m.devices.first(where:{$0.id==selectedDevice})?.platform != "ios" || iosProfile=="ios-backup" {Stepper("Storage limit: \(budget) GiB",value:$budget,in:1...500)}
                if m.devices.first(where:{$0.id==selectedDevice})?.platform == "ios" {
                    Picker("iPhone scope",selection:$iosProfile){Text("Installed apps · 16 MiB").tag("ios-apps");Text("Messages & contacts · 256 MiB").tag("ios-selected");Text("Logical backup").tag("ios-backup")}
                    if iosProfile=="ios-apps" {Text("Collects installed application metadata and device information without a backup. Private app contents are outside this scope.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                    else if iosProfile=="ios-selected" {Text("Keeps message and contact databases with supplied SQLite companions. Attachments and other payloads are omitted. The backup stream still crosses USB and may require phone confirmation or more free space. Encrypted selected backups need a separate supported route. No automatic full-backup fallback.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                    else {Text("Requests all backup-eligible data. The storage threshold stops an oversized backup and can leave it incomplete. Encrypted backups require separate decryption before parsing.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                    Text("Unlock and trust the selected iPhone. Starting collection authorizes this method for the current case. Live collection changes device state.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                }
                Button("Check storage & tools"){
                    guard let d=m.devices.first(where:{$0.id==selectedDevice}) else {return}
                    acquisitionReadiness="Checking storage and installed tools…"
                    m.perform("Checking acquisition readiness…",onError:{acquisitionReadiness=$0.localizedDescription}){
                        let r=try await m.request("preflight",["case":m.caseID,"platform":d.platform,"profile":d.platform=="ios" ? iosProfile : profile,"max_gib":budget]) as? [String:Any] ?? [:]
                        let required=(r["required_bytes"] as? Double ?? 0)/1073741824
                        let missing=r["missing_tools"] as? [String] ?? []
                        acquisitionReadiness="\(r["ready"] as? Bool == true ? "Storage and tools ready" : "Not ready"). Required free space: \(required.formatted()) GiB. Phone authorization and actual backup access still need assessment."
                        if !missing.isEmpty {acquisitionReadiness += " Missing tools: " + missing.joined(separator:", ")}
                    }
                }.disabled(selectedDevice.isEmpty || m.busy)
                if !acquisitionReadiness.isEmpty {Text(acquisitionReadiness).font(.caption).textSelection(.enabled)}
                Color.clear.frame(height:0).onChange(of:selectedDevice){_ in acquisitionReadiness=""}.onChange(of:iosProfile){_ in acquisitionReadiness=""}.onChange(of:profile){_ in acquisitionReadiness=""}.onChange(of:budget){_ in acquisitionReadiness=""}
                Button("Start acquisition"){guard let d=m.devices.first(where:{$0.id==selectedDevice}) else {return};m.dialog=nil;m.perform("Collecting phone data; keep the device connected…"){let r=try await m.request("collect",["case":m.caseID,"serial":d.id,"platform":d.platform,"profile":d.platform=="android" ? profile : iosProfile,"pulls":d.platform=="android" && profile=="files" ? [sharedPath] : [],"max_gib":budget]) as? [String:Any] ?? [:];m.sourceID="";try await m.loadCase();m.notice="Overall: \(r["status"] as? String ?? "unknown") · collection: \(r["collection_status"] as? String ?? "unknown"). Check Evidence & processing for parsing status and coverage.";let failures=(r["errors"] as? [Any] ?? []).prefix(3).compactMap{($0 as? String) ?? ($0 as? [String:Any])?["detail"] as? String};if !failures.isEmpty {m.notice += "\n" + failures.map{String($0.prefix(500))}.joined(separator:"\n")};m.showNotice=true}}.disabled(selectedDevice.isEmpty)
            } else if kind == .analyze {
                Text("Analyze selected evidence").font(.title2);Picker("Engine",selection:$engine){Text("Automatic · ALEAPP / iLEAPP").tag("auto");Text("Native + media index").tag("native");Text("iLEAPP (iOS)").tag("ileapp");Text("ALEAPP (Android)").tag("aleapp");Text("ExifTool media metadata").tag("exiftool")}
                Text("Optional engines must be configured in this workspace. Analysis uses working copies.").foregroundStyle(LawlietTheme.secondary)
                Button(engine=="auto" ? "Preview analysis options":"Preview selected engine"){m.analysisPlan(engine)}.disabled(m.busy)
                Text("Preview lists candidates only. Run analysis uses the engine selected above; automatic analysis runs the existing platform/export parser.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                Button("Run analysis"){var p=m.params();p["engine"]=engine;m.dialog=nil;m.perform("Analyzing evidence…"){let r=try await m.request("analyze",p) as? [String:Any] ?? [:];m.sourceID=engine=="auto" ? (r["source_id"] as? String ?? "") : engine=="native" || engine=="exiftool" ? (p["evidence"] as? String ?? "")+":"+(r["engine"] as? String ?? engine) : (r["run_id"] as? String ?? "");m.mode="All artifacts";try await m.loadCase();if let message=r["message"] as? String {m.notice=message;m.showNotice=true}}}
            } else if kind == .attachments {
                Text("Linked attachments").font(.title2)
                if m.relatedAttachments.isEmpty {Text("No local attachment links for this source. Import and index the originating extraction to examine available bytes.").foregroundStyle(LawlietTheme.secondary)}
                ScrollView {VStack(alignment:.leading,spacing:12){ForEach(m.relatedAttachments){a in HStack{VStack(alignment:.leading){Text(a.title);Text(a.body).font(.caption).foregroundStyle(LawlietTheme.secondary)};Spacer();Button("Preview"){m.dialog=nil;m.previewSelected(a)}.disabled(!a.mediaAvailable)}}}}.frame(maxHeight:360)
            } else {
                Text("SQLite recovery candidates").font(.title2);Text("Carved fragments need corroboration. No candidate does not establish that nothing was deleted. Original databases are preserved.").foregroundStyle(LawlietTheme.secondary)
                Picker("Database",selection:$sqliteID){Text("Choose database").tag(0);ForEach(m.sqliteFiles){f in Text(f.path).tag(f.id)}}
                Picker("Recovery engine",selection:$recoveryEngine){Text("SQLite Dissect").tag("sqlite-dissect");Text("sqlite4n6 · 0.10.1").tag("sqlite4n6")}
                Button("Run recovery"){m.dialog=nil;m.perform("Examining SQLite history and unallocated records…"){let r=try await m.request("recover",["case":m.caseID,"file_id":sqliteID,"engine":recoveryEngine]) as? [String:Any] ?? [:];m.sourceID=r["run_id"] as? String ?? "";m.mode="Recovery";try await m.loadCase()}}.disabled(sqliteID==0)
            }
            Divider();Button(kind == .validation && m.validationReturn != nil ? "Back to analysis":[DesktopDialog.findings,.validation,.attachments].contains(kind) ? "Close":"Cancel"){secret="";m.dialog=kind == .validation ? m.validationReturn:nil}
        }.padding(26).frame(width:520)
    }
    var sourcesView: some View {
        ScrollView {
            VStack(alignment:.leading,spacing:16) {
                HStack(spacing:12) {
                    sourceCard("Evidence sources", "\(m.evidenceItems.count)", "Imported into this case")
                    sourceCard("Analysis runs", "\(m.runItems.count)", "Retained independently")
                    sourceCard("Integrity", m.verification, "Use Verify to check source hashes")
                }
                Text("Evidence inventory").font(.title3).fontWeight(.medium)
                VStack(spacing:0) {ForEach(m.evidenceItems) {e in
                    HStack(alignment:.top,spacing:14) {Image(systemName:e.platform=="ios" ? "iphone":"doc.text").font(.title3).foregroundStyle(LawlietTheme.secondary)
                        VStack(alignment:.leading,spacing:6) {Text(e.label).fontWeight(.medium);Text("\(e.platform.uppercased()) · \(e.id)").font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)}
                        Spacer();Text(String(e.imported.prefix(10))).font(.caption).foregroundStyle(LawlietTheme.secondary)
                    }.padding(16);Divider()
                }}.background(LawlietTheme.panel).cornerRadius(5)
                Text("Retained parser results").font(.title3).fontWeight(.medium)
                VStack(spacing:0) {ForEach(m.sources.filter{$0.hasResults && !$0.isCaseWide}) {source in
                    HStack {
                        VStack(alignment:.leading,spacing:4) {Text(source.label).fontWeight(.medium);Text("\(source.records.formatted()) \(source.rowUnit)").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                        Spacer();Button("Review records"){m.reviewSource(source.id)}.disabled(m.busy)
                    }.padding(14);Divider()
                }}.background(LawlietTheme.panel).cornerRadius(5)
                Text("Processing history").font(.title3).fontWeight(.medium)
                VStack(spacing:0) {ForEach(m.runItems) {r in
                    VStack(alignment:.leading,spacing:10) {
                        HStack {VStack(alignment:.leading,spacing:5){Text(r.engine).fontWeight(.medium);Text(r.id).font(.system(size:11,design:.monospaced)).foregroundStyle(LawlietTheme.secondary)};Spacer();Text("\(r.records.formatted()) rows").font(.caption);Text(r.status.capitalized).font(.caption).padding(.horizontal,9).padding(.vertical,4).background(LawlietTheme.border.opacity(0.5)).cornerRadius(4)}
                        if r.engine=="sqlite-workspace/1" && r.status=="complete" {
                            Button("View query results"){sqliteResultScope=SQLiteResultScope(workspace:m.workspace,caseID:m.caseID,runID:r.id)}.disabled(m.busy)
                        }
                        if !r.summary.isEmpty {Text(r.summary).font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)}
                        DisclosureGroup("Processing details") {Text(r.detail).font(.system(size:11,design:.monospaced)).textSelection(.enabled)}
                    }.padding(14);Divider()
                }}.background(LawlietTheme.panel).cornerRadius(5)
                DisclosureGroup("Technical provenance & acquisition logs") {Text(m.coverage).font(.system(size:11,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading).padding(.top,12)}
            }.padding(24).frame(maxWidth:.infinity,alignment:.leading)
        }
    }
    func sourceCard(_ title:String,_ value:String,_ hint:String) -> some View {
        VStack(alignment:.leading,spacing:10) {Text(title.uppercased()).font(.caption2).foregroundStyle(LawlietTheme.secondary);Text(value).font(.title3).fontWeight(.medium);Text(hint).font(.caption).foregroundStyle(LawlietTheme.secondary)}.frame(maxWidth:.infinity,alignment:.leading).padding(12).background(LawlietTheme.panel).cornerRadius(5)
    }
    var header: some View {
        VStack(alignment:.leading,spacing:7){HStack {VStack(alignment:.leading,spacing:3){Text(m.mode=="Case overview" ? m.caseName:m.mode=="Sources" ? "Evidence & processing":m.reviewTitle).font(.system(size:18,weight:.semibold)).lineLimit(1);if m.mode != "Case overview" {Text(m.caseName).font(.system(size:11)).foregroundStyle(LawlietTheme.secondary).lineLimit(1)}};Spacer();Button{m.perform("Verifying imported evidence…"){let r=try await m.request("verify",["case":m.caseID]) as? [String:Any] ?? [:];m.verification=r["ok"] as? Bool == true ? "Passed · \(r["files_checked"] as? Int ?? 0) files":"Integrity check FAILED";m.notice="Integrity: \(r["ok"] as? Bool == true ? "passed":"FAILED") · \(r["files_checked"] as? Int ?? 0) imported files and \(r["findings_checked"] as? Int ?? 0) saved findings checked. This does not establish acquisition completeness.";m.showNotice=true}}label:{Label("Verify",systemImage:"checkmark.shield")}.disabled(m.busy || m.caseID.isEmpty);if m.mode != "Case overview" && m.mode != "Sources" {Button{m.exportRows()}label:{Label("Export source records",systemImage:"square.and.arrow.up")}.disabled(m.busy || m.source == nil || m.mode == "Sources" || m.reviewNeedsApply)}}
            if m.mode != "Case overview" && m.mode != "Sources" {HStack {Text("PARSED SOURCE").font(.caption2).foregroundStyle(LawlietTheme.secondary);Picker("Source",selection:$m.sourceID){Text("No parsed source").tag("");ForEach(m.sources){Text($0.label).tag($0.id)}}.labelsHidden().disabled(m.busy).onChange(of:m.sourceID){_ in if !m.busy {m.perform("Loading source…"){try await m.loadSource()}}};if let s=m.source {Text("\(s.records.formatted()) \(s.rowUnit) · source total").font(.caption).monospacedDigit().foregroundStyle(LawlietTheme.secondary).help("Total indexed rows in the selected source, before view and search filters. The table below is paginated.")};Spacer();Picker("Review view",selection:$m.investigatorView){Text("Investigator").tag(true);Text("Source records").tag(false)}.pickerStyle(.segmented).labelsHidden().accessibilityLabel("Review view").frame(width:225).disabled(m.busy).onChange(of:m.investigatorView){_ in m.sortField="";m.search()};if m.mode=="Contacts" && m.investigatorView {Picker("Contact representations",selection:$m.contactBasis){Text("Preferred contacts").tag("auto");Text("Source contacts").tag("source");Text("Report entries").tag("reports");Text("All representations").tag("all")}.labelsHidden().accessibilityLabel("Contact representations").frame(width:170).onChange(of:m.contactBasis){_ in m.search()}}}}
        }.padding(.horizontal,16).padding(.vertical,12)
    }
    var emptyState: some View {VStack(spacing:18){Image(systemName:"tray.and.arrow.down").font(.system(size:44)).foregroundStyle(accent);Text("Bring your parsed evidence into view").font(.title2);Text("Create a case, then import the complete ALEAPP or iLEAPP output folder.\nReview every indexed report here, with search and timeline filters.").multilineTextAlignment(.center).foregroundStyle(LawlietTheme.secondary);Button("Import LEAPP output folder"){m.importFolder()}.disabled(m.caseID.isEmpty || m.busy)}.frame(maxWidth:.infinity,maxHeight:.infinity)}
    var upstreamTable: some View {
        ReportTable(rows:m.rows,selection:$m.selected,sortField:m.sortField,ascending:m.sortAscending) {field,ascending in
            guard !m.busy else {return}
            m.sortField=field;m.sortAscending=ascending;m.search()
        }
    }
    var reviewContent: some View {
        VStack(spacing:0){HStack{Button {artifactSearchFocused=true} label:{Image(systemName:"magnifyingglass")}.buttonStyle(.plain).keyboardShortcut("f",modifiers:.command).help("Search this source · ⌘F");Picker("Search type",selection:$m.searchMode){Text("Text").tag("text");Text("Phone number").tag("phone")}.labelsHidden().accessibilityLabel("Search type").frame(width:115).disabled(m.busy);TextField(m.searchMode == "phone" ? "Phone number · ignore formatting…":"String search · all parsed fields in this view…",text:$m.query).textFieldStyle(.plain).focused($artifactSearchFocused).onSubmit{m.search()};if m.mode=="Messages" {Picker("App (messages only)",selection:$m.appFilter){Text("All apps").tag("");ForEach(m.appNames,id:\.self){Text($0).tag($0)}}.labelsHidden().accessibilityLabel("App (messages only)").frame(width:155).disabled(m.mode != "Messages" || m.busy).onChange(of:m.appFilter){_ in if !m.busy {m.conversation="";m.search()}}};Button("Search"){m.search()}.disabled(m.busy);if !["Media","Trash photos","Attachments"].contains(m.mode) {Picker("Layout",selection:$artifactLayout){Text("Table").tag("table");Text("Cards").tag("cards")}.pickerStyle(.segmented).labelsHidden().accessibilityLabel("Artifact layout").frame(width:120);if usesArtifactTable && m.reportFilter.isEmpty {Menu {ForEach(ArtifactTable.columnChoices,id:\.id){column in Toggle(column.title,isOn:Binding(get:{artifactColumns.contains(column.id)},set:{enabled in if enabled {artifactColumns.append(column.id)} else if artifactColumns.count>1 {artifactColumns.removeAll{$0==column.id}}})).disabled(artifactColumns.count==1 && artifactColumns.contains(column.id))}}label:{Image(systemName:"tablecells")}.menuStyle(.borderlessButton).fixedSize().help("Visible columns").accessibilityLabel("Visible columns")}};Button {showFilters.toggle()} label:{Label("Filters",systemImage:"line.3.horizontal.decrease.circle")}.tint(showFilters ? accent:.secondary);Button {showInspector.toggle()} label:{Image(systemName:"sidebar.right")}.help(showInspector ? "Hide record details":"Show record details").accessibilityLabel("Toggle record details")}.padding(8).background(LawlietTheme.panel).overlay(RoundedRectangle(cornerRadius:4).stroke(LawlietTheme.border)).padding(.horizontal,16)
            if m.searchMode == "phone" {Text("Matches complete digits in known phone fields. No country-code guessing or identity attribution.").font(.caption).foregroundStyle(LawlietTheme.secondary).padding(.horizontal,16).padding(.top,6)}
            if showFilters {
            HStack {
                Picker("Report",selection:$m.reportFilter){Text("All reports").tag("");ForEach(m.reportNames,id:\.self){name in Text("\(name) · \(m.reportCounts[name,default:0]) rows").tag(name)}}.frame(maxWidth:400).onChange(of:m.reportFilter){_ in if !m.busy {m.sortField="";m.search()}}
                Text("\(m.source?.records ?? 0) source rows · \(m.undated) undated").font(.caption).foregroundStyle(LawlietTheme.secondary)
                if !m.reportFilter.isEmpty {Toggle("Table",isOn:$reportTable).toggleStyle(.switch).fixedSize()}
                if !m.sortField.isEmpty {Text("\(m.sortMode.capitalized) order: \(m.sortField) \(m.sortAscending ? "↑":"↓")").font(.caption).help("Orders all matching records; missing or uninterpretable fields last.")}
                Spacer();Button("Clear filters"){m.clearFilters()}.disabled(m.busy)
            }.padding(.horizontal,16).padding(.top,8)
            if !m.reportFilter.isEmpty && reportTable {
                HStack {
                    Picker("Sort report",selection:$m.sortField) {
                        Text("Default order").tag("")
                        ForEach(Array(Set(m.rows.flatMap {$0.reportFields.map(\.id)})).sorted(),id:\.self) {Text($0).tag($0)}
                    }.frame(maxWidth:320).onChange(of:m.sortField){_ in if !m.busy {m.search()}}
                    Button(m.sortAscending ? "Ascending ↑":"Descending ↓") {m.sortAscending.toggle();m.search()}.disabled(m.busy || m.sortField.isEmpty)
                    Picker("Interpret as",selection:$m.sortMode) {Text("Text").tag("text");Text("Number").tag("number");Text("ISO timestamp").tag("timestamp")}.frame(width:210).onChange(of:m.sortMode){_ in if !m.busy {m.search()}}
                    Text("All matching rows · invalid values last").font(.caption).foregroundStyle(LawlietTheme.secondary)
                    Spacer()
                }.disabled(m.busy).padding(.horizontal,16).padding(.top,8)
            }
            }
            if showFilters || m.mode=="Timeline" || m.mode=="Messages" {
                HStack {Text("Range").font(.caption);Button("All time"){m.setRange(0)};ForEach([7,30,60,90],id:\.self){days in Button("\(days) days"){m.setRange(days)}.tint(m.rangeDays==days ? accent:.gray)}
                    Picker("Ending",selection:$m.dateAnchor){Text("Latest source record").tag("latest");Text("Now").tag("now")}.frame(width:250).onChange(of:m.dateAnchor){_ in if m.rangeDays>0 && !m.busy {m.setRange(m.rangeDays)}};Spacer()
                }.disabled(m.busy).padding(.horizontal,16).padding(.top,8)
            }
            if showFilters || m.mode=="Timeline" {HStack {Text("Date range (UTC)").font(.caption).foregroundStyle(LawlietTheme.secondary);TextField("From YYYY-MM-DD",text:$m.since).textFieldStyle(.roundedBorder).frame(width:150);TextField("To YYYY-MM-DD",text:$m.until).textFieldStyle(.roundedBorder).frame(width:150);Image(systemName:"info.circle").foregroundStyle(LawlietTheme.secondary).help("Dates use 00:00 UTC; ISO timestamps accepted. Date filters exclude undated rows.").accessibilityLabel("Date filters use UTC and exclude undated rows");Spacer()}.padding(.horizontal,16).padding(.top,8)}
            ReviewContextView(m:m)
            HSplitView {
                if m.mode=="Messages" {VStack(alignment:.leading,spacing:0){Text("SOURCE THREADS · \(visibleThreads.count)").font(.caption2).foregroundStyle(LawlietTheme.secondary).padding(12);TextField("Find conversation…",text:$threadSearch).textFieldStyle(.roundedBorder).padding(.horizontal,10);List(selection:Binding<String?>(get:{m.conversation},set:{value in guard !m.busy else {return};m.conversation=value ?? "";m.search()})) {Text("All conversations").tag("");ForEach(visibleThreads){t in VStack(alignment:.leading,spacing:4){Text(t.label).lineLimit(1);Text("\(t.app) · \(t.count) rows").font(.caption).foregroundStyle(LawlietTheme.secondary);if !t.reports.isEmpty {Text(t.reports).font(.caption2).foregroundStyle(LawlietTheme.secondary).lineLimit(2).help(t.reports)}}.padding(.vertical,5).tag(t.id)}}.disabled(m.busy).listStyle(.plain).scrollContentBackground(.hidden).background(LawlietTheme.panel)}.frame(minWidth:185,idealWidth:220,maxWidth:290)}
                VStack(spacing:0){if m.mode == "Trash photos" {Text("Recorded Trash acquisitions only. This view does not scan the phone or establish permanent-deletion recovery.").font(.caption).foregroundStyle(LawlietTheme.secondary).padding(12)};if m.rows.isEmpty {Text(m.busy ? "Loading…":m.emptyReason).multilineTextAlignment(.center).padding(24).foregroundStyle(LawlietTheme.secondary).frame(maxWidth:.infinity,maxHeight:.infinity)}else if reportTable && !m.reportFilter.isEmpty && m.rows.contains(where:{!$0.reportFields.isEmpty}) {upstreamTable}else if usesArtifactTable {ArtifactTable(rows:m.rows,selection:$m.selected,visibleColumns:artifactColumns)}else{List{ForEach(m.rows){r in Button {m.selected=r.id} label:{HStack(spacing:10){if r.autoImagePreview {InlineMediaView(cache:m.inlineMedia,key:m.imageKey(r,compact:true),compact:true).id(m.imageKey(r,compact:true))};VStack(alignment:.leading,spacing:4){HStack{Text(r.kindLabel).font(.system(size:10,weight:.semibold)).foregroundStyle(LawlietTheme.secondary);Spacer();Text(r.dateLabel).font(.system(size:10)).foregroundStyle(LawlietTheme.secondary)};if !r.investigatorKind.isEmpty && r.category != "messages" {Text(r.title).font(.system(size:12,weight:.medium)).lineLimit(1)};Text(r.body.isEmpty ? "[No text body]":r.body).lineLimit(2).font(.system(size:12));Text(r.observations.count>1 ? "\(r.observations.count) source observations · \(r.originLabel)":r.investigatorKind.isEmpty ? r.title:r.originLabel).font(.caption).foregroundStyle(LawlietTheme.secondary).lineLimit(1)}}.foregroundStyle(LawlietTheme.text).padding(.vertical,9).padding(.horizontal,6).frame(maxWidth:.infinity,alignment:.leading)}.buttonStyle(.plain).listRowBackground(m.selected == r.id ? LawlietTheme.selection:LawlietTheme.panel).overlay(alignment:.leading){if m.selected == r.id {RoundedRectangle(cornerRadius:2).fill(accent).frame(width:3).padding(.vertical,7)}}.tag(r.id)}}.listStyle(.inset).focusable().onMoveCommand {direction in
                        guard !m.busy, !m.rows.isEmpty else {return}
                        let current=m.rows.firstIndex(where:{$0.id==m.selected}) ?? 0
                        if direction == .down {m.selected=m.rows[min(current+1,m.rows.count-1)].id}
                        if direction == .up {m.selected=m.rows[max(current-1,0)].id}
                    }.scrollContentBackground(.hidden).background(LawlietTheme.panel)};HStack{Button("Previous"){m.offset=max(0,m.offset-100);m.perform("Loading previous page…"){try await m.loadRecords()}}.disabled(m.busy || m.reviewNeedsApply || m.offset==0);Spacer();Text("\(m.rows.isEmpty ? 0:m.displayedOffset+1)–\(m.displayedOffset+m.rows.count)").font(.caption).monospacedDigit();Spacer();Button("Next"){m.offset+=100;m.perform("Loading next page…"){try await m.loadRecords()}}.disabled(m.busy || m.reviewNeedsApply || !m.hasMore)}.padding(12)}.frame(minWidth:290)
                if showInspector {ScrollView {if let r=m.selectedArtifact {VStack(alignment:.leading,spacing:10){Text("RECORD DETAILS").font(.caption2).foregroundStyle(LawlietTheme.secondary);if r.observations.count>1 {Text("\(r.observations.count) source observations · choose one under Evidence provenance to cite.").font(.caption).foregroundStyle(LawlietTheme.secondary)} else {Button("Save finding"){m.prepareFinding()}.disabled(m.busy)};Text(r.title).font(.headline);Text(r.dateLabel).font(.caption).foregroundStyle(LawlietTheme.secondary);if !r.investigatorNote.isEmpty {DisclosureGroup("Entry interpretation"){Text(r.investigatorNote).font(.caption).foregroundStyle(LawlietTheme.secondary)}};if !r.reviewNote.isEmpty {DisclosureGroup("Interpretation notes"){Text(r.reviewNote).font(.caption).textSelection(.enabled)}};if r.reportFields.isEmpty || r.category=="messages" {Text(r.body.isEmpty ? "No text body in this record.":r.body).font(.system(size:13)).textSelection(.enabled)} else {DisclosureGroup("Record summary"){Text(r.body).font(.system(size:12)).textSelection(.enabled)}};if r.mediaObservationCount > 1 {Text("One media item · \(r.mediaObservationCount) preserved source/parser observations").font(.caption).foregroundStyle(LawlietTheme.secondary)};if r.trashSource {Text("Recorded acquisition: Gallery Trash. This is not proof of permanent-deletion recovery.").font(.caption).foregroundStyle(LawlietTheme.secondary)};if r.category=="messages" {Button("View linked attachments"){m.showAttachments()}.disabled(m.busy)};if r.taskSnapshot {InlineMediaView(cache:m.inlineMedia,key:m.imageKey(r)).id(m.imageKey(r));Button("Open larger preview"){m.previewSelected()}.disabled(m.busy);Text("App snapshot, not proof of physical presence. Task activity time is not necessarily image capture time.").font(.caption).foregroundStyle(LawlietTheme.secondary)};if r.category=="media" || r.category=="attachments" {if r.autoImagePreview {InlineMediaView(cache:m.inlineMedia,key:m.imageKey(r)).id(m.imageKey(r))};Button(r.autoImagePreview ? "Open larger preview":"Verify & open media"){m.previewSelected()}.disabled(m.busy)};if !r.reportFields.isEmpty {VStack(alignment:.leading,spacing:12){Text(!r.investigatorKind.isEmpty ? "INVESTIGATOR FIELDS":r.category == "media" ? "MEDIA METADATA" : "REPORT FIELDS").font(.caption2).foregroundStyle(LawlietTheme.secondary);ForEach(r.reportFields){field in VStack(alignment:.leading,spacing:4){HStack {Text(field.id).font(.caption).foregroundStyle(LawlietTheme.secondary);Spacer();if !field.value.isEmpty {Button {m.searchField(field.value)} label:{Image(systemName:"magnifyingglass")}.buttonStyle(.borderless).help("Search this value in source · clears report, category and date filters").accessibilityLabel("Search \(field.id) value in source").disabled(m.busy)}};Text(field.value.isEmpty ? "[Empty in source]":field.value).font(.system(size:12)).textSelection(.enabled);if ["phone number","address","partner","number","from_id","to_id"].contains(field.id.lowercased()) && !field.value.isEmpty {Button("Find matching phone number"){m.searchField(field.value,phone:true)}.font(.caption).disabled(m.busy)}}.frame(maxWidth:.infinity,alignment:.leading);Divider()}}};DisclosureGroup("Evidence provenance"){VStack(alignment:.leading,spacing:10){InvestigatorSourcesView(m:m,observations:r.observations);Divider();VStack(alignment:.leading,spacing:7){Text("SOURCE REFERENCE").font(.caption2).foregroundStyle(LawlietTheme.secondary);Text(r.sourceFile).font(.system(size:11,design:.monospaced)).textSelection(.enabled);DisclosureGroup("Recorded source SHA-256"){Text(r.sourceHash).font(.system(size:10,design:.monospaced)).textSelection(.enabled)};Text(r.sourceRef).font(.system(size:11,design:.monospaced)).textSelection(.enabled);Text(r.parser).font(.caption).foregroundStyle(LawlietTheme.secondary)}}};DisclosureGroup("Original fields & provenance"){Text(r.raw).font(.system(size:11,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)};if r.category == "recovery" {Text("Recovery candidate: fragments can duplicate live records. Corroborate before concluding that a message was deleted.").font(.caption).foregroundStyle(LawlietTheme.secondary)} else if ["messages","attachments","media"].contains(r.category) {Text("Attachment references alone do not establish that attachment bytes were acquired.").font(.caption).foregroundStyle(LawlietTheme.secondary)}}.padding(14).frame(maxWidth:.infinity,alignment:.leading)}else{Text("Select a record").foregroundStyle(LawlietTheme.secondary).padding(24)}}.frame(minWidth:270,idealWidth:330,maxWidth:480)}
            }.padding(.top,8)
        }
    }
}

struct MediaPreview: View {
    let path:String;let mime:String
    @Environment(\.dismiss) var dismiss
    @State private var player:AVPlayer?
    func thumbnail() -> NSImage? {
        guard let source=CGImageSourceCreateWithURL(URL(fileURLWithPath:path) as CFURL,[kCGImageSourceShouldCache:false] as CFDictionary),
              let image=CGImageSourceCreateThumbnailAtIndex(source,0,[kCGImageSourceCreateThumbnailFromImageAlways:true,kCGImageSourceThumbnailMaxPixelSize:1600,kCGImageSourceCreateThumbnailWithTransform:true] as CFDictionary) else {return nil}
        return NSImage(cgImage:image,size:.zero)
    }
    var body: some View {VStack {HStack{Text("Verified evidence preview").font(.headline);Spacer();Button("Close"){dismiss()}};if mime.hasPrefix("image/"), let image=thumbnail() {Image(nsImage:image).resizable().scaledToFit()} else if mime.hasPrefix("video/") || mime.hasPrefix("audio/") {VideoPlayer(player:player)} else {Text("This media could not be decoded by macOS.")};Text(mime).font(.caption).foregroundStyle(LawlietTheme.secondary)}.padding(22).frame(width:780,height:620).onAppear{if !mime.hasPrefix("image/"){player=AVPlayer(url:URL(fileURLWithPath:path))}}.onDisappear{player?.pause();player=nil}}
}

@main struct LawlietMobileApp: App {
    @AppStorage("review.showSidebar") private var showSidebar=true
    var body: some Scene {WindowGroup("LAWLIET"){ContentView()}.defaultSize(width:1420,height:880).commands{CommandGroup(replacing:.newItem){};CommandGroup(after:.sidebar){Button(showSidebar ? "Hide Sidebar":"Show Sidebar"){showSidebar.toggle()}.keyboardShortcut("s",modifiers:[.control,.command])}}}
}
