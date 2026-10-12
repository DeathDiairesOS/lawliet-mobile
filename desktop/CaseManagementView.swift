import SwiftUI

let caseStatuses = ["Untriaged", "Intake", "In progress", "Awaiting input", "Review", "Closed"]
let casePriorities = ["Normal", "High", "Urgent", "Low"]

struct CaseTaskItem: Identifiable {
    let id:String; let text:String; let completed:Bool; let revision:Int
    init(_ r:[String:Any]) {id=r["id"] as? String ?? "";text=r["text"] as? String ?? "";completed=r["completed"] as? Int == 1;revision=r["revision"] as? Int ?? 0}
}
struct CaseActivityItem: Identifiable {
    let id:Int; let at:String; let action:String
    init(_ r:[String:Any]) {id=r["id"] as? Int ?? 0;at=r["at"] as? String ?? "";action=r["action"] as? String ?? ""}
}
extension AppModel {
    func invalidateWorkspaceView() {
        cases=[];caseID="";sourceID="";sources=[];rows=[];threads=[];selected=nil;displayedReview=nil
        contactSummary=[:];investigatorSummary=[:];contactBasis="auto";evidenceItems=[];runItems=[];categoryCounts=[:];reportNames=[];reportCounts=[:];reportCategories=[:];reportGroups=[:]
        caseProfile=[:];caseTasks=[];caseActivity=[];caseTaskOffset=0;caseTasksMore=false;openTaskCount=0
        findings=[];findingTotal=0;findingOffset=0;findingsMore=false;findingArtifactID="";findingTitle="";findingNote=""
        relatedAttachments=[];previewPath="";previewShown=false;dialog=nil
        draftPath=""
        validationReturn=nil
        coverage="";incomplete=false;verification="Not checked this session";hasMore=false;offset=0
        conversation="";appFilter="";reportFilter="";query="";since="";until="";rangeDays=0;undated=0
        mode="Cases"
    }
    var caseName:String {cases.first(where:{$0.id==currentCasePath})?.name ?? caseID}
    func managementValue(_ key:String) -> String {caseProfile[key] as? String ?? ""}
    func applyManagement(_ result:[String:Any]) {
        caseProfile=result["profile"] as? [String:Any] ?? [:]
        caseTasks=(result["tasks"] as? [[String:Any]] ?? []).map(CaseTaskItem.init)
        caseActivity=(result["activity"] as? [[String:Any]] ?? []).map(CaseActivityItem.init)
        caseTasksMore=result["has_more"] as? Bool ?? false
        openTaskCount=(result["summary"] as? [String:Any])?["open_tasks"] as? Int ?? 0
    }
    func loadCaseManagement() async throws {
        applyManagement(try await request("case-management",["case":caseID,"offset":caseTaskOffset]) as? [String:Any] ?? [:])
    }
    func reloadCaseList() async throws {
        do {
            let result=try await request("catalog",["roots":catalogRoots]) as? [String:Any] ?? [:]
            guard result["schema_version"] as? Int==1,let rows=result["cases"] as? [[String:Any]],rows.count<=2000 else {throw DraftReviewError.invalid("Unsupported case catalog response.")}
            cases=rows.map(CaseItem.init);catalogWarnings=result["warnings"] as? [String] ?? [];catalogPartial=result["partial"] as? Bool ?? false;caseListError=""
        } catch {invalidateWorkspaceView();caseListError=error.localizedDescription;throw error}
    }
    func openCase(_ path:String) {
        guard let item=cases.first(where:{$0.id==path}),item.available else {return}
        perform("Opening case…",onError:{error in
            let catalog=self.cases;self.invalidateWorkspaceView();self.cases=catalog;self.notice=error.localizedDescription;self.showNotice=true
        }) {self.workspace=item.workspace;self.caseID=item.identifier;self.sourceID="";self.mode="Case overview";try await self.loadCase()}
    }
    func taskPage(_ offset:Int) {
        perform("Loading case tasks…") {self.caseTaskOffset=offset;try await self.loadCaseManagement()}
    }
    func setTask(_ task:CaseTaskItem) {
        perform("Saving task state…") {
            _ = try await self.request("case-task-update",["case":self.caseID,"task_id":task.id,"revision":task.revision,"completed":!task.completed])
            try await self.loadCaseManagement();try await self.reloadCaseList()
        }
    }
}

struct CaseStatusLabel:View {
    let status:String
    var color:Color {status=="Awaiting input" ? .orange : status=="Review" ? .purple : status=="In progress" ? .blue : .secondary}
    var body:some View {HStack(spacing:5){Circle().fill(color).frame(width:6,height:6);Text(status).lineLimit(1)}.font(.system(size:11)).accessibilityElement(children:.combine)}
}

struct CaseBrowserView:View {
    @ObservedObject var m:AppModel
    let newCase:()->Void
    private var query:String {m.caseQuery}
    private var status:String {m.caseQueueStatus}
    private var ordering:String {m.caseQueueSort}
    @State private var selection:String?
    @State private var page=0
    private var pageRows:[CaseItem] {Array(matching.dropFirst(page*50).prefix(50))}
    @FocusState private var searchFocused:Bool
    private var matching:[CaseItem] {
        let result=m.cases.filter {c in
            (status=="All cases" || (status=="Active" ? c.status != "Closed":status=="Needs attention" ? c.needsAttention:c.status==status)) &&
            (query.isEmpty || [c.identifier,c.name,c.client,c.owner,c.location,c.root].contains {$0.localizedCaseInsensitiveContains(query)})
        }
        if ordering=="Due date" {return result.sorted {($0.due.isEmpty ? "9999":$0.due,$0.id)<($1.due.isEmpty ? "9999":$1.due,$1.id)}}
        if ordering=="Priority" {let rank=["Urgent":0,"High":1,"Normal":2,"Low":3];return result.sorted {(rank[$0.priority,default:2],$0.id)<(rank[$1.priority,default:2],$1.id)}}
        return result
    }
    var body:some View {
        VStack(alignment:.leading,spacing:0) {
            HStack {
                VStack(alignment:.leading,spacing:4){Text("Cases").font(.system(size:18,weight:.semibold));Text(m.busy && m.cases.isEmpty ? "Loading workspace…":!m.caseListError.isEmpty ? "Workspace needs attention":"\(m.cases.filter{$0.available && $0.status != "Closed"}.count) active · \(m.cases.filter{$0.needsAttention}.count) need attention · \(m.cases.reduce(0){$0+$1.openTasks}) open tasks").foregroundStyle(LawlietTheme.secondary)}
                Spacer();Button("Case folders…"){m.dialog = .caseFolders}.disabled(m.busy);Button("Open existing case…"){m.openRetainedCase()}.disabled(m.busy);Button {m.refreshCases()} label:{Label("Refresh",systemImage:"arrow.clockwise")}.disabled(m.busy)
                Button(action:newCase){Label("New case",systemImage:"plus")}.buttonStyle(.borderedProminent).disabled(m.busy)
            }.padding(20)
            Text("Local catalog · \(m.catalogRoots.count) registered folders").font(.system(size:10)).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled).padding(.horizontal,20).padding(.bottom,10)
            if !m.catalogWarnings.isEmpty {DisclosureGroup("Catalog notices · \(m.catalogWarnings.count)\(m.catalogPartial ? " · incomplete discovery":"")"){ForEach(Array(m.catalogWarnings.enumerated()),id:\.offset){_,text in Text(text).font(.caption).textSelection(.enabled)}}.padding(.horizontal,20).padding(.bottom,10)}
            HStack(spacing:12) {
                Button {searchFocused=true} label:{Image(systemName:"magnifyingglass")}.buttonStyle(.plain).keyboardShortcut("f",modifiers:.command).help("Search cases · ⌘F")
                TextField("Search case, client or examiner",text:$m.caseQuery).textFieldStyle(.plain).accessibilityLabel("Search cases").focused($searchFocused)
                if !query.isEmpty {Button {m.caseQuery=""} label:{Image(systemName:"xmark.circle.fill")}.buttonStyle(.plain).foregroundStyle(LawlietTheme.secondary).accessibilityLabel("Clear case search")}
                Picker("Status",selection:$m.caseQueueStatus){Text("Active").tag("Active");Text("Needs attention").tag("Needs attention");Text("All cases").tag("All cases");ForEach(caseStatuses,id:\.self){Text($0).tag($0)}}.frame(width:185).help("Needs attention: awaiting input, in review, or overdue by this Mac's calendar date.")
                Picker("Sort",selection:$m.caseQueueSort){ForEach(["Recent","Priority","Due date"],id:\.self){Text($0).tag($0)}}.frame(width:150)
            }.padding(12).background(LawlietTheme.panel).padding(.horizontal,20).padding(.bottom,12)
            if m.busy && m.cases.isEmpty {
                VStack(spacing:12){ProgressView();Text("Loading cases…").foregroundStyle(LawlietTheme.secondary)}.frame(maxWidth:.infinity,maxHeight:.infinity)
            } else if !m.caseListError.isEmpty {
                VStack(alignment:.leading,spacing:12) {
                    Label("Workspace unavailable",systemImage:"exclamationmark.triangle").font(.headline)
                    Text(m.caseListError).textSelection(.enabled)
                    Text("Check the drive connection and selected folder, then retry.").foregroundStyle(LawlietTheme.secondary)
                    HStack {Button("Retry"){m.refreshCases()};Button("Choose workspace"){m.chooseWorkspace()}}
                }.padding(24).frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading)
            } else if matching.isEmpty {
                VStack(spacing:10){Image(systemName:"folder").font(.system(size:26)).foregroundStyle(LawlietTheme.secondary);Text(m.cases.isEmpty ? "Your cases start here":"No matching cases").font(.headline);Text(m.cases.isEmpty ? "Create a case or add a case folder. Check catalog notices for unavailable locations.":"Try a different search or show all cases.").foregroundStyle(LawlietTheme.secondary)}.frame(maxWidth:.infinity,maxHeight:.infinity)
            } else {
                Table(pageRows,selection:$selection) {
                    TableColumn("Case") {c in VStack(alignment:.leading,spacing:3){Text(c.name).fontWeight(.medium).lineLimit(1);Text(c.location).font(.system(size:10,design:.monospaced)).foregroundStyle(LawlietTheme.secondary).lineLimit(1)}.padding(.vertical,5).help(c.id)}.width(min:220,ideal:320)
                    TableColumn("Status") {c in CaseStatusLabel(status:c.available ? c.status:"Unavailable").help(c.error)}.width(120)
                    TableColumn("Priority",value:\.priority).width(65)
                    TableColumn("Client / reference") {c in Text(c.client.isEmpty ? "—":c.client).lineLimit(1)}.width(min:100,ideal:140)
                    TableColumn("Examiner") {c in Text(c.owner.isEmpty ? "Unassigned":c.owner).lineLimit(1)}.width(min:90,ideal:120)
                    TableColumn("Due") {c in Text(c.due.isEmpty ? "—":c.due).monospacedDigit().foregroundStyle(c.overdue ? .orange:.primary).help(c.overdue ? "Overdue · administrative due date":"Administrative due date")}.width(82)
                    TableColumn("Tasks") {c in Text("\(c.openTasks)").monospacedDigit()}.width(40)
                }.contextMenu(forSelectionType:String.self) {ids in
                    if let id=ids.first {Button("Open case"){m.openCase(id)}}
                } primaryAction:{ids in if let id=ids.first {m.openCase(id)}}
                .disabled(m.busy)
                if let selected=m.cases.first(where:{$0.id==selection}) {Text(selected.error.isEmpty ? selected.id:selected.error).font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled).padding(.horizontal,20).padding(.top,8)}
            }
            HStack {Text(!m.caseListError.isEmpty ? "Workspace unavailable · case list not refreshed":"\(matching.count) \(matching.count==1 ? "case":"cases") · case status is administrative; it does not approve a report.").font(.caption).foregroundStyle(LawlietTheme.secondary);Spacer();Button("Previous"){page=max(0,page-1)}.disabled(m.busy || page==0);Text("Page \(page+1)").font(.caption);Button("Next"){page+=1}.disabled(m.busy || (page+1)*50>=matching.count);Button("Open case"){if let id=selection {m.openCase(id)}}.disabled(m.busy || !m.caseListError.isEmpty || !matching.contains(where:{$0.id==selection && $0.available})).keyboardShortcut(.defaultAction)}.padding(14)
        }.onAppear{selection=m.currentCasePath}.onChange(of:m.currentCasePath){selection=$0}.onChange(of:m.caseQuery){_ in page=0}.onChange(of:m.caseQueueStatus){_ in page=0}.onChange(of:m.caseQueueSort){_ in page=0}.onChange(of:m.cases.map{ $0.id }){_ in page=0}
    }
}

struct CaseOverviewView:View {
    @ObservedObject var m:AppModel
    @State private var edit=false
    @State private var task=""
    private func addTask() {
        guard !task.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,task.count<=2000 else {return}
        let text=task
        m.perform("Adding task…") {_ = try await m.request("case-task-add",["case":m.caseID,"text":text]);task="";m.caseTaskOffset=0;try await m.loadCaseManagement();try await m.reloadCaseList()}
    }
    private func field(_ label:String,_ value:String) -> some View {
        VStack(alignment:.leading,spacing:5){Text(label.uppercased()).font(.system(size:10,weight:.medium)).foregroundStyle(LawlietTheme.secondary);Text(value.isEmpty ? "Not set":value).textSelection(.enabled)}.frame(maxWidth:.infinity,alignment:.leading)
    }
    private func sectionTitle(_ text:String) -> some View {Text(text).font(.system(size:13,weight:.semibold))}
    var body:some View {
        ScrollView {
            VStack(alignment:.leading,spacing:18) {
                HStack {CaseStatusLabel(status:m.managementValue("status"));Text("· \(m.managementValue("priority")) priority").foregroundStyle(LawlietTheme.secondary);Spacer();Button("Edit case details"){edit=true}.disabled(m.busy)}
                HStack(alignment:.top,spacing:20){field("Client / reference",m.managementValue("client"));field("Examiner",m.managementValue("owner"));field("Due date",m.managementValue("due_date"));field("Case ID",m.caseID)}.padding(16).background(LawlietTheme.panel).cornerRadius(6)
                HStack(alignment:.top,spacing:18) {
                    VStack(alignment:.leading,spacing:16) {
                        sectionTitle("Investigation brief")
                        field("Objective",m.managementValue("objective"))
                        field("Authorized scope",m.managementValue("scope"))
                        if !m.managementValue("notes").isEmpty {DisclosureGroup("Administrative notes") {Text(m.managementValue("notes")).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading).padding(.top,6)}}
                        Divider()
                        sectionTitle("Evidence & review")
                        HStack {Label("\(m.evidenceItems.count) evidence sources",systemImage:"externaldrive");Spacer();Text("\(m.runItems.count) analysis runs").foregroundStyle(LawlietTheme.secondary)}
                        Text("Integrity: \(m.verification)").foregroundStyle(LawlietTheme.secondary)
                        HStack {Button("Evidence & processing"){m.mode="Sources"};Button("Saved findings"){m.loadFindings()};Button("Report history"){m.dialog = .reportHistory}.disabled(m.busy)}
                        HStack {Button("Coverage & review"){m.mode="Coverage"};Button("Agent investigation"){m.dialog = .investigationEngine}.disabled(m.busy)}
                        Text("Case status and tasks organize work. Findings and report approval keep their separate review records.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                    }.padding(16).frame(maxWidth:.infinity,alignment:.leading).background(LawlietTheme.panel).cornerRadius(6)
                    VStack(alignment:.leading,spacing:12) {
                        HStack {sectionTitle("Follow-up tasks");Spacer();Text("\(m.openTaskCount) open").foregroundStyle(LawlietTheme.secondary)}
                        HStack {TextField("Add an investigative follow-up…",text:$task).textFieldStyle(.roundedBorder).accessibilityLabel("New case task").onSubmit{addTask()};Button("Add"){addTask()}.disabled(m.busy || task.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty || task.count>2000)}
                        if m.caseTasks.isEmpty {Text("Track outstanding questions, missing evidence and review work here.").foregroundStyle(LawlietTheme.secondary).padding(.vertical,8)}
                        ForEach(m.caseTasks) {item in
                            HStack(alignment:.top,spacing:8){Button {m.setTask(item)} label:{Image(systemName:item.completed ? "checkmark.circle.fill":"circle").foregroundStyle(item.completed ? .secondary:Color.accentColor)}.buttonStyle(.plain).accessibilityLabel(item.completed ? "Reopen task: \(item.text)":"Complete task: \(item.text)").disabled(m.busy);Text(item.text).strikethrough(item.completed).foregroundStyle(item.completed ? .secondary:.primary).textSelection(.enabled);Spacer()};Divider()
                        }
                        if m.caseTaskOffset>0 || m.caseTasksMore {HStack {Button("Previous tasks"){m.taskPage(max(0,m.caseTaskOffset-100))}.disabled(m.busy || m.caseTaskOffset==0);Spacer();Button("Next tasks"){m.taskPage(m.caseTaskOffset+100)}.disabled(m.busy || !m.caseTasksMore)}}
                    }.padding(16).frame(maxWidth:.infinity,alignment:.leading).background(LawlietTheme.panel).cornerRadius(6)
                }
                DisclosureGroup("Recent activity · last 30 audit entries") {
                    VStack(spacing:0){ForEach(m.caseActivity) {event in HStack {Text(event.action.replacingOccurrences(of:".",with:" › ").replacingOccurrences(of:"_",with:" "));Spacer();Text(event.at).font(.system(size:11,design:.monospaced)).foregroundStyle(LawlietTheme.secondary)}.padding(.vertical,7);Divider()}}
                    Text("Local audit history; examiner labels are not authenticated identities.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                }.padding(16).background(LawlietTheme.panel).cornerRadius(6)
            }.padding(20)
        }.sheet(isPresented:$edit){CaseDetailsEditor(m:m)}
    }
}

struct CaseDetailsEditor:View {
    @ObservedObject var m:AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var values:[String:String]=[:]
    @State private var revision=0
    @State private var error=""
    private func binding(_ key:String) -> Binding<String> {Binding(get:{values[key] ?? ""},set:{values[key]=$0})}
    var body:some View {
        VStack(alignment:.leading,spacing:14) {
            HStack {Text("Case details").font(.system(size:18,weight:.semibold));Spacer();Text(m.caseID).font(.caption).foregroundStyle(LawlietTheme.secondary)}
            HStack {Picker("Status",selection:binding("status")){ForEach(caseStatuses,id:\.self){Text($0).tag($0)}};Picker("Priority",selection:binding("priority")){ForEach(casePriorities,id:\.self){Text($0).tag($0)}}}
            HStack {TextField("Client or reference",text:binding("client"));TextField("Assigned examiner",text:binding("owner"))}
            TextField("Due date · YYYY-MM-DD (optional)",text:binding("due_date"))
            Text("Investigation objective").font(.caption).foregroundStyle(LawlietTheme.secondary)
            TextEditor(text:binding("objective")).frame(height:65).border(.gray.opacity(0.2)).accessibilityLabel("Case objective")
            Text("Authorized scope & exclusions").font(.caption).foregroundStyle(LawlietTheme.secondary)
            TextEditor(text:binding("scope")).frame(height:80).border(.gray.opacity(0.2)).accessibilityLabel("Case scope")
            Text("Administrative notes").font(.caption).foregroundStyle(LawlietTheme.secondary)
            TextEditor(text:binding("notes")).frame(height:70).border(.gray.opacity(0.2)).accessibilityLabel("Case notes")
            Text("Changes are saved in this case's local audit history. Scope notes do not authorize collection, uploads or report release.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            if !error.isEmpty {Label(error,systemImage:"exclamationmark.circle").foregroundStyle(.red).font(.caption).textSelection(.enabled).fixedSize(horizontal:false,vertical:true)}
            HStack {Button("Cancel"){dismiss()}.keyboardShortcut(.cancelAction);Spacer();Button("Save details") {
                let snapshot=values;error=""
                m.perform("Saving case details…",onError:{error=$0.localizedDescription}) {
                    _ = try await m.request("case-update",["case":m.caseID,"values":snapshot,"revision":revision])
                    try await m.loadCaseManagement();try await m.reloadCaseList();dismiss()
                }
            }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)}
        }.disabled(m.busy).padding(24).frame(width:570).textFieldStyle(.roundedBorder)
        .onAppear {for key in ["status","priority","client","owner","due_date","objective","scope","notes"] {values[key]=m.managementValue(key)};revision=m.caseProfile["revision"] as? Int ?? 0}
    }
}
