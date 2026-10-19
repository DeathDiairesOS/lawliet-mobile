import SwiftUI
import AppKit

struct EngineInvestigationView: View {
    @ObservedObject var m:AppModel
    @State private var executable=""
    @State private var model=""
    @State private var provider="anthropic"
    @State private var objective=""
    @State private var questions=""
    @State private var facts=""
    @State private var scope=""
    @State private var evidence=""
    @State private var authorizeRemote=false
    @State private var authorizeEnrichment=false
    @State private var working=false
    @State private var polling=false
    @State private var message=""
    @State private var jobs:[[String:Any]]=[]
    @State private var jobID=""
    @State private var state:[String:Any]=[:]
    @State private var tab="Collect with agent"
    @State private var handoff:CodexInvestigationHandoff?
    @State private var logText=""
    @State private var reportText=""
    @State private var findings:[[String:Any]]=[]
    @State private var query=""
    @State private var offset=0
    @State private var more=false
    @State private var reviewer=""
    @State private var reviewNote=""
    @State private var outputCaseID=""
    @State private var outputVersion="1.5.2"
    private let timer=Timer.publish(every:3,on:.main,in:.common).autoconnect()
    private var usesLegacyEngine:Bool {!["Collect with agent","Codex + Mulder"].contains(tab)}
    private var handoffIsCurrent:Bool {
        handoff?.matches(workspace:m.workspace,caseID:m.caseID,evidenceID:evidence,objective:objective,questions:questions,scope:scope)==true && m.evidenceItems.contains{$0.id==evidence}
    }
    private var retainedSource:SourceItem? {m.sources.first{$0.evidence==evidence && $0.hasResults && !$0.isCaseWide}}
    private func prepareHandoff() {
        handoff=nil;message=""
        guard m.evidenceItems.contains(where:{$0.id==evidence}) else {message="Select imported evidence in this case.";return}
        do {handoff=try CodexInvestigationHandoff(workspace:m.workspace,caseID:m.caseID,evidenceID:evidence,objective:objective,questions:questions,scope:scope)}
        catch {message=error.localizedDescription}
    }
    private var handoffView:some View {
        VStack(alignment:.leading,spacing:10) {
            Text("Continue an investigation in Codex").font(.headline)
            Text("Codex reasons over the evidence using your configured Mulder MCP tools. Prepare a scoped request here, paste it into the intended Codex chat, then review retained results in Lawliet. This panel does not launch or control that chat.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            Picker("Evidence",selection:$evidence){Text("Select imported evidence").tag("");ForEach(m.evidenceItems){Text($0.label).tag($0.id)}}
            TextField("Investigation objective",text:$objective).accessibilityLabel("Codex investigation objective")
            Text("Questions (optional)").font(.caption)
            TextEditor(text:$questions).frame(height:55).border(.gray.opacity(0.3)).accessibilityLabel("Codex investigation questions")
            TextField("Authorized examination scope",text:$scope).accessibilityLabel("Codex examination scope")
            Text("The request includes your briefing and local case paths. Review the configured Codex model and data policy before pasting it; this panel cannot verify its connection, permissions or provider.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            HStack {
                Button("Prepare request"){prepareHandoff()}.disabled(evidence.isEmpty || m.busy)
                Button("Copy request") {
                    guard handoffIsCurrent,let request=handoff else {return}
                    NSPasteboard.general.clearContents();NSPasteboard.general.setString(request.text,forType:.string)
                    message="Copied the scoped request. Paste it into the intended Codex chat to continue; no investigation was started here."
                }.disabled(!handoffIsCurrent || m.busy)
                if handoff != nil && !handoffIsCurrent {Text("Briefing changed · prepare it again before copying.").font(.caption).foregroundStyle(.orange)}
            }
            if let request=handoff,handoffIsCurrent {
                DisclosureGroup("Review prepared request · \(request.text.utf8.count.formatted()) bytes") {
                    Text(request.text).font(.system(size:10,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)
                }
            }
            Divider()
            Text("Review retained work").fontWeight(.medium)
            HStack {
                Button("Open indexed results"){if let source=retainedSource {m.dialog=nil;m.reviewSource(source.id)}}.disabled(retainedSource==nil || m.busy)
                Button("Evidence & processing"){m.dialog=nil;m.mode="Sources"}.disabled(m.busy)
                Button("Coverage & review"){m.dialog=nil;m.mode="Coverage"}.disabled(m.busy)
            }
            Text("Indexed results show a retained source for the selected evidence. Mulder tool visibility and successful case access must be checked in the connected Codex chat; neither is established by preparing this request.").font(.caption).foregroundStyle(LawlietTheme.secondary)
        }
    }
    private var config:[String:Any] {
        ["executable":executable,"model":model,"provider":provider,"objective":objective,
         "questions":questions,"known_facts":facts,"scope":scope,"evidence_id":evidence,
         "authorize_remote":authorizeRemote,"authorize_enrichment":authorizeEnrichment,"workers":1,"timeout":7200,"max_output_gib":5]
    }
    private func request(_ action:String,_ values:[String:Any]=[:]) async throws -> Any {
        var p=values;p["case"]=m.caseID
        return try await m.request(action,p)
    }
    private func perform(_ body:@escaping () async throws -> Void) {
        guard !working else {return};working=true
        Task {do {try await body()} catch {message=error.localizedDescription};working=false}
    }
    private func refresh() async throws {
        let context=m.currentCasePath
        let refreshed=try await request("engine-list") as? [[String:Any]] ?? []
        guard context==m.currentCasePath,usesLegacyEngine else {return}
        jobs=refreshed
        if jobID.isEmpty {jobID=jobs.last?["id"] as? String ?? ""}
        if !jobID.isEmpty {
            let selected=jobID
            let result=try await request("engine-status",["job_id":selected]) as? [String:Any] ?? [:]
            guard context==m.currentCasePath,jobID==selected,usesLegacyEngine else {return}
            let logs=try await request("engine-logs",["job_id":selected]) as? [String:Any] ?? [:]
            guard context==m.currentCasePath,jobID==selected,usesLegacyEngine else {return}
            state=result
            logText=(logs["truncated"] as? Bool == true ? "[Last 16 KiB]\n":"")+(logs["text"] as? String ?? "")
        }
    }
    private func loadFindings() async throws {
        guard !jobID.isEmpty else {findings=[];more=false;return}
        let selected=jobID,context=m.currentCasePath,submittedQuery=query,submittedOffset=offset
        let result=try await request("engine-findings",["job_id":selected,"query":query,"offset":offset]) as? [String:Any] ?? [:]
        guard context==m.currentCasePath,jobID==selected,query==submittedQuery,offset==submittedOffset else {return}
        findings=result["records"] as? [[String:Any]] ?? [];more=result["has_more"] as? Bool ?? false
    }
    private func loadReport() async throws {
        guard !jobID.isEmpty else {reportText="";return}
        let selected=jobID,context=m.currentCasePath
        let r=try await request("engine-report",["job_id":selected]) as? [String:Any] ?? [:]
        guard context==m.currentCasePath,jobID==selected else {return}
        reportText=(r["text"] as? String ?? "")+(r["truncated"] as? Bool == true ? "\n[Preview truncated at 2 MiB]":"")
    }
    var body:some View {
        VStack(alignment:.leading,spacing:10) {
            HStack {Text("Agent investigation").font(.system(size:17,weight:.semibold));Spacer();Text(m.caseID).foregroundStyle(LawlietTheme.secondary)}
            Text("AI-generated interpretations require source verification and examiner review.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            Picker("Workflow",selection:$tab){
                Text("Collect with agent").tag("Collect with agent")
                Text("Examine retained evidence · Codex + Mulder").tag("Codex + Mulder")
                Text("Import autonomous Mulder output").tag("Import output")
                Text("Legacy autonomous launcher · advanced").tag("Launch engine")
                Text("Imported / legacy runs").tag("Runs")
                Text("Imported / legacy findings").tag("Findings")
                Text("Imported / legacy report").tag("Report")
                Text("Imported / legacy logs").tag("Logs")
            }.disabled(working)
            ScrollView {
                VStack(alignment:.leading,spacing:10) {
                    if tab=="Collect with agent" {AgentCollectionView(m:m)}
                    else if tab=="Codex + Mulder" {handoffView}
                    else if tab=="Launch engine" {
                        Text("Separate legacy adapter · reviewed upstream CLI 1.5.2 only. The patched Mulder installed by Lawliet setup serves the current MCP workflow and is not accepted by this launcher.").font(.caption).foregroundStyle(.orange)
                        Text("Native macOS and local-model autonomous execution are not yet validated. Working copies are not an OS sandbox.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                        Text("This launches mulder investigate, the autonomous engine. Codex uses a separate mulder serve / MCP connection; this panel does not control that session.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                        Picker("Evidence",selection:$evidence){Text("Select imported evidence").tag("");ForEach(m.evidenceItems){Text($0.label).tag($0.id)}}
                        Button("Import evidence only…") {
                            let panel=NSOpenPanel();panel.canChooseDirectories=true;panel.canChooseFiles=true
                            if panel.runModal() == .OK,let url=panel.url {perform {
                                let r=try await request("engine-import",["path":url.path]) as? [String:Any] ?? [:]
                                evidence=r["evidence_id"] as? String ?? "";try await m.loadCase()
                            }}
                        }
                        TextField("Mulder executable path (blank uses PATH)",text:$executable)
                        Picker("Provider",selection:$provider){Text("Anthropic · remote").tag("anthropic");Text("Ollama · local, launch pending validation").tag("ollama")}
                        TextField("Explicit model identifier",text:$model)
                        Text("Credentials stay in the host environment. For the remote route, ANTHROPIC_API_KEY must be available to the app; do not enter it in the briefing.").font(.caption)
                        TextField("Investigation objective",text:$objective)
                        Text("Investigative questions").font(.caption)
                        TextEditor(text:$questions).frame(height:60).border(.gray.opacity(0.3)).accessibilityLabel("Investigative questions")
                        TextField("Known facts (optional)",text:$facts)
                        TextField("Scope and limitations (optional)",text:$scope)
                        Toggle("I authorize sending this evidence to the selected remote model provider",isOn:$authorizeRemote).disabled(provider != "anthropic")
                        Toggle("I separately authorize upstream IP-indicator lookup at ip-api.com (HTTP)",isOn:$authorizeEnrichment)
                        Text("Mulder 1.5.2 has no reviewed global enrichment-disable option. Leave this unchecked to block launch when that disclosure is outside scope.").font(.caption)
                        HStack {
                            Button("Check setup"){perform {let r=try await request("engine-check",["config":config]) as? [String:Any] ?? [:];message=(r["errors"] as? [String] ?? []).joined(separator:"\n");if message.isEmpty {message="Reviewed CLI detected. Credentials and the complete forensic toolchain have not been tested by this probe."}}}
                            Button("Start investigation"){perform {let r=try await request("engine-start",["config":config]) as? [String:Any] ?? [:];jobID=r["id"] as? String ?? "";message="Investigation queued. Closing this panel does not cancel it.";tab="Runs";try await refresh()}}.disabled(evidence.isEmpty || objective.isEmpty || model.isEmpty || !authorizeEnrichment || (provider=="anthropic" && !authorizeRemote))
                        }
                    } else if tab=="Import output" {
                        Text("Review an existing Mulder investigation").font(.headline)
                        Text("Select its completed output folder. Lawliet preserves and hashes the supplied database, audit log and reports, then indexes them locally. No model, agent or forensic parser is launched.")
                        TextField("Mulder case ID (matches the output filenames)",text:$outputCaseID)
                        TextField("Mulder version used to produce these outputs",text:$outputVersion)
                        Text("Version is examiner-supplied; supported schema: 1.5.2. Imported reports do not establish upstream execution success or possession of the original device evidence.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                        Button("Choose Mulder output folder…") {
                            let panel=NSOpenPanel();panel.canChooseDirectories=true;panel.canChooseFiles=false
                            if panel.runModal() == .OK,let url=panel.url {perform {
                                let r=try await request("engine-import-output",["path":url.path,"upstream_case_id":outputCaseID,"version":outputVersion]) as? [String:Any] ?? [:]
                                jobID=r["id"] as? String ?? "";try await m.loadCase();try await refresh()
                                tab="Runs";message="Output import: \(r["status"] as? String ?? "unknown"). No investigation was executed."
                            }}
                        }.disabled(outputCaseID.isEmpty || outputVersion.isEmpty)
                    } else {
                        Picker("Investigation run",selection:$jobID){Text("Select run").tag("");ForEach(jobs.indices,id:\.self){i in Text("\((jobs[i]["id"] as? String ?? "").prefix(12)) · \(jobs[i]["status"] as? String ?? "unknown")").tag(jobs[i]["id"] as? String ?? "")}}
                        if jobs.isEmpty {Text("No imported or legacy autonomous runs in this case. Current Codex/Mulder MCP results appear in Evidence & processing and the artifact views.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                        if tab=="Runs" {
                            Text("Status: \(state["status"] as? String ?? "No run selected")").font(.headline)
                            Text(state["objective"] as? String ?? "").textSelection(.enabled)
                            if state["execution_mode"] as? String == "output_import" {
                                Text("Imported output · upstream execution status unknown · version supplied by examiner").font(.caption).foregroundStyle(LawlietTheme.secondary)
                            }
                            if let error=state["error"] as? String {Text(error).foregroundStyle(.orange)}
                            if let results=state["results"] as? [String:Any] {
                                Text("\(results["findings"] as? Int ?? 0) findings · \(results["windows"] as? Int ?? 0) indexed windows")
                                Text("Windows are indexed output chunks, not message counts or whole-phone coverage.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                                Text((results["warnings"] as? [String] ?? []).joined(separator:"\n")).textSelection(.enabled)
                            }
                            Text((state["limitations"] as? [String] ?? []).joined(separator:"\n")).font(.caption)
                            Button("Request cancellation"){perform {_ = try await request("engine-cancel",["job_id":jobID]);message="Cancellation requested.";try await refresh()}}.disabled(jobID.isEmpty || ["completed","partial","failed","cancelled","interrupted"].contains(state["status"] as? String ?? ""))
                            Button("Open this run in Artifact Explorer"){m.dialog=nil;m.sourceID=jobID;m.mode="All artifacts";m.perform("Loading engine results…"){try await m.loadCase()}}.disabled(jobID.isEmpty)
                        } else if tab=="Findings" {
                            HStack{TextField("Search findings",text:$query);Button("Search"){offset=0;perform{try await loadFindings()}}}.disabled(jobID.isEmpty)
                            TextField("Examiner name for review decisions",text:$reviewer)
                            TextField("Review note / limitations",text:$reviewNote)
                            ForEach(findings.indices,id:\.self){i in
                                DisclosureGroup(findings[i]["title"] as? String ?? "Finding") {
                                    VStack(alignment:.leading,spacing:6) {
                                    Text(findings[i]["body"] as? String ?? "").textSelection(.enabled)
                                    Text("AI-generated interpretation · examiner decision kept separately").font(.caption).foregroundStyle(.orange)
                                    Text("Examiner decision: \((findings[i]["examiner_review"] as? [String:Any])?["decision"] as? String ?? "unreviewed")").font(.caption)
                                    Text(findings[i]["source_ref"] as? String ?? "").font(.caption).textSelection(.enabled)
                                    EngineFindingEvidence(data:findings[i]["data"] as? [String:Any] ?? [:])
                                    Button("Save examiner review note") {m.findingArtifactID=findings[i]["id"] as? String ?? "";m.findingTitle=findings[i]["title"] as? String ?? "";m.findingNote="";m.dialog = .findingNote}
                                    HStack {ForEach(["approved","rejected","needs_follow_up"],id:\.self){decision in
                                        Button(decision.replacingOccurrences(of:"_",with:" ").capitalized){perform {
                                            _ = try await request("engine-review",["artifact_id":findings[i]["id"] as? String ?? "","decision":decision,"reviewer":reviewer,"note":reviewNote]);try await loadFindings()
                                        }}.disabled(reviewer.isEmpty)
                                    }}
                                    }.frame(maxWidth:.infinity,alignment:.leading)
                                }
                            }
                            HStack{Button("Previous"){offset=max(0,offset-100);perform{try await loadFindings()}}.disabled(offset==0);Text(findings.isEmpty ? "No findings loaded":"Rows \(offset+1)–\(offset+findings.count)");Button("Next"){offset+=100;perform{try await loadFindings()}}.disabled(!more)}
                        } else if tab=="Report" {
                            Text("Original Mulder Markdown · unreviewed · shown as text without executing HTML").font(.caption)
                            Button("Reload report"){perform {try await loadReport()}}.disabled(jobID.isEmpty)
                            Button("Export original Markdown…") {let panel=NSSavePanel();panel.nameFieldStringValue="Mulder-draft.md";if panel.runModal() == .OK,let url=panel.url {perform {_ = try await request("engine-export-report",["job_id":jobID,"path":url.path]);message="Original draft report exported. Finding reviews do not rewrite or approve the upstream report."}}}.disabled(jobID.isEmpty)
                            Text(reportText).font(.system(size:12)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)
                        } else {Text(logText).font(.system(size:11,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)}
                    }
                }.padding(4).disabled(working)
            }.frame(height:460)
            Text(message).font(.caption).textSelection(.enabled).lineLimit(5)
            HStack{if working {ProgressView().controlSize(.small)};if usesLegacyEngine {Button("Refresh"){perform{try await refresh()}}};Spacer();Button("Close"){m.dialog=nil}}
        }.font(.system(size:12)).controlSize(.small).padding(20).frame(width:700)
        .task {evidence=m.source?.evidence ?? "";objective=m.managementValue("objective");scope=m.managementValue("scope")}
        .onChange(of:m.currentCasePath){_ in handoff=nil;evidence="";objective="";questions="";scope="";message="";jobs=[];jobID="";state=[:];findings=[];reportText="";logText="";tab="Collect with agent"}
        .onReceive(timer){_ in if ["Runs","Logs"].contains(tab) && !working && !polling {
            polling=true
            Task {do {try await refresh()} catch {message=error.localizedDescription};polling=false}
        }}
        .onChange(of:jobID){_ in findings=[];reportText="";offset=0;guard usesLegacyEngine else {return};perform{
            try await refresh()
            if tab=="Findings" {try await loadFindings()}
            if tab=="Report" {try await loadReport()}
        }}
        .onChange(of:tab){value in message="";if usesLegacyEngine {perform {
            try await refresh()
            if value=="Findings" {try await loadFindings()}
            if value=="Report" {try await loadReport()}
        }}}
    }
}

private struct EngineFindingEvidence:View {
    let data:[String:Any]
    var body:some View {
        VStack(alignment:.leading,spacing:6) {
            Text("Severity: \(data["severity"] as? String ?? "unknown") · Confidence: \(data["confidence"] as? String ?? "unspecified")")
            Text("Engine: \(data["engine"] as? String ?? "unknown") \(data["engine_version"] as? String ?? "")").font(.caption)
            if let refs=data["supporting_evidence"] as? [[String:Any]] {
                ForEach(refs.indices,id:\.self){i in
                    let ref=refs[i]
                    Text("Tool-call citation: \(ref["tool_call_id"] as? String ?? "unknown") · \(ref["tool"] as? String ?? "unresolved") · audit line \((ref["audit_line"] as? Int).flatMap{$0>0 ? String($0):nil} ?? "unavailable") · \(ref["verified_in_audit"] as? Bool == true ? "ID present":"unverified")").font(.caption).textSelection(.enabled)
                }
            }
            Text((data["limitations"] as? [String] ?? []).joined(separator:"\n")).font(.caption).foregroundStyle(LawlietTheme.secondary)
            DisclosureGroup("Original fields and complete provenance") {
                if let raw=try? JSONSerialization.data(withJSONObject:data,options:[.prettyPrinted,.sortedKeys]),let text=String(data:raw,encoding:.utf8) {
                    Text(text).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
                }
            }
        }
    }
}
