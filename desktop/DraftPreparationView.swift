import SwiftUI

/// Explicit selection of existing saved findings; deterministic backend binding.
/// This creates an unreviewed local draft without running an agent or parsers.
struct DraftPreparationView:View {
    @ObservedObject var m:AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var objective=""
    @State private var findings:[FindingItem]=[]
    @State private var selected=Set<String>()
    @State private var offset=0
    @State private var total=0
    @State private var more=false
    @State private var working=false
    @State private var error=""
    @State private var investigationID=""
    @State private var boundIDs:[String]=[]
    @State private var context=""
    private var canCreate:Bool {!working && !m.busy && context==m.currentCasePath && !objective.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty && objective.count<=16000 && !selected.isEmpty && selected.count<=100}
    private func load(_ next:Int=0) {
        guard !working else {return};working=true;error=""
        let identity=context,workspace=m.workspace,caseID=m.caseID
        Task {
            do {
                let result=try await AppModel.bridge(["action":"findings","workspace":workspace,"case":caseID,"offset":next]) as? [String:Any] ?? [:]
                guard context==identity,m.currentCasePath==identity else {return}
                findings=(result["findings"] as? [[String:Any]] ?? []).map(FindingItem.init)
                total=result["total"] as? Int ?? 0;more=result["has_more"] as? Bool ?? false;offset=next
            } catch {if context==identity {self.error=error.localizedDescription}}
            if context==identity {working=false}
        }
    }
    private func create() {
        guard canCreate else {return};working=true;error=""
        let ids=selected.sorted(),question=objective,caseID=m.caseID,workspace=m.workspace,identity=context
        Task {
            do {
                // Retain a successful binding if report output fails; retrying the
                // same selection then reuses it rather than creating another ledger.
                if investigationID.isEmpty || boundIDs != ids {
                    let result=try await AppModel.bridge(["action":"investigation-from-findings","workspace":workspace,"case":caseID,"finding_ids":ids,"objective":question]) as? [String:Any] ?? [:]
                    guard context==identity,m.currentCasePath==identity else {return}
                    guard let iid=result["investigation_id"] as? String,!iid.isEmpty else {throw DraftReviewError.invalid("Backend returned no investigation identifier.")}
                    investigationID=iid;boundIDs=ids
                }
                guard context==identity,m.currentCasePath==identity else {return}
                let result=try await AppModel.bridge(["action":"customer-report-draft","workspace":workspace,"case":caseID,"investigation_id":investigationID]) as? [String:Any] ?? [:]
                guard context==identity,m.currentCasePath==identity else {return}
                guard let path=result["path"] as? String,result["review_status"] as? String=="draft_unreviewed" else {throw DraftReviewError.invalid("Backend did not return a supported unreviewed draft.")}
                m.draftPath=path;m.dialog = .draftReview
            } catch {if context==identity {self.error=error.localizedDescription}}
            if context==identity {working=false}
        }
    }
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            HStack {Text("Prepare an internal draft").font(.system(size:18,weight:.semibold));Spacer();Text(m.caseID).font(.caption).foregroundStyle(LawlietTheme.secondary)}
            Text("Select the saved findings to include. Their notes remain unreviewed interpretations, with source snapshots attached. This does not run Mulder, reparse evidence, approve or release a report.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            Text("Preparation verifies hashes across the whole case. Large collections can take time; findings exceeding the backend note limit are refused rather than shortened.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            TextField("Report investigation objective",text:$objective).accessibilityLabel("Draft investigation objective").disabled(working || !investigationID.isEmpty)
            if !investigationID.isEmpty {Text("Investigation retained: \(investigationID). Retry draft creation after resolving the error; the successful finding binding will be reused.").font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)}
            HStack {Text("\(selected.count) selected · \(total) saved findings in this case").font(.caption);Spacer();Button("Select this page"){for finding in findings.prefix(max(0,100-selected.count)){selected.insert(finding.id)}}.disabled(working || !investigationID.isEmpty || findings.isEmpty || selected.count>=100);Button("Clear selection"){selected=[]}.disabled(working || !investigationID.isEmpty || selected.isEmpty)}
            ScrollView {
                LazyVStack(alignment:.leading,spacing:12) {
                    if findings.isEmpty && !working {Text("No saved findings. Select an evidence record and choose Save finding first.").foregroundStyle(LawlietTheme.secondary)}
                    ForEach(findings) {finding in
                        HStack(alignment:.top,spacing:10) {
                            Toggle("Include finding: \(finding.artifact.title)",isOn:Binding(get:{selected.contains(finding.id)},set:{include in if include {selected.insert(finding.id)} else {selected.remove(finding.id)}})).labelsHidden().accessibilityLabel("Include finding: \(finding.artifact.title)").disabled(working || !investigationID.isEmpty || (selected.count>=100 && !selected.contains(finding.id)))
                            VStack(alignment:.leading,spacing:5){Text(finding.artifact.title).fontWeight(.medium);Text(finding.note).textSelection(.enabled);Text("\(finding.artifact.parser) · \(finding.artifact.sourceRef)").font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled);Text("Examiner label: \(finding.examiner.isEmpty ? "Unspecified":finding.examiner) · interpretation / unreviewed").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                        };Divider()
                    }
                }
            }.frame(minHeight:280)
            HStack {Button("Previous"){load(max(0,offset-100))}.disabled(working || offset==0);Text("Showing \(findings.isEmpty ? 0:offset+1)–\(offset+findings.count)").font(.caption);Button("Next"){load(offset+100)}.disabled(working || !more);Spacer();Text("Select up to 100 findings across pages").font(.caption).foregroundStyle(LawlietTheme.secondary)}
            if !error.isEmpty {Label(error,systemImage:"exclamationmark.triangle").font(.caption).foregroundStyle(.orange).textSelection(.enabled).fixedSize(horizontal:false,vertical:true)}
            HStack {Button("Cancel"){dismiss()}.disabled(working).keyboardShortcut(.cancelAction);if working {ProgressView().controlSize(.small)};Spacer();Button(investigationID.isEmpty ? "Create unreviewed draft":"Retry draft creation"){create()}.disabled(!canCreate).buttonStyle(.borderedProminent)}
        }.font(.system(size:12)).controlSize(.small).padding(20).frame(width:780,height:590)
        .task {context=m.currentCasePath;objective=m.managementValue("objective");load()}
        .onChange(of:m.currentCasePath){_ in context="";working=false;investigationID="";findings=[];selected=[];error="Case changed. Reopen preparation from the intended case."}
    }
}
