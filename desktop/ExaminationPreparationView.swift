import SwiftUI

/// A scoped, deterministic examination record. Queries execute against the local
/// index; the outcome never changes an evidence record or creates a finding.
struct ExaminationPreparationView:View {
    @ObservedObject var m:AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var objective=""
    @State private var examiner=""
    @State private var scope=""
    @State private var limitations=""
    @State private var queryText=""
    @State private var outcome="inconclusive"
    @State private var selected=Set<String>()
    @State private var working=false
    @State private var error=""
    @State private var investigationID=""
    @State private var context=""
    private var queries:[String] {queryText.components(separatedBy:.newlines).map{$0.trimmingCharacters(in:.whitespacesAndNewlines)}.filter{!$0.isEmpty}}
    private var canCreate:Bool {
        !working && !m.busy && context==m.currentCasePath && !selected.isEmpty && selected.count<=100 &&
        !objective.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty && objective.count<=16000 &&
        !examiner.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty && examiner.count<=200 &&
        !scope.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty && scope.count<=16000 &&
        !limitations.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty && limitations.count<=16000 &&
        queries.count<=20 && queries.allSatisfy{$0.count<=1000} && Set(queries).count==queries.count &&
        (outcome=="inconclusive" || !queries.isEmpty)
    }
    private func create() {
        guard canCreate else {return}
        working=true;error=""
        let workspace=m.workspace,caseID=m.caseID,identity=context
        let values:[String:Any]=["workspace":workspace,"case":caseID,"action":"investigation-from-examination",
            "objective":objective,"examiner":examiner,"examination_scope":scope,"limitations":limitations,
            "outcome":outcome,"queries":queries,"evidence_ids":selected.sorted()]
        Task {
            do {
                if investigationID.isEmpty {
                    let result=try await AppModel.bridge(values) as? [String:Any] ?? [:]
                    guard context==identity,m.currentCasePath==identity else {return}
                    guard result["review_status"] as? String=="unreviewed",let id=result["investigation_id"] as? String,!id.isEmpty else {throw DraftReviewError.invalid("No supported examination record was returned.")}
                    investigationID=id
                }
                guard context==identity,m.currentCasePath==identity else {return}
                let result=try await AppModel.bridge(["workspace":workspace,"case":caseID,"action":"customer-report-draft","investigation_id":investigationID]) as? [String:Any] ?? [:]
                guard context==identity,m.currentCasePath==identity else {return}
                guard result["review_status"] as? String=="draft_unreviewed",let path=result["path"] as? String else {throw DraftReviewError.invalid("The examination was retained, but no supported draft was returned.")}
                m.draftPath=path;m.dialog = .draftReview
            } catch {if context==identity,m.currentCasePath==identity {self.error=error.localizedDescription}}
            if context==identity {working=false}
        }
    }
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            HStack {Text("Scoped examination draft").font(.system(size:18,weight:.semibold));Spacer();Text(m.caseID).font(.caption).foregroundStyle(LawlietTheme.secondary)}
            Text("Record an inconclusive examination or a search with no indexed matches. The draft includes the actual queries, selected evidence and limitations. Saved findings are not required.").foregroundStyle(LawlietTheme.secondary)
            ScrollView {
                VStack(alignment:.leading,spacing:12) {
                    TextField("Investigation objective",text:$objective).accessibilityLabel("Examination objective")
                    TextField("Examiner label",text:$examiner).accessibilityLabel("Examination examiner")
                    Picker("Outcome",selection:$outcome){Text("Inconclusive").tag("inconclusive");Text("No indexed matches").tag("no_matches")}.pickerStyle(.segmented)
                    Text("No indexed matches requires at least one search and indexed records. Any matching query blocks that outcome. Neither outcome establishes that a device is free of compromise.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                    Text("Evidence scope · select up to 100 sources").fontWeight(.medium)
                    if m.evidenceItems.isEmpty {Text("Import evidence into this case first.").foregroundStyle(.orange)}
                    ForEach(m.evidenceItems) {item in
                        Toggle(isOn:Binding(get:{selected.contains(item.id)},set:{include in if include {selected.insert(item.id)} else {selected.remove(item.id)}})) {
                            Text("\(item.label) · \(item.id)").lineLimit(2)
                        }.disabled(!selected.contains(item.id) && selected.count>=100)
                    }
                    TextField("What was examined, including date range and application scope",text:$scope,axis:.vertical).lineLimit(2...4).accessibilityLabel("Examination scope")
                    Text("Literal searches · one per line, up to 20").fontWeight(.medium)
                    TextEditor(text:$queryText).frame(height:85).border(.gray.opacity(0.3)).accessibilityLabel("Examination queries")
                    Text("Searches run over indexed titles and bodies only. Inconclusive reports may omit searches if the limitations explain the missing evidence. A failed search stops preparation and is not recorded as zero matches.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                    TextField("Limitations, missing evidence, failures and alternative explanations",text:$limitations,axis:.vertical).lineLimit(3...6).accessibilityLabel("Examination limitations")
                }.disabled(working || !investigationID.isEmpty)
            }
            if !investigationID.isEmpty {Text("Examination retained: \(investigationID). Retry draft creation after resolving the error; its original scope and searches will be reused.").font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)}
            if !error.isEmpty {Text(error).font(.caption).foregroundStyle(.orange).textSelection(.enabled)}
            Text("Preparation verifies retained sources and binds the current index. Changed evidence or processing requires a new examination. Examiner approval and export remain separate.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            HStack {Button("Cancel"){dismiss()}.disabled(working).keyboardShortcut(.cancelAction);if working {ProgressView().controlSize(.small)};Spacer();Button(investigationID.isEmpty ? "Run searches & prepare draft":"Retry draft creation"){create()}.disabled(!canCreate).buttonStyle(.borderedProminent)}
        }.font(.system(size:12)).controlSize(.small).padding(20).frame(width:800,height:680)
        .task {context=m.currentCasePath;objective=m.managementValue("objective")}
        .onChange(of:m.currentCasePath){_ in context="";working=false;investigationID="";selected=[];error="Case changed. Reopen examination preparation from the intended case."}
    }
}
