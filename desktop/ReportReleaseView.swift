import SwiftUI
import AppKit

struct ReportReleaseView:View {
    @ObservedObject var m:AppModel
    let draft:DraftReview
    let openDerivative:(String)->Void
    @Environment(\.dismiss) private var dismiss
    @State private var binding:ReportReviewBinding?
    @State private var verification:ReportReviewVerification?
    @State private var working=false
    @State private var error=""
    @State private var reviewer=""
    @State private var declaration=""
    @State private var acknowledged=false
    @State private var literals=""
    @State private var showRedaction=false
    @State private var exportedPath=""
    private var current:Bool {binding?.workspace==m.workspace && binding?.caseID==m.caseID}
    private func response(_ request:[String:Any]) async throws->[String:Any] {
        guard current else {throw DraftReviewError.invalid("The selected case changed. Reopen this report.")}
        guard let result=try await AppModel.bridge(request) as? [String:Any] else {throw DraftReviewError.invalid("Invalid report response.")}
        guard current else {throw DraftReviewError.invalid("The selected case changed; inspect report history for the completed action.")}
        return result
    }
    private func check() {
        guard let binding=binding,!working else {return};working=true;error="";verification=nil
        Task {do {verification=try ReportReviewVerification(try await response(binding.request("review")),binding:binding)} catch {self.error=error.localizedDescription};working=false}
    }
    private func approve() {
        guard let binding=binding,!working,verification != nil else {return};working=true;error=""
        Task {
            do {
                let value=try await response(binding.request("approve",reviewer:reviewer,declaration:declaration,acknowledged:acknowledged))
                guard value[binding.identifierKey] as? String==binding.id,value["manifest_sha256"] as? String==binding.manifestHash else {throw DraftReviewError.invalid("Approval response does not match this bundle.")}
                verification=try ReportReviewVerification(try await response(binding.request("review")),binding:binding)
                declaration="";acknowledged=false
            } catch {verification=nil;self.error=error.localizedDescription}
            working=false
        }
    }
    private func export() {
        guard let binding=binding,!working,current,verification?.approved==true else {return}
        let panel=NSSavePanel();panel.title="Export approved report locally";panel.message="Choose a new folder name. Existing folders are refused. This creates a local copy only; it does not send the report."
        panel.nameFieldStringValue="LAWLIET-\(binding.caseID)-\(binding.id.prefix(8))";panel.canCreateDirectories=true
        guard panel.runModal() == .OK,let url=panel.url else {return}
        working=true;error="";exportedPath=""
        Task {
            do {
                let value=try await response(binding.request("release",path:url.path))
                guard value[binding.identifierKey] as? String==binding.id,value["manifest_sha256"] as? String==binding.manifestHash,
                      let path=value["path"] as? String else {throw DraftReviewError.invalid("Export receipt does not match this bundle.")}
                exportedPath=path
            } catch {verification=nil;self.error=error.localizedDescription}
            working=false
        }
    }
    private func redact() {
        guard let binding=binding,!working,verification != nil else {return};working=true;error=""
        Task {
            do {
                let value=try await response(binding.request("redact",literals:literals))
                guard value["source_draft_id"] as? String==binding.id,value["source_manifest_sha256"] as? String==binding.manifestHash,
                      value["review_status"] as? String=="unreviewed_redacted_derivative",let path=value["path"] as? String else {throw DraftReviewError.invalid("Derivative response does not match the reviewed original.")}
                literals="";dismiss();openDerivative(path)
            } catch {self.error=error.localizedDescription}
            working=false
        }
    }
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            HStack {Text("Examiner review & local export").font(.system(size:17,weight:.semibold));Spacer();Button("Close"){dismiss()}.disabled(working).keyboardShortcut(.cancelAction)}
            Text(draft.kind=="redacted" ? "SELECTED-LITERAL DERIVATIVE · REFERENCES ONLY":"ORIGINAL BUNDLE · UNREDACTED").font(.caption).foregroundStyle(.orange)
            Text("Case \(draft.caseID) · Bundle \(draft.id)").font(.caption).textSelection(.enabled)
            Text("SHA-256: \(draft.manifestHash)").font(.system(size:10,design:.monospaced)).textSelection(.enabled)
            HStack {Button("Recheck sources & bundle"){check()}.disabled(working || !current);if working {ProgressView().controlSize(.small)};Spacer();Text(verification == nil ? "Verification required":"Sources and reviewed bytes checked").font(.caption)}
            if let verified=verification,verified.approved {Label("Approval recorded: \(verified.reviewer) · \(verified.approvedAt)",systemImage:"checkmark.shield").font(.caption).textSelection(.enabled)}
            ScrollView {
                VStack(alignment:.leading,spacing:12) {
                    Text("Record examiner approval").font(.headline)
                    Text("Enter your own name and declaration after reviewing the report, source records and limitations. These fields start blank. A recorded declaration does not authenticate examiner identity or qualifications.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                    TextField("Examiner name",text:$reviewer).accessibilityLabel("Report examiner name")
                    Text("Approval declaration").font(.caption)
                    TextEditor(text:$declaration).font(.system(size:12)).frame(height:70).border(Color.secondary.opacity(0.3)).accessibilityLabel("Report approval declaration")
                    Toggle("I have reviewed this bundle’s content, sources and limitations.",isOn:$acknowledged)
                    Button("Record approval for these bytes"){approve()}.disabled(working || !current || verification==nil || !acknowledged || reviewer.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty || declaration.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty)
                    if draft.kind=="original" {
                        Divider()
                        DisclosureGroup("Create a selected-literal redacted derivative",isExpanded:$showRedaction) {
                            VStack(alignment:.leading,spacing:8) {
                                Text("One case-sensitive literal per line. Only those exact variants are removed from text and structured fields. Media, attachments and PDFs are excluded. Review the new derivative separately; the original approval does not apply.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                                TextEditor(text:$literals).font(.system(size:12)).frame(height:70).border(Color.secondary.opacity(0.3)).accessibilityLabel("Report redaction literals")
                                Button("Create derivative for review"){redact()}.disabled(working || !current || verification==nil || literals.isEmpty)
                            }.padding(.top,6)
                        }
                    }
                    Divider()
                    Text("Export copies the approved bytes to a new local folder. Source or report changes block export. Original draft labels remain in the bundle; approval is recorded separately.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                }.disabled(working)
            }
            if !current {Text("Case changed. Close and reopen the report in the intended case.").foregroundStyle(.orange)}
            if !error.isEmpty {Text(error).foregroundStyle(.orange).font(.caption).textSelection(.enabled).fixedSize(horizontal:false,vertical:true)}
            if !exportedPath.isEmpty {HStack {Text("Local copy created: \(exportedPath)").font(.caption).textSelection(.enabled);Button("Reveal"){NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath:exportedPath)])}}}
            HStack {Spacer();Button("Export approved copy…"){export()}.disabled(working || !current || verification?.approved != true).buttonStyle(.borderedProminent)}
        }.font(.system(size:12)).controlSize(.small).padding(20).frame(width:740,height:650)
        .task {do {binding=try ReportReviewBinding(workspace:m.workspace,caseID:draft.caseID,id:draft.id,kind:draft.kind,manifestHash:draft.manifestHash);check()} catch {self.error=error.localizedDescription}}
    }
}
