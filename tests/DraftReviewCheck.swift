import Foundation

@main struct DraftReviewCheck {
    static func main()throws {
        let mode=CommandLine.arguments[1],folder=URL(fileURLWithPath:CommandLine.arguments[2])
        if mode=="valid" {
            let draft=try DraftReview.load(folder,expectedCase:"A")
            precondition(draft.entries.count==3 && draft.citations.count==1)
            precondition(Set(draft.entries.map{$0.kind})==["observation","interpretation","question"])
            precondition(draft.citations[0].source("record_table_key_or_offset")=="line=1")
            precondition(draft.citations[0].text("attachment_state")=="not_acquired")
            precondition(draft.citations[0].text("parser_run_link_state")=="unavailable")
            precondition(draft.citations[0].timestamp=="Undated / timezone unknown")
            precondition(draft.report.contains("UTC unknown"))
            precondition(!draft.report.contains("EXCLUDED_CANARY"))
        } else if mode=="examination-no-matches" || mode=="examination-inconclusive" {
            let draft=try DraftReview.load(folder,expectedCase:"A")
            precondition(draft.entries.isEmpty && draft.citations.isEmpty)
            guard let examination=draft.examination else {fatalError("Missing examination")}
            precondition(examination.outcome == (mode=="examination-no-matches" ? "no_matches":"inconclusive"))
            precondition(examination.examiner=="Synthetic examiner")
            precondition(examination.scope=="Selected supplied text index only")
            precondition(examination.limitations.contains("not a complete phone extraction"))
            if examination.outcome=="no_matches" {precondition(examination.queries.count==1 && examination.queries[0].returnedRecords==0)}
            precondition(!draft.report.contains("EXCLUDED_CANARY"))
        } else if mode=="redacted" {
            let draft=try DraftReview.load(folder,expectedCase:"A")
            precondition(draft.kind=="redacted" && draft.entries.count==1 && draft.citations.count==1)
            precondition(!draft.report.contains("PERSON_CANARY"))
            precondition(draft.citations[0].source("recorded_source_sha256").count==64)
            precondition(draft.limitations.contains(where:{$0.contains("case-sensitive")}))
        } else {
            do {
                _ = try DraftReview.load(folder,expectedCase:mode=="wrong-case" ? "B":"A")
                fatalError("Invalid report was accepted: \(mode)")
            } catch {print("rejected: \(error.localizedDescription)")}
        }
        print("passed: \(mode)")
    }
}
