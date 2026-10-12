import Foundation

@main struct CoverageReviewCheck {
    static func expectFailure(_ body:() throws -> Void) {
        do {try body();fatalError("Unsupported/inconsistent input accepted")} catch {}
    }
    static func main() throws {
        let mode=CommandLine.arguments[1]
        let bytes=try Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[2]))
        let fixture=try JSONSerialization.jsonObject(with:bytes) as! [String:Any]
        if mode=="independent" {
            let page=try CoveragePage(fixture,expectedOffset:0,expectedFilters:[:])
            precondition(page.entries.count==3 && page.total==3 && !page.hasMore)
            precondition(page.axisCounts["review"]==1)
            precondition(page.countLabel("review")=="1 observation")
            precondition(page.axisCounts["examiner-verification"]==0)
            precondition(page.countLabel("examiner-verification")=="0 observations")
            precondition(page.countLabel("unknown-axis")=="Count unavailable")
            precondition(page.entries.contains{$0.state=="parser-failed" && $0.isLimited})
            precondition(page.entries.contains{$0.state=="reviewed" && $0.text("origin")=="explicit"})
            precondition(page.entries[0].text("device_state")=="unknown")
            var paginated=fixture
            paginated["entries"]=Array((fixture["entries"] as! [[String:Any]]).prefix(1))
            paginated["has_more"]=true;paginated["next_offset"]=1
            let window=try CoveragePage(paginated,expectedOffset:0,expectedFilters:[:])
            precondition(window.filteredTotal==3 && window.total==3 && window.nextOffset==1)
            precondition(window.axisCounts["review"]==1)
        } else if mode=="errors" {
            var legacy=fixture;legacy.removeValue(forKey:"offset")
            expectFailure {_ = try CoveragePage(legacy,expectedOffset:0,expectedFilters:[:])}
            var future=fixture;future["schema_version"]=2
            expectFailure {_ = try CoveragePage(future,expectedOffset:0,expectedFilters:[:])}
            expectFailure {_ = try CoveragePage(fixture,expectedOffset:100,expectedFilters:[:])}
            expectFailure {_ = try CoveragePage(fixture,expectedOffset:0,expectedFilters:["state":"verified"])}
            var tooLarge=fixture;tooLarge["entries"]=Array(repeating:(fixture["entries"] as! [[String:Any]])[0],count:101)
            expectFailure {_ = try CoveragePage(tooLarge,expectedOffset:0,expectedFilters:[:])}
            var signed=fixture;signed["independent_examiner_signoff"]=true
            expectFailure {_ = try CoveragePage(signed,expectedOffset:0,expectedFilters:[:])}
            var missing=fixture;missing["summary"]=["axis_counts":["parsing":999],"state_counts":["parsed":999]]
            expectFailure {_ = try CoveragePage(missing,expectedOffset:0,expectedFilters:[:])}
            var corrupt=fixture;corrupt["has_more"]=true;corrupt["next_offset"]=1000
            expectFailure {_ = try CoveragePage(corrupt,expectedOffset:0,expectedFilters:[:])}
            var emptyRecord=fixture;emptyRecord["entries"]=[[:],[:],[:]]
            expectFailure {_ = try CoveragePage(emptyRecord,expectedOffset:0,expectedFilters:[:])}
            var unmatched=fixture;unmatched["entries"]=[];unmatched["filtered_total"]=0;unmatched["filters"]=["state":"verified"]
            let page=try CoveragePage(unmatched,expectedOffset:0,expectedFilters:["state":"verified"])
            precondition(page.rangeLabel=="0 shown" && page.total==3)
        } else if mode=="century" {
            let blank=try ChatDateInterpretation.centuryFields("")
            let spaces=try ChatDateInterpretation.centuryFields("  ")
            let declared=try ChatDateInterpretation.centuryFields(" 2000 ")
            let earlier=try ChatDateInterpretation.centuryFields("1900")
            precondition(blank.isEmpty && spaces.isEmpty)
            precondition(declared["year_century"] as? Int == 2000)
            precondition(earlier["year_century"] as? Int == 1900)
            for invalid in ["2026","0","10000","+2000","2e3","２０００","true","99"] {
                expectFailure {_ = try ChatDateInterpretation.centuryFields(invalid)}
            }
        } else {fatalError("Unknown test mode")}
        print("passed: \(mode)")
    }
}
