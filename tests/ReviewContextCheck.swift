import Foundation

@main struct ReviewContextCheck {
    static func main() {
        let first=ReviewContext(["case":"A", "query":" _% ", "offset":0, "path":"/first"])
        let second=ReviewContext(["case":"A", "query":" _% ", "offset":100, "path":"/other", "until":""])
        precondition(first==second)
        precondition(first != ReviewContext(["case":"B", "query":" _% "]))
        precondition(first != ReviewContext(["case":"A", "query":"_%"]))
        precondition(first != ReviewContext(["case":"A", "phone_query":" _% "]))
        for key in ["evidence", "parser", "run", "category", "report", "app", "conversation", "since", "until", "sort_field", "sort_mode", "sort_direction"] {
            precondition(first != ReviewContext(["case":"A", "query":" _% ", key:"changed"]))
        }
        let scoped=ReviewContext(["category":"messages", "report":"SMS", "app":"sms", "conversation":"thread", "query":"word", "since":"2026-10-01"])
        precondition(scoped.restrictions)
        precondition(Set(scoped.activeFilters.map(\.id))==Set(["category","report","app","conversation","query","dates"]))
        precondition(scoped.activeFilters.last!.label.contains("Any end"))
        precondition(scoped.activeFilters.last!.label.contains("excludes undated"))
        let until=ReviewContext(["until":"2026-10-11"])
        precondition(until.activeFilters[0].label.contains("Any start"))
        precondition(ReviewContext.dateLabel("2026-10-11T09:00:00.123456Z")=="2026-10-11 09:00:00.123456 UTC")
        precondition(ReviewContext.dateLabel("2026-10-11 09:00:00")=="2026-10-11 09:00:00")
        precondition(ReviewContext.dateLabel("Undated")=="Undated")
        let ordered=ReviewContext(["sort_field":"Message Row ID","sort_mode":"number","sort_direction":"desc"])
        precondition(ordered.activeFilters==[ReviewFilter(id:"sort",label:"Order: Message Row ID · number ↓")])
        print("passed: search identity, filter disclosure, timestamp preservation")
    }
}
