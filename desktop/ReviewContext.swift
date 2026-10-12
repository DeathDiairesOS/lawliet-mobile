import Foundation

struct ReviewFilter: Identifiable, Equatable {
    let id: String
    let label: String
}

struct ReviewContext: Equatable {
    let values: [String:String]
    init(_ parameters: [String:Any]) {
        let keys = ["case", "evidence", "parser", "run", "category", "view_group", "presentation", "contact_basis", "query", "phone_query",
                    "app", "conversation", "report", "since", "until", "sort_field", "sort_mode", "sort_direction"]
        var normalized: [String:String] = [:]
        for key in keys {
            if let value = parameters[key] as? String, !value.isEmpty { normalized[key] = value }
        }
        values = normalized
    }
    var restrictions: Bool {
        ["category", "view_group", "app", "conversation", "report", "since", "until"].contains { values[$0] != nil }
    }
    var activeFilters: [ReviewFilter] {
        var result: [ReviewFilter] = []
        let labels = [("category", "Category"), ("view_group", "Evidence type"), ("query", "Text"), ("phone_query", "Phone"),
                      ("report", "Report"), ("app", "App"), ("conversation", "Conversation")]
        for (key,label) in labels {
            if let value = values[key] { result.append(ReviewFilter(id:key, label:"\(label): \(value)")) }
        }
        if values["since"] != nil || values["until"] != nil {
            result.append(ReviewFilter(id:"dates", label:"UTC: \(values["since"] ?? "Any start") → \(values["until"] ?? "Any end") · excludes undated"))
        }
        if let field=values["sort_field"] {
            let direction=values["sort_direction"]=="desc" ? "↓":"↑"
            result.append(ReviewFilter(id:"sort",label:"Order: \(field) · \(values["sort_mode"] ?? "text") \(direction)"))
        }
        return result
    }
    static func dateLabel(_ timestamp: String) -> String {
        timestamp.hasSuffix("Z") ? String(timestamp.dropLast()).replacingOccurrences(of:"T",with:" ") + " UTC" : timestamp
    }
}
