import Foundation

enum CoverageReviewError: LocalizedError {
    case unsupported, malformed, invalidCentury
    var errorDescription:String? {
        switch self {
        case .unsupported: return "This backend does not provide the supported paginated coverage format. Refresh the application backend; no coverage conclusions were loaded."
        case .malformed: return "The coverage response was incomplete or inconsistent. No coverage conclusions were loaded."
        case .invalidCentury: return "Enter a century from 1000 to 9900 ending in 00, or leave it blank."
        }
    }
}

struct CoverageAxis: Identifiable {
    let id:String
    let label:String
    static let all = [CoverageAxis(id:"acquisition",label:"Collection"),
                      CoverageAxis(id:"decryption",label:"Decryption"),
                      CoverageAxis(id:"parsing",label:"Parsing"),
                      CoverageAxis(id:"review",label:"Review"),
                      CoverageAxis(id:"examiner-verification",label:"Examiner verification"),
                      CoverageAxis(id:"search",label:"Search")]
    static func label(_ id:String) -> String {all.first{$0.id==id}?.label ?? id}
}

struct CoverageObservation: Identifiable {
    let id:String
    let values:[String:Any]
    var axis:String {text("axis")}
    var state:String {text("state")}
    var source:String {text("source")}
    var reason:String {text("reason",fallback:"Not recorded")}
    var isLimited:Bool {["inaccessible","excluded","collection-unresolved","unsupported","parser-failed","unresolved","decryption-failed"].contains(state)}
    func text(_ key:String,fallback:String="unknown") -> String {
        guard let value=values[key] as? String,!value.isEmpty else {return fallback}
        return value
    }
    var raw:String {
        String(data:(try? JSONSerialization.data(withJSONObject:values,options:[.prettyPrinted,.sortedKeys])) ?? Data(),encoding:.utf8) ?? ""
    }
}

struct CoveragePage {
    let entries:[CoverageObservation]
    let offset:Int
    let total:Int
    let filteredTotal:Int
    let hasMore:Bool
    let nextOffset:Int?
    let axisCounts:[String:Int]
    let stateCounts:[String:Int]
    let limitations:[String]
    let filters:[String:String]
    init(_ result:[String:Any],expectedOffset:Int,expectedFilters:[String:String]) throws {
        guard result["schema_version"] as? Int == 1, result["offset"] != nil,
              result["summary"] != nil, result["filters"] != nil else {throw CoverageReviewError.unsupported}
        guard let rows=result["entries"] as? [[String:Any]],rows.count<=100,
              rows.allSatisfy({row in ["axis","state","source","reason"].allSatisfy {key in (row[key] as? String).map{!$0.isEmpty} ?? false}}),
              let offset=result["offset"] as? Int,offset==expectedOffset,
              let limit=result["limit"] as? Int,limit==100,
              let total=result["total"] as? Int,total>=0,
              let matched=result["filtered_total"] as? Int,matched>=0,matched<=total,
              let more=result["has_more"] as? Bool,
              let filters=result["filters"] as? [String:String],filters==expectedFilters,
              let summary=result["summary"] as? [String:Any],
              let axes=summary["axis_counts"] as? [String:Int],
              let states=summary["state_counts"] as? [String:Int],
              axes.values.allSatisfy({$0>=0}),states.values.allSatisfy({$0>=0}),
              axes.values.reduce(0,+)==total,states.values.reduce(0,+)==total,
              let limitations=result["limitations"] as? [String],
              result["independent_examiner_signoff"] as? Bool == false else {throw CoverageReviewError.malformed}
        let next=result["next_offset"] as? Int
        guard rows.count<=max(0,matched-offset),
              more == (offset+rows.count<matched),
              !more || (!rows.isEmpty && next==offset+rows.count) else {throw CoverageReviewError.malformed}
        self.entries=rows.enumerated().map {CoverageObservation(id:"\(offset+$0.offset)",values:$0.element)}
        self.offset=offset;self.total=total;self.filteredTotal=matched;self.hasMore=more;self.nextOffset=next
        self.axisCounts=axes;self.stateCounts=states;self.limitations=limitations;self.filters=filters
    }
    var rangeLabel:String {entries.isEmpty ? "0 shown":"\(offset+1)–\(offset+entries.count) of \(filteredTotal.formatted()) matching observations"}
    func countLabel(_ axis:String) -> String {
        axisCounts[axis].map {"\($0.formatted()) \($0==1 ? "observation":"observations")"} ?? "Count unavailable"
    }
}

enum ChatDateInterpretation {
    static func centuryFields(_ entered:String) throws -> [String:Any] {
        let value=entered.trimmingCharacters(in:.whitespacesAndNewlines)
        guard !value.isEmpty else {return [:]}
        guard value.count==4,value.allSatisfy({$0.isASCII && $0.isNumber}),
              let century=Int(value),(1000...9900).contains(century),century%100==0 else {throw CoverageReviewError.invalidCentury}
        return ["year_century":century]
    }
}
