import Foundation

@main struct MVTObservationSummaryCheck {
    static func main() {
        let mode = CommandLine.arguments[1]
        if mode == "alert" {
            let summary = MVTObservationSummary(["message":"Matched supplied indicator 😀", "upstream_level":"CRITICAL", "module":"aqf_packages", "indicator_type":"app_ids", "indicator_value":"com.example.synthetic"])
            precondition(summary.message == "Matched supplied indicator 😀")
            precondition(summary.context == "Upstream level: CRITICAL · Module: aqf_packages · Indicator (app_ids): com.example.synthetic")
            precondition(summary.available)
        } else if mode == "fallback" {
            for fields: Any? in [nil, "not an object", ["message":42,"upstream_level":true,"module":[],"indicator_value":false]] {
                let summary = MVTObservationSummary(fields)
                precondition(!summary.available && summary.message == nil && summary.context.isEmpty)
            }
            let partial = MVTObservationSummary(["message":"Original message only"])
            precondition(partial.message == "Original message only" && partial.context.isEmpty)
            let unknown = MVTObservationSummary(["upstream_level":"future-original-label"])
            precondition(unknown.context == "Upstream level: future-original-label")
        } else if mode == "bounds" {
            let summary = MVTObservationSummary(["message":String(repeating:"😀",count:650), "upstream_level":String(repeating:"X",count:40), "indicator_value":String(repeating:"V",count:300)])
            precondition(summary.message == String(repeating:"😀",count:600)+"…")
            precondition(summary.context == "Upstream level: "+String(repeating:"X",count:32)+"… · Indicator: "+String(repeating:"V",count:256)+"…")
            let clipped = MVTObservationSummary(["message":"Retained prefix", "truncated_fields":["message"]])
            precondition(clipped.message == "Retained prefix…")
        } else { fatalError("Unknown mode") }
        print("passed: " + mode)
    }
}
