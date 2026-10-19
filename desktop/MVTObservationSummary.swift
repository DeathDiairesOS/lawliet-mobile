import Foundation

/// Display-only strings from retained MVT output. No severity inference or deduplication.
struct MVTObservationSummary {
    let message: String?
    let context: String
    var available: Bool { message != nil || !context.isEmpty }

    init(_ display: Any?) {
        let fields = display as? [String: Any] ?? [:]
        let truncated = Set(fields["truncated_fields"] as? [String] ?? [])
        func value(_ key: String, _ limit: Int) -> String? {
            guard let text = fields[key] as? String, !text.isEmpty else { return nil }
            return String(text.prefix(limit)) + ((text.count > limit || truncated.contains(key)) ? "…" : "")
        }
        message = value("message", 600)
        var parts: [String] = []
        if let level = value("upstream_level", 32) { parts.append("Upstream level: " + level) }
        if let module = value("module", 100) { parts.append("Module: " + module) }
        if let indicator = value("indicator_value", 256) {
            let type = value("indicator_type", 64)
            parts.append("Indicator" + (type.map { " (" + $0 + ")" } ?? "") + ": " + indicator)
        }
        context = parts.joined(separator: " · ")
    }
}
