import Foundation
import CoreFoundation

enum SQLiteResultReviewError: LocalizedError {
    case invalid(String)
    var errorDescription: String? { if case let .invalid(message) = self { return message }; return nil }
}

struct SQLiteResultScope: Identifiable, Equatable {
    let workspace: String
    let caseID: String
    let runID: String
    var id: String { workspace + ":" + caseID + ":" + runID }
}

struct SQLiteResultCell: Equatable {
    let kind: String
    let value: String
    var preview: String {
        if kind == "NULL" { return "NULL" }
        if kind == "Text" && value.isEmpty { return "[Empty text]" }
        if kind == "BLOB" { return "BLOB · \(value.count / 2) bytes" }
        return String(value.prefix(512))
    }
    init(_ raw: Any) throws {
        if raw is NSNull { kind = "NULL"; value = "" }
        else if let text = raw as? String { kind = "Text"; value = text }
        else if let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite {
            if !CFNumberIsFloatType(number), number.stringValue != String(number.int64Value) {
                throw SQLiteResultReviewError.invalid("SQLite integer is outside the supported signed 64-bit range.")
            }
            let isReal = CFNumberIsFloatType(number)
            kind = isReal ? "Real" : "Integer"
            value = isReal ? String(number.doubleValue) : number.stringValue
        } else if let object = raw as? [String: Any], object.count == 1,
                  let hex = object["sqlite_blob_hex"] as? String, hex.count % 2 == 0,
                  hex.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) {
            kind = "BLOB"; value = hex
        } else if let object = raw as? [String: Any], object.count == 1,
                  let special = object["sqlite_nonfinite_float"] as? String, ["inf", "-inf", "nan"].contains(special) {
            kind = "Nonfinite real"; value = special
        } else { throw SQLiteResultReviewError.invalid("Unsupported SQLite result value. Results were not displayed.") }
    }
}

struct SQLiteResultPage {
    let columns: [String]
    let rows: [[SQLiteResultCell]]
    let offset: Int
    let hasMore: Bool
    let queryTruncated: Bool
    let state: String
    let totalRows: Int?
    let resultHash: String?
    let metadata: [String: Any]
    init(_ reply: [String: Any], expectedOffset: Int, pageSize: Int = 100, expectedRunID: String? = nil) throws {
        guard let columns = reply["columns"] as? [String], columns.count <= 256,
              let rawRows = reply["rows"] as? [[Any]], rawRows.count <= pageSize,
              let offset = Self.integer(reply["offset"]), offset == expectedOffset,
              let hasMore = Self.boolean(reply["has_more"]),
              let truncated = Self.boolean(reply["query_truncated"]),
              let state = reply["state"] as? String,
              ["parsed", "empty", "limited"].contains(state),
              !hasMore || rawRows.count == pageSize else {
            throw SQLiteResultReviewError.invalid("Invalid SQLite result page. Results were not displayed.")
        }
        if let returnedRun = reply["run_id"], let expectedRunID = expectedRunID {
            guard returnedRun as? String == expectedRunID else { throw SQLiteResultReviewError.invalid("SQLite response belongs to a different run.") }
        }
        let total = Self.integer(reply["total_rows"])
        if reply["total_rows"] != nil {
            guard let total = total, offset <= total, rawRows.count <= total - offset,
                  hasMore == (offset + rawRows.count < total) else { throw SQLiteResultReviewError.invalid("SQLite result count does not match this page.") }
        }
        let resultHash = reply["result_sha256"] as? String
        if reply["result_sha256"] != nil {
            guard let hash = resultHash, hash.count == 64, hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                throw SQLiteResultReviewError.invalid("Invalid retained result hash.")
            }
        }
        var parsed: [[SQLiteResultCell]] = []
        for row in rawRows {
            guard row.count == columns.count else { throw SQLiteResultReviewError.invalid("SQLite result columns and row values do not match.") }
            parsed.append(try row.map(SQLiteResultCell.init))
        }
        self.columns = columns; rows = parsed; self.offset = offset
        self.hasMore = hasMore; queryTruncated = truncated; self.state = state; totalRows = total; self.resultHash = resultHash; metadata = reply
    }
    static func integer(_ raw: Any?) -> Int? {
        guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              !CFNumberIsFloatType(number), number.int64Value >= 0, number.uint64Value <= UInt64(Int.max) else { return nil }
        return number.intValue
    }
    static func boolean(_ raw: Any?) -> Bool? {
        guard let number = raw as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }
    func columnTitle(_ index: Int) -> String {
        let name = columns[index].isEmpty ? "[Unnamed column]" : columns[index]
        return "\(index + 1). \(name)"
    }
    var rangeLabel: String { rows.isEmpty ? "0 rows on this page" : "Rows \(offset + 1)–\(offset + rows.count)" }
}
