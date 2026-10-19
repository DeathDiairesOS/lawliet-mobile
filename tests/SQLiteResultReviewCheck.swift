import Foundation

@main struct SQLiteResultReviewCheck {
    static func main() throws {
        let mode = CommandLine.arguments[1]
        var response: [String: Any] = ["columns": ["same", "same", "null", "empty", "blob", "special"],
            "rows": [[Int64.max, "café 東京", NSNull(), "", ["sqlite_blob_hex": "00ff"], ["sqlite_nonfinite_float": "nan"]]],
            "offset": 0, "has_more": false, "query_truncated": false, "state": "parsed", "run_id": "123456789abc", "total_rows": 1, "result_sha256": String(repeating: "a", count: 64)]
        switch mode {
        case "typed":
            let data = try JSONSerialization.data(withJSONObject: response)
            let decoded = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            let page = try SQLiteResultPage(decoded, expectedOffset: 0, expectedRunID: "123456789abc")
            precondition(page.rows[0][0].value == "9223372036854775807" && page.rows[0][0].kind == "Integer")
            precondition(page.rows[0][1].value == "café 東京")
            precondition(page.columnTitle(0) == "1. same" && page.columnTitle(1) == "2. same")
            precondition(page.rows[0][2].kind == "NULL" && page.rows[0][3].kind == "Text" && page.rows[0][3].value.isEmpty)
            precondition(page.rows[0][4].kind == "BLOB" && page.rows[0][4].value == "00ff")
            precondition(page.rows[0][5].kind == "Nonfinite real" && page.rows[0][5].value == "nan")
        case "page":
            response["columns"] = ["x"]; response["rows"] = [[42]]; response["offset"] = 100; response["total_rows"] = 101
            let page = try SQLiteResultPage(response, expectedOffset: 100)
            precondition(page.rangeLabel == "Rows 101–101" && !page.hasMore)
        case "empty":
            response["rows"] = []; response["total_rows"] = 0; response["state"] = "empty"
            let page = try SQLiteResultPage(response, expectedOffset: 0)
            precondition(page.rows.isEmpty && page.rangeLabel == "0 rows on this page")
        case "limited":
            response["state"] = "limited"; response["query_truncated"] = true
            let page = try SQLiteResultPage(response, expectedOffset: 0)
            precondition(page.queryTruncated)
        case "blob-empty":
            let cell = try SQLiteResultCell(["sqlite_blob_hex": ""])
            precondition(cell.preview == "BLOB · 0 bytes" && cell.kind == "BLOB")
        case "real-boundaries":
            let values = [1.0000000000000002, Double.greatestFiniteMagnitude, -Double.greatestFiniteMagnitude, Double.leastNonzeroMagnitude, -0.0]
            for number in values {
                // Match Python's numeric JSON input. Foundation's writer itself
                // serializes -0.0 as 0, which would erase the sign before review.
                let encoded = Data("[\(String(number))]".utf8)
                let decoded = try JSONSerialization.jsonObject(with: encoded) as! [Any]
                let cell = try SQLiteResultCell(decoded[0])
                precondition(cell.kind == "Real" && Double(cell.value)!.bitPattern == number.bitPattern, "Lost REAL precision: \(number) -> \(cell.value)")
            }
        default:
            if mode == "wrong-run" { response["run_id"] = "different" }
            if mode == "wrong-offset" { response["offset"] = 100 }
            if mode == "row-width" { response["rows"] = [[42]] }
            if mode == "boolean-cell" { response["rows"] = [[true, "", NSNull(), "", ["sqlite_blob_hex": "00"], ["sqlite_nonfinite_float": "inf"]]] }
            if mode == "boolean-count" { response["offset"] = false }
            if mode == "numeric-flag" { response["has_more"] = 0 }
            if mode == "wrong-total" { response["total_rows"] = 2 }
            if mode == "wrong-hash" { response["result_sha256"] = "unchecked" }
            if mode == "invalid-blob" { response["rows"] = [[0, "", NSNull(), "", ["sqlite_blob_hex": "xx"], ["sqlite_nonfinite_float": "inf"]]] }
            if mode == "wrong-state" { response["state"] = "corrupt" }
            do { _ = try SQLiteResultPage(response, expectedOffset: 0, expectedRunID: "123456789abc"); fatalError("Expected refusal: \(mode)") }
            catch is SQLiteResultReviewError { }
        }
        print("passed: \(mode)")
    }
}
