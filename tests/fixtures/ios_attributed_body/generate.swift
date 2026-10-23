// Generates synthetic fixtures using Apple's encoder, independently of LAWLIET.
// Run on macOS: swift generate.swift > fixtures.json
import Foundation

let basic = "LAWLIET fixture: café 🦉\nSecond line"
let decorated = NSMutableAttributedString(string: "Visible message only")
decorated.addAttribute(NSAttributedString.Key("SyntheticAttribute"), value: "DECOY ATTRIBUTE TEXT", range: NSRange(location: 0, length: decorated.length))
let inputs: [(String, NSAttributedString)] = [
    ("immutable-unicode", NSAttributedString(string: basic)),
    ("mutable-unicode", NSMutableAttributedString(string: basic)),
    ("attribute-decoy", decorated),
    ("long", NSMutableAttributedString(string: String(repeating: "x", count: 200) + "🦉")),
    ("empty", NSAttributedString(string: "")),
    ("literal-markers", NSAttributedString(string: "NSString\0NSAttributes\n\u{fffc}")),
]
var fixtures: [[String: Any]] = []
for (name, value) in inputs {
    for (format, data) in [("typedstream", NSArchiver.archivedData(withRootObject: value)),
                           ("keyed", try NSKeyedArchiver.archivedData(withRootObject: value, requiringSecureCoding: true))] {
        fixtures.append(["id": name + "-" + format, "format": format,
                         "expected_text": value.string,
                         "hex": data.map { String(format: "%02x", $0) }.joined()])
    }
}
let output: [String: Any] = ["generator": "Apple Foundation NSArchiver and NSKeyedArchiver; generate.swift",
                           "host": ProcessInfo.processInfo.operatingSystemVersionString,
                           "synthetic": true, "fixtures": fixtures]
let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys, .prettyPrinted])
print(String(decoding: data, as: UTF8.self))
