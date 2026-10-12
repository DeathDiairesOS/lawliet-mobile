import SwiftUI

struct InvestigatorObservation:Identifiable {
    let id:String;let title:String;let body:String;let parser:String;let reference:String;let hash:String;let raw:String
    init(_ row:[String:Any]) {id=row["id"] as? String ?? "";title=row["title"] as? String ?? "";body=row["body"] as? String ?? "";parser=row["parser"] as? String ?? "";reference=row["source_ref"] as? String ?? "";hash=row["source_sha256"] as? String ?? "Unavailable";raw=String(data:(try? JSONSerialization.data(withJSONObject:row,options:[.prettyPrinted,.sortedKeys])) ?? Data(),encoding:.utf8) ?? ""}
}

struct InvestigatorSourcesView:View {
    @ObservedObject var m:AppModel
    let observations:[InvestigatorObservation]
    var body:some View {
        if !observations.isEmpty {
            DisclosureGroup("Source observations · \(observations.count)") {
                ForEach(observations){source in
                    VStack(alignment:.leading,spacing:6) {
                        Text(source.title).fontWeight(.medium)
                        Text(source.body).font(.caption).textSelection(.enabled)
                        Text(source.parser+" · "+source.reference).font(.system(size:10,design:.monospaced)).textSelection(.enabled)
                        DisclosureGroup("Recorded source SHA-256"){Text(source.hash).font(.system(size:10,design:.monospaced)).textSelection(.enabled)}
                        DisclosureGroup("Original source fields"){Text(source.raw).font(.system(size:10,design:.monospaced)).textSelection(.enabled)}
                        Button("Save finding from this source"){
                            m.findingArtifactID=source.id;m.findingTitle=source.title;m.findingNote="";m.dialog = .findingNote
                        }.disabled(m.busy)
                        Divider()
                    }.padding(.top,6)
                }
            }
        }
    }
}
