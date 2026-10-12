import SwiftUI

struct RetainedFile:Identifiable {
    let id:Int;let path:String;let evidence:String;let sha256:String;let size:Int
    init(_ row:[String:Any]) {id=row["id"] as? Int ?? 0;path=row["logical_path"] as? String ?? "";evidence=row["evidence_id"] as? String ?? "";sha256=row["sha256"] as? String ?? "";size=row["size"] as? Int ?? 0}
}
struct EvidenceFilesView:View {
    @ObservedObject var m:AppModel
    @State private var hasLoaded=false
    @State private var query="";@State private var appliedQuery=""
    @State private var files:[RetainedFile]=[];@State private var selected:Int?
    @State private var offset=0;@State private var total=0;@State private var more=false
    @State private var detail=""
    @State private var byteOffset="0";@State private var byteMode="text"
    @State private var inspection:[String:Any]=[:]
    private func inspect(_ file:RetainedFile,_ start:Int) {
        m.perform("Verifying source bytes…") {
            let value=try await m.request("evidence-inspect",["case":m.caseID,"file_id":file.id,"offset":start,"length":4096])
            inspection=value as? [String:Any] ?? [:];byteOffset=String(start)
            detail=String(data:try JSONSerialization.data(withJSONObject:value,options:[.prettyPrinted,.sortedKeys]),encoding:.utf8) ?? ""
        }
    }
    private var byteText:String {
        if byteMode=="text" {return (inspection["text"] as? [String:Any])?["text"] as? String ?? ""}
        let hex=inspection["hex"] as? String ?? "";let chars=Array(hex)
        let start=inspection["offset"] as? Int ?? 0
        return stride(from:0,to:chars.count,by:32).map { i in
            let end=min(i+32,chars.count)
            let values=stride(from:i,to:end,by:2).map { String(chars[$0..<min($0+2,end)]) }.joined(separator:" ")
            return String(format:"%08X",start+i/2)+"  "+values
        }.joined(separator:"\n")
    }
    private var current:RetainedFile? {files.first{$0.id==selected}}
    private func load(_ next:Int=0) {
        m.perform("Loading retained files…") {
            hasLoaded=true
            var p=m.params();p["query"]=query;p["offset"]=next;p["limit"]=100
            let result=try await m.request("file-inventory",p) as? [String:Any] ?? [:]
            files=(result["files"] as? [[String:Any]] ?? []).map(RetainedFile.init)
            total=result["total"] as? Int ?? 0;more=result["has_more"] as? Bool ?? false
            offset=next;appliedQuery=query;selected=nil;detail=""
        }
    }
    var body:some View {
        VStack(alignment:.leading,spacing:10) {
            Text("Retained files · \(total.formatted()) matching files").font(.headline)
            Text("Files retained in the selected case or evidence source, including APKs, databases and images. Parsed report and date filters do not restrict this file inventory.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            HStack {TextField("Search file path · .apk, snapshots, downloads…",text:$query).onSubmit{load()};Button("Search files"){load()}.disabled(m.busy);if !query.isEmpty || !appliedQuery.isEmpty {Button("Clear search"){query="";load()}.disabled(m.busy)}}
            HSplitView {
                VStack {
                    List(selection:$selected) {ForEach(files) {file in
                        VStack(alignment:.leading,spacing:4) {Text(file.path).lineLimit(2);Text("\(file.size.formatted()) bytes · \(file.evidence)").font(.caption).foregroundStyle(LawlietTheme.secondary)}.tag(file.id)
                    }}.overlay {
                        if files.isEmpty && hasLoaded && !m.busy {
                            VStack(spacing:8) {
                                Text(appliedQuery.isEmpty ? "No retained files in this source":"No files match this search").font(.headline)
                                Text(appliedQuery.isEmpty ? "Choose another evidence source to inspect its files.":"Try a different file path or clear the search.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                            }.padding(24)
                        }
                    }
                    HStack {Button("Previous files"){load(max(0,offset-100))}.disabled(m.busy || offset==0 || query != appliedQuery);Spacer();Text("\(files.isEmpty ? 0:offset+1)–\(offset+files.count)");Spacer();Button("Next files"){load(offset+100)}.disabled(m.busy || !more || query != appliedQuery)}
                }.frame(minWidth:350)
                ScrollView {
                    if let file=current {
                        VStack(alignment:.leading,spacing:12) {
                            Text(file.path).font(.headline).textSelection(.enabled)
                            Text("Recorded file SHA-256").font(.caption).foregroundStyle(LawlietTheme.secondary)
                            Text(file.sha256).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
                            Text("\(file.size.formatted()) bytes · File ID \(file.id)").font(.caption)
                            HStack {
                                TextField("Byte offset (decimal)",text:$byteOffset).frame(width:160)
                                Button("Verify & inspect bytes"){inspect(file,Int(byteOffset) ?? 0)}.disabled(m.busy || Int(byteOffset)==nil || (Int(byteOffset) ?? -1)<0 || (Int(byteOffset) ?? 0)>file.size)
                            }
                            Text("Read-only windows of up to 4,096 bytes. Each inspection verifies the retained file hash.").font(.caption).foregroundStyle(.secondary)
                            Button("Verify & preview image") {m.perform("Verifying image…") {
                                let result=try await m.request("file-preview",["case":m.caseID,"file_id":file.id]) as? [String:Any] ?? [:]
                                m.previewPath=result["path"] as? String ?? "";m.previewMime=result["mime"] as? String ?? "";m.previewShown=true
                            }}.disabled(m.busy)
                            if !detail.isEmpty {
                                Text("Verified bytes · \(inspection["offset"] as? Int ?? 0)–\(inspection["end_offset_exclusive"] as? Int ?? 0) (end exclusive)").font(.caption)
                                HStack {
                                    Button("Previous bytes"){inspect(file,max(0,(inspection["offset"] as? Int ?? 0)-4096))}.disabled(m.busy || (inspection["offset"] as? Int ?? 0)==0)
                                    Button("Next bytes"){inspect(file,inspection["end_offset_exclusive"] as? Int ?? 0)}.disabled(m.busy || !(inspection["has_more"] as? Bool ?? false))
                                }
                                Picker("Byte display",selection:$byteMode){Text("Decoded text").tag("text");Text("Hex").tag("hex")}.pickerStyle(.segmented)
                                Text("Decoded text uses UTF-8; escaped bytes can indicate invalid text or a split character. Hex preserves the bytes.").font(.caption).foregroundStyle(.secondary)
                                Text(byteText).font(.system(size:11,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)
                                DisclosureGroup("Full inspection metadata"){Text(detail).font(.system(size:11,design:.monospaced)).textSelection(.enabled)}
                            }
                        }.frame(maxWidth:.infinity,alignment:.leading).padding(12)
                    } else {Text("Select a retained file").foregroundStyle(LawlietTheme.secondary).padding(24)}
                }.frame(minWidth:300)
            }
        }.padding(16).onChange(of:selected){_ in detail="";inspection=[:];byteOffset="0"}.task {if !m.busy {load()}}
        .onChange(of:m.busy){busy in if !busy && !hasLoaded {load()}}
        .onChange(of:m.sourceID){_ in hasLoaded=false;files=[];total=0;selected=nil;detail="";if !m.busy {load()}}
        .onChange(of:m.caseID){_ in hasLoaded=false;files=[];total=0;selected=nil;detail="";if !m.busy {load()}}
    }
}
