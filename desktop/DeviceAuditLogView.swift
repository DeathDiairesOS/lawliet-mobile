import SwiftUI
import AppKit

struct DeviceAuditLogView:View {
    let path:String
    let close:()->Void
    @State private var snapshot:DeviceAuditSnapshot?
    @State private var query=""
    @State private var selected:Int?
    @State private var error=""
    @State private var loading=false
    @State private var refreshed=""
    private var events:[DeviceAuditEvent] {
        (snapshot?.events ?? []).reversed().filter {query.isEmpty || $0.raw.localizedCaseInsensitiveContains(query)}
    }
    private var current:DeviceAuditEvent? {events.first {$0.id==selected}}
    private func refresh() {
        guard !loading else {return};loading=true
        Task {
            do {
                let url=URL(fileURLWithPath:path)
                let loaded=try await Task.detached {try DeviceAuditSnapshot.load(url)}.value
                snapshot=loaded;error="";refreshed=Date().formatted(date:.omitted,time:.standard)
                if !loaded.events.contains(where:{$0.id==selected}) {selected=nil}
            } catch {self.error=error.localizedDescription}
            loading=false
        }
    }
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            HStack {
                Text("Device audit log").font(.title2)
                Spacer()
                Button("Refresh"){refresh()}.disabled(loading)
                Button("Back to device",action:close).keyboardShortcut(.cancelAction)
            }
            Text("Recorded session actions and ADB commands · timestamps in UTC. Inputs made directly in the scrcpy window are not individually recorded.").font(.caption).foregroundStyle(LawlietTheme.secondary).fixedSize(horizontal:false,vertical:true)
            HStack {
                TextField("Search events, commands or details…",text:$query)
                if !query.isEmpty {Button("Clear search"){query=""}}
                if loading {ProgressView().controlSize(.small)}
            }
            if !error.isEmpty {Text(error).foregroundStyle(.red).textSelection(.enabled)}
            if snapshot?.limited==true {Text("Showing the latest 1,000 events within a 2 MB log window. The original log contains the full record.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
            if snapshot?.pendingLine==true {Text("An event is still being written. Refresh to read it once complete.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
            HSplitView {
                List(selection:$selected) {
                    ForEach(events) {event in
                        VStack(alignment:.leading,spacing:4) {
                            Text(event.event).fontWeight(.medium)
                            Text(event.timestamp).font(.caption).foregroundStyle(LawlietTheme.secondary)
                        }.tag(event.id)
                    }
                }.overlay {
                    if events.isEmpty && !loading && error.isEmpty {
                        Text(query.isEmpty ? "No recorded events yet":"No events match this search").foregroundStyle(LawlietTheme.secondary).padding()
                    }
                }.frame(minWidth:240)
                ScrollView {
                    if let event=current {
                        VStack(alignment:.leading,spacing:10) {
                            Text(event.event).font(.headline)
                            Text(event.timestamp).font(.caption).foregroundStyle(LawlietTheme.secondary)
                            if event.malformed {Text("This complete log line could not be parsed. Its original text is shown below.").font(.caption).foregroundStyle(.orange)}
                            Text(event.details).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
                            DisclosureGroup("Original JSONL event") {Text(event.raw).font(.system(size:11,design:.monospaced)).textSelection(.enabled)}
                        }.frame(maxWidth:.infinity,alignment:.leading).padding(12)
                    } else {Text("Select an event to inspect its details").foregroundStyle(LawlietTheme.secondary).padding(20)}
                }.frame(minWidth:270)
            }
            HStack {
                Text("\(events.count) visible events · newest first\(refreshed.isEmpty ? "":" · refreshed "+refreshed)").font(.caption).foregroundStyle(LawlietTheme.secondary)
                Spacer()
                Button("Show log in Finder") {NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath:path)])}
            }
            DisclosureGroup("Log location") {Text(path).font(.system(size:11,design:.monospaced)).textSelection(.enabled)}
        }.padding(22).frame(width:720,height:740).font(.system(size:12)).controlSize(.small)
        .foregroundStyle(LawlietTheme.text).background(LawlietTheme.background)
        .task {refresh()}
    }
}
