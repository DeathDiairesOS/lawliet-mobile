import Foundation

struct DeviceAuditEvent:Identifiable, Sendable {
    let id:Int
    let timestamp:String
    let event:String
    let details:String
    let raw:String
    let malformed:Bool
}
struct DeviceAuditSnapshot:Sendable {
    let events:[DeviceAuditEvent]
    let limited:Bool
    let pendingLine:Bool
    static func load(_ url:URL,maxBytes:Int=2*1024*1024,maxEvents:Int=1000)throws->Self {
        let values=try url.resourceValues(forKeys:[.isRegularFileKey,.isSymbolicLinkKey])
        guard values.isRegularFile==true,values.isSymbolicLink != true else {
            throw NSError(domain:"Lawliet",code:1,userInfo:[NSLocalizedDescriptionKey:"The audit log must be a regular file."])
        }
        let handle=try FileHandle(forReadingFrom:url);defer {try? handle.close()}
        let size=try handle.seekToEnd()
        let start=size>UInt64(maxBytes) ? size-UInt64(maxBytes):0
        try handle.seek(toOffset:start)
        var lineOffset=Int(start)
        var data=try handle.read(upToCount:maxBytes) ?? Data()
        // A bounded tail may begin midway through an event. Never present that fragment.
        if start>0 {
            try handle.seek(toOffset:start-1)
            let previous=try handle.read(upToCount:1)
            if previous?.first != 10 {
                if let newline=data.firstIndex(of:10) {lineOffset+=data.distance(from:data.startIndex,to:newline)+1;data=Data(data[data.index(after:newline)...])}
                else {data=Data()}
            }
        }
        let pending=data.last != nil && data.last != 10
        var lines=data.split(separator:10,omittingEmptySubsequences:false)
        if !lines.isEmpty {lines.removeLast()} // Empty terminator or an event still being written.
        let all=lines.compactMap { line->DeviceAuditEvent? in
            let index=lineOffset;defer {lineOffset+=line.count+1}
            guard !line.isEmpty else {return nil}
            let raw=String(decoding:line,as:UTF8.self)
            if let object=try? JSONSerialization.jsonObject(with:Data(line)) as? [String:Any],
               let at=object["at"] as? String,let event=object["event"] as? String {
                var detail=object;detail.removeValue(forKey:"at");detail.removeValue(forKey:"event")
                let pretty=(try? JSONSerialization.data(withJSONObject:detail,options:[.prettyPrinted,.sortedKeys])) ?? Data()
                return DeviceAuditEvent(id:index,timestamp:at,event:event,details:String(decoding:pretty,as:UTF8.self),raw:raw,malformed:false)
            }
            return DeviceAuditEvent(id:index,timestamp:"Unavailable",event:"Unreadable event",details:raw,raw:raw,malformed:true)
        }
        return Self(events:Array(all.suffix(maxEvents)),limited:start>0 || all.count>maxEvents,pendingLine:pending)
    }
}
