import Foundation

struct CaseItem: Identifiable {
    let id:String;let identifier:String;let workspace:String;let location:String;let root:String
    let name:String;let records:Int;let created:String;let available:Bool;let error:String
    let status:String;let priority:String;let client:String;let owner:String;let due:String;let openTasks:Int
    var overdue:Bool {
        guard !due.isEmpty,status != "Closed" else {return false}
        let f=DateFormatter();f.locale=Locale(identifier:"en_US_POSIX");f.calendar=Calendar(identifier:.gregorian);f.dateFormat="yyyy-MM-dd"
        return due < f.string(from:Date())
    }
    var needsAttention:Bool {!available || overdue || ["Awaiting input","Review"].contains(status)}
    init(_ r:[String:Any]) {
        identifier=r["id"] as? String ?? "";workspace=r["workspace"] as? String ?? ""
        id=r["path"] as? String ?? identifier;location=r["location"] as? String ?? identifier;root=r["root"] as? String ?? workspace
        name=r["name"] as? String ?? identifier;records=r["records"] as? Int ?? 0;created=r["created"] as? String ?? ""
        available=r["available"] as? Bool ?? true;error=r["error"] as? String ?? ""
        status=r["status"] as? String ?? "Untriaged";priority=r["priority"] as? String ?? "Normal"
        client=r["client"] as? String ?? "";owner=r["owner"] as? String ?? "";due=r["due_date"] as? String ?? "";openTasks=r["open_tasks"] as? Int ?? 0
    }
}

enum CaseCatalog {
    static func initialRoots(saved:[String]?,configured:String,creation:String,current:String)->[String] {
        roots((saved ?? [configured,current])+[creation])
    }
    static func key(workspace:String,identifier:String)->String {
        guard !identifier.isEmpty else {return ""}
        return URL(fileURLWithPath:workspace).appendingPathComponent(identifier).standardizedFileURL.path
    }
    static func roots(_ values:[String])->[String] {
        var result=[String]()
        for value in values where !value.isEmpty && value != "/Volumes/easystore" && !value.hasPrefix("/Volumes/easystore/") {
            let path=URL(fileURLWithPath:value).standardizedFileURL.path
            if result.contains(where:{path==$0 || path.hasPrefix($0+"/")}) {continue}
            result.removeAll(where:{$0.hasPrefix(path+"/")});result.append(path)
        }
        return result
    }
}

struct ReportHistoryItem:Identifiable {
    let id:String;let path:String;let entries:Int;let sources:Int;let investigation:String;let available:Bool;let error:String;let modified:Date?;let kind:String
    init(_ r:[String:Any]) {
        id=r["id"] as? String ?? "";path=r["path"] as? String ?? "";entries=r["entries"] as? Int ?? 0;sources=r["sources"] as? Int ?? 0
        investigation=r["investigation_id"] as? String ?? "";available=r["available"] as? Bool ?? false;error=r["error"] as? String ?? ""
        kind=r["kind"] as? String ?? "original"
        modified=(r["modified"] as? Double).map{Date(timeIntervalSince1970:$0)}
    }
}
