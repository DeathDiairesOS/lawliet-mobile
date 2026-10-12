import Foundation

@main struct BackendProcessCheck {
    static func main() throws {
        let mode=CommandLine.arguments[1]
        let script=#"""
import sys,json,time
mode=sys.argv[1]
if mode=='timeout':
    time.sleep(30)
elif mode=='flood':
    sys.stderr.write('x'*1048576);sys.stderr.flush()
    request=json.load(sys.stdin)
    print(json.dumps({'ok':True,'result':{'received':len(request['text']),'payload':'y'*262144}}))
elif mode=='crash':
    sys.stderr.write('Synthetic backend failure\n');sys.exit(7)
elif mode=='flood_crash':
    sys.stderr.write('Synthetic flood failure\n'+'x'*1048576);sys.stderr.flush();sys.exit(8)
elif mode=='false_success':
    print(json.dumps({'ok':True,'result':'must not accept'}));sys.exit(9)
elif mode=='structured_error':
    print(json.dumps({'ok':False,'error':'Synthetic structured error'}));sys.exit(1)
"""#
        let input=try JSONSerialization.data(withJSONObject:["text":String(repeating:"a",count:262144)])
        let reply=try BackendProcess.run(executable:URL(fileURLWithPath:CommandLine.arguments[2]),arguments:["-c",script,mode],environment:ProcessInfo.processInfo.environment,inputData:mode == "flood" ? input:Data(),listingTimeout:mode == "timeout" ? 0.2:nil)
        if mode == "flood" {
            let value=try reply.decode() as! [String:Any]
            precondition(value["received"] as? Int == 262144)
            precondition((value["payload"] as? String)?.count == 262144)
            precondition(reply.diagnostics.count == 16384 && reply.diagnosticsTruncated)
        } else if mode == "timeout" {
            precondition(reply.signalled && reply.status != 0)
        } else {
            do {_=try reply.decode();fatalError("Invalid result accepted")}
            catch {
                let message=error.localizedDescription
                if mode == "crash" {precondition(message.contains("Synthetic backend failure") && message.contains("7"))}
                if mode == "flood_crash" {
                    precondition(reply.diagnostics.count == 16384 && reply.diagnosticsTruncated)
                    precondition(message.contains("Synthetic flood failure") && message.contains("exit 8") && message.contains("[Diagnostics truncated]"))
                    precondition(message.utf8.count < 17000)
                }
                if mode == "structured_error" {precondition(message == "Synthetic structured error")}
                if mode == "false_success" {precondition(message.contains("not accepted as success"))}
            }
        }
        print("passed: "+mode)
    }
}
