import Foundation

private final class DiagnosticBuffer {
    private let lock=NSLock()
    private var bytes=Data()
    private var discarded=false
    func append(_ chunk:Data) {
        lock.lock();defer {lock.unlock()}
        let remaining=max(0,16384-bytes.count)
        bytes.append(contentsOf:chunk.prefix(remaining))
        if chunk.count>remaining {discarded=true}
    }
    func result() -> (Data,Bool) {
        lock.lock();defer {lock.unlock()};return (bytes,discarded)
    }
}

struct BackendProcessResult {
    let output:Data
    let diagnostics:Data
    let diagnosticsTruncated:Bool
    let status:Int32
    let signalled:Bool
    func decode() throws -> Any {
        let parsed=try? JSONSerialization.jsonObject(with:output)
        guard let envelope=parsed as? [String:Any] else {
            let diagnostic=String(decoding:diagnostics,as:UTF8.self)
            throw NSError(domain:"Lawliet",code:2,userInfo:[NSLocalizedDescriptionKey:"Backend returned an invalid response (exit \(status))."+(diagnostic.isEmpty ? "":"\n"+diagnostic)+(diagnosticsTruncated ? "\n[Diagnostics truncated]":"")])
        }
        if envelope["ok"] as? Bool != true {
            throw NSError(domain:"Lawliet",code:3,userInfo:[NSLocalizedDescriptionKey:envelope["error"] as? String ?? "Operation failed."])
        }
        guard status==0 && !signalled else {
            throw NSError(domain:"Lawliet",code:5,userInfo:[NSLocalizedDescriptionKey:"Backend exited unsuccessfully (\(status)); its response was not accepted as success."])
        }
        return envelope["result"] ?? NSNull()
    }
}

enum BackendProcess {
    static func run(executable:URL,arguments:[String],environment:[String:String],inputData:Data,listingTimeout:TimeInterval?=nil) throws -> BackendProcessResult {
        let process=Process(),input=Pipe(),output=Pipe(),errors=Pipe()
        process.executableURL=executable;process.arguments=arguments;process.environment=environment
        process.standardInput=input;process.standardOutput=output;process.standardError=errors
        try process.run()
        // Drain stderr concurrently even after the capture limit is reached.
        // Discarding excess bytes avoids both pipe blockage and unbounded memory.
        let diagnostics=DiagnosticBuffer(),drained=DispatchGroup()
        drained.enter()
        DispatchQueue.global(qos:.utility).async {
            defer {drained.leave()}
            while true {
                let chunk=errors.fileHandleForReading.availableData
                if chunk.isEmpty {break}
                diagnostics.append(chunk)
            }
        }
        let deadline=DispatchWorkItem {if process.isRunning {process.terminate()}}
        if let timeout=listingTimeout {DispatchQueue.global().asyncAfter(deadline:.now()+timeout,execute:deadline)}
        defer {deadline.cancel()}
        do {
            try input.fileHandleForWriting.write(contentsOf:inputData)
            try input.fileHandleForWriting.close()
        } catch {
            try? input.fileHandleForWriting.close()
            if process.isRunning {process.terminate()}
            _=output.fileHandleForReading.readDataToEndOfFile();process.waitUntilExit();drained.wait()
            throw error
        }
        let data=output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit();drained.wait()
        let (captured,truncated)=diagnostics.result()
        return BackendProcessResult(output:data,diagnostics:captured,diagnosticsTruncated:truncated,status:process.terminationStatus,signalled:process.terminationReason == .uncaughtSignal)
    }
}
