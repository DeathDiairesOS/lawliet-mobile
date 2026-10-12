import SwiftUI
import AppKit

/// One persistent, serial stdio channel owns the Python service and scrcpy.
protocol DeviceInteractionClient: AnyObject {
    func request(_ value:[String:Any]) async throws -> [String:Any]
    func close()
}

final class DeviceInteractionBridge: DeviceInteractionClient, @unchecked Sendable {
    private let queue = DispatchQueue(label:"com.lawliet.device-interaction")
    private var process:Process?
    private var input:FileHandle?
    private var output:FileHandle?
    private var closed=false
    init(workspace:String,platform:String="android") throws {
        guard let python=Bundle.main.object(forInfoDictionaryKey:"LawlietPython") as? String,
              let resources=Bundle.main.resourceURL else {throw NSError(domain:"Lawliet",code:1,userInfo:[NSLocalizedDescriptionKey:"Application configuration is missing."])}
        let p=Process(),i=Pipe(),o=Pipe()
        p.executableURL=URL(fileURLWithPath:python)
        p.arguments=["-m","lawliet_mobile.device_worker",workspace,platform]
        var env=ProcessInfo.processInfo.environment
        env["PYTHONPATH"]=resources.path;env["PYTHONDONTWRITEBYTECODE"]="1"
        p.environment=env;p.standardInput=i;p.standardOutput=o;p.standardError=FileHandle.nullDevice
        try p.run();process=p;input=i.fileHandleForWriting;output=o.fileHandleForReading
    }
    func request(_ value:[String:Any]) async throws -> [String:Any] {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    guard !self.closed,let p=self.process,p.isRunning,let input=self.input,let output=self.output else {throw self.failure("Device service has closed. Reopen the panel.")}
                    var data=try JSONSerialization.data(withJSONObject:value);data.append(10)
                    try input.write(contentsOf:data)
                    // Every request has a deadline. Closing the child also unblocks EOF.
                    let deadline=DispatchWorkItem {if p.isRunning {p.terminate()}}
                    DispatchQueue.global().asyncAfter(deadline:.now()+45,execute:deadline)
                    defer {deadline.cancel()}
                    var reply=Data()
                    while reply.count<131072 {
                        guard let byte=try output.read(upToCount:1),!byte.isEmpty else {throw self.failure("Device service stopped or timed out.")}
                        if byte[0]==10 {break};reply.append(byte)
                    }
                    guard reply.count<131072,let object=try JSONSerialization.jsonObject(with:reply) as? [String:Any] else {throw self.failure("Invalid device service response.")}
                    guard object["ok"] as? Bool==true else {throw self.failure(object["error"] as? String ?? "Device operation failed.")}
                    continuation.resume(returning:object["result"] as? [String:Any] ?? [:])
                } catch {continuation.resume(throwing:error)}
            }
        }
    }
    private func failure(_ message:String)->NSError {NSError(domain:"Lawliet",code:1,userInfo:[NSLocalizedDescriptionKey:message])}
    func close() {
        queue.async {
            guard !self.closed else {return};self.closed=true
            try? self.input?.close() // EOF makes worker stop scrcpy and write audit.
            if let p=self.process {
                DispatchQueue.global().asyncAfter(deadline:.now()+10) {if p.isRunning {p.terminate()}}
            }
        }
    }
    deinit {try? input?.close()}
}

struct InteractionDevice:Identifiable, Equatable {
    let id:String;let manufacturer:String;let model:String;let version:String;let status:String;let authorization:String
    init(_ d:[String:Any]) {id=d["serial"] as? String ?? "";manufacturer=d["manufacturer"] as? String ?? "";model=d["model"] as? String ?? "";version=d["android_version"] as? String ?? "";status=d["status"] as? String ?? "";authorization=d["authorization"] as? String ?? ""}
}

@MainActor final class DeviceInteractionModel:ObservableObject {
    @Published var devices=[InteractionDevice]()
    @Published var selected=""
    @Published var status="stopped"
    @Published var started=""
    @Published var sessionSerial=""
    @Published var control=false
    @Published var rotation=0
    @Published var acknowledged=false
    @Published var busy=false
    @Published var error=""
    @Published var dependencyInfo="Checking ADB and scrcpy…"
    @Published var auditPath=""
    private var bridge:DeviceInteractionClient?
    private var polling=false
    private var revision=0
    private var actionError=""
    private var snapshotError=""
    init(client:DeviceInteractionClient?=nil) {bridge=client}
    private var timer:Timer?
    var active:Bool {status=="starting" || status=="running"}
    var ready:Bool {devices.contains {$0.id==selected && $0.status=="device"}}
    func open(workspace:String) {
        guard bridge==nil else {return}
        do {bridge=try DeviceInteractionBridge(workspace:workspace)} catch {self.error=error.localizedDescription;return}
        guard let currentBridge=bridge else {return}
        Task {
            do {
                let deps=try await currentBridge.request(["action":"dependencies"])
                dependencyInfo=["adb","scrcpy"].map {name in
                    let d=deps[name] as? [String:Any] ?? [:]
                    return name+": "+(d["available"] as? Bool==true ? (d["version"] as? String ?? "available"):(d["error"] as? String ?? "missing"))
                }.joined(separator:"\n")
            } catch {self.error=error.localizedDescription}
            await refresh()
        }
        timer=Timer.scheduledTimer(withTimeInterval:3,repeats:true) {[weak self] _ in Task {@MainActor in await self?.refresh()}}
    }
    // Polls never disable input. Explicit actions can queue behind a poll in the bridge.
    // Ignore a late poll once an action starts or the panel closes.
    func refresh() async {
        guard !busy,!polling,let bridge else {return}
        polling=true;let currentRevision=revision
        defer {polling=false}
        do {
            let response=try await bridge.request(["action":"status"])
            guard revision==currentRevision,self.bridge != nil else {return}
            apply(response)
        } catch {
            guard revision==currentRevision,self.bridge != nil else {return}
            snapshotError=error.localizedDescription;updateError()
        }
    }
    private func updateError() {
        error=[actionError,snapshotError].filter {!$0.isEmpty}.joined(separator:"\n")
    }
    private func apply(_ r:[String:Any]) {
        let updated=(r["devices"] as? [[String:Any]] ?? []).map(InteractionDevice.init)
        if devices != updated {devices=updated}
        let s=r["session"] as? [String:Any] ?? [:]
        status=s["status"] as? String ?? "stopped";started=s["started_at"] as? String ?? ""
        sessionSerial=s["serial"] as? String ?? "";control=s["control"] as? Bool ?? false;rotation=s["rotation"] as? Int ?? 0
        auditPath=r["audit_path"] as? String ?? ""
        if !active,!selected.isEmpty,!devices.contains(where:{$0.id==selected}) {selected=""}
        snapshotError=[r["error"] as? String ?? "",s["error"] as? String ?? ""].filter {!$0.isEmpty}.joined(separator:"\n")
        updateError()
    }
    func send(_ request:[String:Any]) async {
        guard !busy,let bridge else {return}
        revision+=1;let currentRevision=revision
        busy=true;actionError="";updateError();defer {busy=false}
        do {
            let response=try await bridge.request(request)
            guard revision==currentRevision,self.bridge != nil else {return}
            apply(response)
        } catch {
            guard revision==currentRevision,self.bridge != nil else {return}
            actionError=error.localizedDescription;updateError()
        }
    }
    func mirror(action:String="start",control:Bool=false,rotation:Int=0) {
        Task {await send(["action":action,"serial":active ? sessionSerial:selected,"control":control,"rotation":rotation,"acknowledge_state_changes":acknowledged])}
    }
    func stop() {Task {await send(["action":"stop"])}}
    func key(_ name:String) {Task {await send(["action":"key","key":name])}}
    func close() {revision+=1;timer?.invalidate();timer=nil;bridge?.close();bridge=nil}
}

struct AndroidInteractionView:View {
    let workspace:String
    @StateObject private var model=DeviceInteractionModel()
    @State private var auditShown=false
    @Environment(\.dismiss) private var dismiss
    var body:some View {
        VStack(spacing:0) {
        if auditShown {DeviceAuditLogView(path:model.auditPath) {auditShown=false}}
        else {ScrollView { VStack(alignment:.leading,spacing:14) {
            HStack {Text("Connected device · Android").font(.title2);Spacer();Button("Close"){model.close();dismiss()}.keyboardShortcut(.cancelAction)}
            Text("USB debugging, ADB and scrcpy may modify device state, including copying and running a temporary scrcpy server. They are not forensically non-invasive. No lock or authentication bypass is provided.").font(.caption).foregroundStyle(LawlietTheme.secondary).fixedSize(horizontal:false,vertical:true)
            Toggle("I acknowledge these device state changes",isOn:$model.acknowledged).disabled(model.active || model.busy)
            GroupBox("Device information") {
                VStack(alignment:.leading,spacing:8) {
                    Picker("USB device",selection:$model.selected) {Text("Choose device").tag("");ForEach(model.devices) {d in Text("\(d.model.isEmpty ? "Android":d.model) · \(d.id) · \(d.status)").tag(d.id)}}.disabled(model.active || model.busy)
                    if model.devices.isEmpty {
                        Text("No USB Android device found. Connect the phone with a data cable and enable USB debugging.")
                            .foregroundStyle(LawlietTheme.secondary).fixedSize(horizontal:false,vertical:true)
                    }
                    if let device=model.devices.first(where:{$0.id==model.selected}) {
                        Text("Manufacturer: \(device.manufacturer.isEmpty ? "Unavailable":device.manufacturer)\nModel: \(device.model)\nAndroid: \(device.version.isEmpty ? "Unavailable":device.version)\nSerial: \(device.id)\nConnection: \(device.status) · ADB: \(device.authorization)").font(.system(size:12,design:.monospaced)).textSelection(.enabled)
                    }
                    Text("Authorize USB debugging on the unlocked phone if prompted. Offline devices cannot start a session.").font(.caption).foregroundStyle(LawlietTheme.secondary).fixedSize(horizontal:false,vertical:true)
                }.frame(maxWidth:.infinity,alignment:.leading)
            }
            GroupBox("Screen view · managed scrcpy window") {
                VStack(alignment:.leading,spacing:8) {
                    Text("Live video opens in a separate resizable scrcpy window. It preserves aspect ratio and follows device orientation.").fixedSize(horizontal:false,vertical:true)
                    HStack {
                        Button("Start viewing"){model.mirror()}.disabled(!model.ready || !model.acknowledged || model.active || model.busy)
                        Button("Stop mirroring"){model.stop()}.disabled(!model.active || model.busy)
                        Button(model.control ? "Disable device control":"Enable device control") {model.mirror(action:"control",control:!model.control,rotation:model.rotation)}.disabled(!model.active || !model.acknowledged || model.busy)
                    }
                    Text(!model.active ? "NO ACTIVE SESSION · Start viewing to open the phone screen.":model.control ? "CONTROL ENABLED · Use mouse taps, drags, scrolling and keyboard in scrcpy.":"VIEW ONLY · Device input disabled. Enabling control restarts scrcpy.").font(.caption).fontWeight(.medium)
                    Text("Individual inputs in the scrcpy window are not available to Lawliet's audit logger. Navigation buttons, mode changes and ADB commands are logged. File drops and APK installs are blocked.").font(.caption).foregroundStyle(LawlietTheme.secondary).fixedSize(horizontal:false,vertical:true)
                }.frame(maxWidth:.infinity,alignment:.leading)
            }
            HStack {
                Button("Back"){model.key("back")}.disabled(!model.active || !model.control || model.busy)
                Button("Home"){model.key("home")}.disabled(!model.active || !model.control || model.busy)
                Button("Recent apps"){model.key("recent")}.disabled(!model.active || !model.control || model.busy)
                Button("Rotate display"){model.mirror(action:"rotate",control:model.control,rotation:(model.rotation+90)%360)}.disabled(!model.active || model.busy)
                Button("Disconnect session"){model.stop()}.disabled(!model.active || model.busy)
            }
            GroupBox("Session information") {
                VStack(alignment:.leading,spacing:6) {
                    Text("Status: \(model.status) · Device: \(model.sessionSerial.isEmpty ? "None":model.sessionSerial)")
                    Text("Started (UTC): \(model.started.isEmpty ? "—":model.started)")
                    Button("Open audit log"){auditShown=true}.disabled(model.auditPath.isEmpty)
                    Text("Discovery polls every 3 seconds while this panel is open. Closing it stops the session. Disconnect session stops mirroring; unplug USB to disconnect the device.").font(.caption).foregroundStyle(LawlietTheme.secondary).fixedSize(horizontal:false,vertical:true)
                }.frame(maxWidth:.infinity,alignment:.leading)
            }
            DisclosureGroup("Dependencies & installation") {
                Text(model.dependencyInfo).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
                Text("macOS: brew install scrcpy; brew install --cask android-platform-tools. Configure executable paths with Lawliet tools configure if the app's PATH cannot find them. See docs/ANDROID-MIRRORING.md.").font(.caption).textSelection(.enabled)
            }
            if !model.error.isEmpty {ScrollView {Text(model.error).font(.caption).foregroundStyle(.red).textSelection(.enabled)}.frame(maxHeight:90)}
        }.padding(22) }.frame(width:720,height:740).font(.system(size:12)).controlSize(.small)}
        }
        .task {model.open(workspace:workspace)}
        .onDisappear {model.close()}
        .onReceive(NotificationCenter.default.publisher(for:NSApplication.willTerminateNotification)) {_ in model.close()}
    }
}


struct DeviceInteractionView:View {
    let workspace:String
    @State private var platform="ios"
    var body:some View {
        VStack(spacing:0) {
            Picker("Device platform",selection:$platform){Text("iPhone / iPad").tag("ios");Text("Android").tag("android")}.pickerStyle(.segmented).padding(.horizontal,22).padding(.top,16)
            if platform=="ios" {IPhoneInteractionView(workspace:workspace)} else {AndroidInteractionView(workspace:workspace)}
        }
    }
}
