import SwiftUI
import AppKit
@preconcurrency import AVFoundation
import CoreMediaIO

@MainActor final class IPhoneConnectionModel:ObservableObject {
    @Published var devices=[String]()
    @Published var selected=""
    @Published var info=[String:String]()
    @Published var error=""
    @Published var busy=false
    @Published var auditPath=""
    private var bridge:DeviceInteractionClient?
    private var informationSerial=""
    var preserveSelection=false
    init(client:DeviceInteractionClient?=nil) {bridge=client}
    func open(_ workspace:String) {
        guard bridge==nil else {return}
        do {bridge=try DeviceInteractionBridge(workspace:workspace,platform:"ios")} catch {self.error=error.localizedDescription}
    }
    func refresh(force:Bool=false) async {
        guard !busy,let bridge else {return};busy=true;defer{busy=false}
        do {
            let response=try await bridge.request(["action":"ios-status"])
            guard self.bridge != nil else {return}
            auditPath=response["audit_path"] as? String ?? ""
            devices=(response["devices"] as? [[String:Any]] ?? []).compactMap{$0["serial"] as? String}
            if !preserveSelection && !devices.contains(selected) {selected=devices.first ?? "";info=[:];informationSerial=""}
            error=""
            if !selected.isEmpty && (force || informationSerial != selected) {
                let serial=selected
                let details=try await bridge.request(["action":"ios-info","serial":serial])
                guard self.bridge != nil,selected==serial else {return}
                info=details.compactMapValues{$0 as? String};informationSerial=serial
                error=info["error"] ?? ""
            }
        } catch {if self.bridge != nil {self.error=error.localizedDescription}}
    }
    func record(_ event:String,capture:String="") async {
        guard let bridge else {return}
        do {_ = try await bridge.request(["action":"ios-audit","event":event,"serial":selected,"capture_source":capture])}
        catch {self.error="Session log: "+error.localizedDescription}
    }
    func close(){
        guard let bridge else {return};self.bridge=nil;preserveSelection=false
        let serial=selected
        Task { _ = try? await bridge.request(["action":"ios-audit","event":"screen.closed","serial":serial]);bridge.close() }
    }
}

final class USBFrameMonitor:NSObject,AVCaptureVideoDataOutputSampleBufferDelegate {
    var firstFrame:(()->Void)?
    private var seen=false
    func captureOutput(_ output:AVCaptureOutput,didOutput sampleBuffer:CMSampleBuffer,from connection:AVCaptureConnection){
        if !seen {seen=true;firstFrame?()}
    }
}

@MainActor final class IPhoneScreenModel:ObservableObject {
    let session=AVCaptureSession()
    @Published var sources=[AVCaptureDevice]()
    @Published var selectedSource=""
    @Published var status="Stopped"
    @Published var error=""
    @Published var active=false
    @Published var acknowledged=false
    private let queue=DispatchQueue(label:"com.lawliet.iphone-screen")
    private let frames=DispatchQueue(label:"com.lawliet.iphone-frames")
    private var monitor:USBFrameMonitor?
    var firstFrame: (() -> Void)?
    private var revision=0
    func authorizeSources() async {
        let allowed:Bool
        switch AVCaptureDevice.authorizationStatus(for:.video) {
        case .authorized:allowed=true
        case .notDetermined:allowed=await AVCaptureDevice.requestAccess(for:.video)
        default:allowed=false
        }
        if allowed {error="";discover()} else {error="Allow Lawliet Camera access in macOS Privacy & Security to discover USB video sources."}
    }
    func discover() {
        var property=CMIOObjectPropertyAddress(mSelector:CMIOObjectPropertySelector(kCMIOHardwarePropertyAllowScreenCaptureDevices),mScope:CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),mElement:CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain))
        var enabled:UInt32=1
        let result=CMIOObjectSetPropertyData(CMIOObjectID(kCMIOObjectSystemObject),&property,0,nil,UInt32(MemoryLayout<UInt32>.size),&enabled)
        guard result==noErr else {error="macOS could not expose USB screen sources (\(result)).";return}
        // Screen devices are exposed only after the explicit CoreMediaIO opt-in.
        // Exclude built-in/Continuity cameras; never auto-select a webcam.
        let devices=AVCaptureDevice.DiscoverySession(deviceTypes:[.externalUnknown],mediaType:.muxed,position:.unspecified).devices
        var seen=Set<String>()
        sources=devices.filter {d in
            let screen=d.modelID.lowercased().contains("ios") || d.modelID.lowercased().contains("iphone") || d.modelID.lowercased().contains("ipad") || d.localizedName.lowercased().contains("iphone") || d.localizedName.lowercased().contains("ipad")
            return screen && d.deviceType != .builtInWideAngleCamera && d.deviceType.rawValue != "AVCaptureDeviceTypeContinuityCamera" && seen.insert(d.uniqueID).inserted
        }
        if !sources.contains(where:{$0.uniqueID==selectedSource}) {selectedSource=""}
    }
    func start() async {
        guard acknowledged,!active,let device=sources.first(where:{$0.uniqueID==selectedSource}) else {return}
        revision+=1;let generation=revision;active=true;status="Waiting for macOS permission…"
        let allowed:Bool
        switch AVCaptureDevice.authorizationStatus(for:.video) {
        case .authorized:allowed=true
        case .notDetermined:allowed=await AVCaptureDevice.requestAccess(for:.video)
        default:allowed=false
        }
        guard revision==generation else {return}
        guard allowed else {active=false;status="Permission required";error="Allow Lawliet Camera access in macOS Privacy & Security to view the USB screen source.";return}
        active=true;status="Starting USB preview…";error=""
        let session=self.session,monitor=USBFrameMonitor();self.monitor=monitor
        monitor.firstFrame={ [weak self] in Task{@MainActor in guard let self,self.revision==generation else{return};self.status="Live USB screen · view only";self.firstFrame?()}}
        queue.async {
            do {
                session.beginConfiguration();defer{session.commitConfiguration()}
                session.inputs.forEach{session.removeInput($0)};session.outputs.forEach{session.removeOutput($0)}
                let input=try AVCaptureDeviceInput(device:device)
                guard session.canAddInput(input) else {throw NSError(domain:"Lawliet",code:1,userInfo:[NSLocalizedDescriptionKey:"macOS cannot use this USB screen source."])}
                session.addInput(input)
                let output=AVCaptureVideoDataOutput();output.alwaysDiscardsLateVideoFrames=true
                output.setSampleBufferDelegate(monitor,queue:self.frames)
                guard session.canAddOutput(output) else {throw NSError(domain:"Lawliet",code:2,userInfo:[NSLocalizedDescriptionKey:"macOS cannot monitor preview frames."])}
                session.addOutput(output)
            } catch {
                Task{@MainActor in guard self.revision==generation else{return};self.active=false;self.error=error.localizedDescription;self.status="Preview failed"};return
            }
            session.startRunning()
            Task{@MainActor in guard self.revision==generation else{return};if !session.isRunning {self.active=false;self.status="Preview failed";self.error="Unlock the iPhone, check its USB cable, then retry."}}
        }
    }
    func stop() {
        revision+=1;active=false;status="Stopped";monitor=nil
        let session=self.session
        queue.async {session.stopRunning();session.beginConfiguration();session.inputs.forEach{session.removeInput($0)};session.outputs.forEach{session.removeOutput($0)};session.commitConfiguration()}
    }
}

struct USBScreenPreview:NSViewRepresentable {
    let session:AVCaptureSession
    final class Surface:NSView {
        let preview=AVCaptureVideoPreviewLayer()
        override init(frame:NSRect){super.init(frame:frame);wantsLayer=true;layer=CALayer();layer?.backgroundColor=NSColor.black.cgColor;preview.videoGravity = .resizeAspect;layer?.addSublayer(preview)}
        required init?(coder:NSCoder){fatalError()}
        override func layout(){super.layout();preview.frame=bounds}
    }
    func makeNSView(context:Context)->Surface {let view=Surface();view.preview.session=session;return view}
    func updateNSView(_ view:Surface,context:Context){view.preview.session=session}
}

// Own the capture independently of the device sheet so investigators can return to a case.
@MainActor final class IPhonePreviewWindow: NSObject, ObservableObject, NSWindowDelegate {
    static let shared=IPhonePreviewWindow()
    let connection:IPhoneConnectionModel
    let screen:IPhoneScreenModel
    private var panelAttached=false
    private var previewSerial=""
    private var missingPolls=0
    override init() {connection=IPhoneConnectionModel();screen=IPhoneScreenModel();super.init()}
    init(connection:IPhoneConnectionModel,screen:IPhoneScreenModel) {self.connection=connection;self.screen=screen;super.init()}
    func panelOpened() {panelAttached=true}
    func panelClosed() {panelAttached=false;if !isOpen {screen.stop();connection.close();screen.acknowledged=false}}
    @Published private(set) var isOpen=false
    private var controller:NSWindowController?
    func open() {
        if let window=controller?.window {window.makeKeyAndOrderFront(nil);return}
        previewSerial=connection.selected;missingPolls=0;connection.preserveSelection=true
        let window=NSWindow(contentRect:NSRect(x:0,y:0,width:410,height:790),styleMask:[.titled,.closable,.miniaturizable,.resizable],backing:.buffered,defer:false)
        window.title=(connection.info["name"] ?? "iPhone")+" · USB screen"
        window.minSize=NSSize(width:300,height:430)
        window.isReleasedWhenClosed=false
        window.delegate=self
        window.contentView=NSHostingView(rootView:IPhonePreviewWindowView(owner:self,connection:connection,screen:screen))
        controller=NSWindowController(window:window);isOpen=true
        window.center();window.makeKeyAndOrderFront(nil)
    }
    func pollConnection() async {
        guard !connection.busy else {return}
        await connection.refresh()
        guard screen.active else {return}
        missingPolls=connection.devices.contains(previewSerial) ? 0 : missingPolls+1
        if missingPolls>=3 {stop()}
    }
    func stop() {
        connection.preserveSelection=false;screen.stop()
        Task {await connection.record("screen.stopped",capture:screen.selectedSource)}
    }
    func close() {controller?.window?.close()}
    func windowWillClose(_ notification:Notification) {
        connection.preserveSelection=false;screen.stop();if !panelAttached {connection.close()};screen.acknowledged=false;isOpen=false
        controller?.window?.contentView=nil;controller=nil
    }
}

struct IPhonePreviewWindowView:View {
    @ObservedObject var owner:IPhonePreviewWindow
    @ObservedObject var connection:IPhoneConnectionModel
    @ObservedObject var screen:IPhoneScreenModel
    var body:some View {
        VStack(spacing:0) {
            HStack {
                Label("View only",systemImage:"eye").font(.caption)
                Spacer()
                Button("Stop & close",action:owner.close)
            }.padding(12)
            ZStack {
                Color.black
                if screen.active {USBScreenPreview(session:screen.session)}
                else {Text("Screen disconnected or stopped").foregroundStyle(.white)}
            }.frame(maxWidth:.infinity,maxHeight:.infinity)
            VStack(alignment:.leading,spacing:4) {
                Text(screen.status).font(.caption)
                if !screen.error.isEmpty {Text(screen.error).font(.caption).foregroundStyle(.orange)}
                Text("Use the phone to interact. Preview is not recorded.").font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth:.infinity,alignment:.leading).padding(12)
        }
        .task {while !Task.isCancelled {await owner.pollConnection();try? await Task.sleep(nanoseconds:5_000_000_000)}}
        .onReceive(NotificationCenter.default.publisher(for:NSApplication.willTerminateNotification)){_ in owner.close()}
        .onReceive(NotificationCenter.default.publisher(for:AVCaptureDevice.wasDisconnectedNotification)){notice in
            if let device=notice.object as? AVCaptureDevice,device.uniqueID==screen.selectedSource {owner.stop();screen.discover()}
        }
    }
}

struct IPhoneInteractionView:View {
    let workspace:String
    @ObservedObject private var owner=IPhonePreviewWindow.shared
    @ObservedObject private var connection=IPhonePreviewWindow.shared.connection
    @ObservedObject private var screen=IPhonePreviewWindow.shared.screen
    @State private var auditShown=false
    @State private var setupExpanded=true
    @Environment(\.dismiss) private var dismiss
    private var ready:Bool {!connection.selected.isEmpty && connection.info["trust"]=="trusted" && !screen.selectedSource.isEmpty && screen.acknowledged}
    var body:some View {
        ScrollView {VStack(alignment:.leading,spacing:18) {
            HStack{Text("iPhone / iPad").font(.title2);Spacer();Button("Done"){dismiss()}.keyboardShortcut(.cancelAction)}
            GroupBox {VStack(alignment:.leading,spacing:8) {
                HStack {
                    Image(systemName:"iphone").font(.title)
                    VStack(alignment:.leading,spacing:4) {
                        Text(connection.info["name"] ?? "Connect your iPhone").font(.headline)
                        Text(connection.selected.isEmpty ? "Connect by USB, unlock, and approve Trust." : "iOS \(connection.info["version"] ?? "—") · \(connection.info["trust"] == "trusted" ? "Connected · Trusted" : "Trust required")").foregroundStyle(LawlietTheme.secondary)
                    }
                    Spacer()
                    Button("Refresh"){Task{await connection.refresh(force:true);screen.discover()}}.disabled(connection.busy || screen.active)
                }
                if !connection.error.isEmpty {Text(connection.error).foregroundStyle(.orange)}
            }.padding(6).frame(maxWidth:.infinity,alignment:.leading)}
            VStack(alignment:.leading,spacing:10) {
                Text("Phone screen").font(.headline)
                Text("Open a separate, resizable window beside your investigation.").foregroundStyle(LawlietTheme.secondary)
                HStack {
                    Button(owner.isOpen ? "Show screen window" : "Open screen window") {
                        Task {
                            if !screen.active {
                                await connection.record("screen.start_requested",capture:screen.selectedSource)
                                connection.preserveSelection=true
                                await screen.start()
                                if !screen.active {connection.preserveSelection=false}
                            }
                            if screen.active {owner.open();setupExpanded=false;dismiss()}
                        }
                    }.buttonStyle(.borderedProminent).disabled(!owner.isOpen && !ready)
                    if owner.isOpen {Button("Stop & close",action:owner.close)}
                    Spacer()
                    Text(screen.status).font(.caption).foregroundStyle(LawlietTheme.secondary)
                }
                if !screen.error.isEmpty {Text(screen.error).foregroundStyle(.orange)}
                Text("Use the phone to interact. Frames are not recorded or added to case evidence.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                if owner.isOpen {Text("You can close this panel and keep investigating. Closing the screen window stops the preview.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
            }
            Divider()
            DisclosureGroup("Screen setup & device details",isExpanded:$setupExpanded) {
                VStack(alignment:.leading,spacing:12) {
                    Picker("USB device",selection:$connection.selected){Text("Choose device").tag("");ForEach(connection.devices,id:\.self){Text($0).tag($0)}}.disabled(connection.busy || screen.active)
                    if !connection.selected.isEmpty {Text("Model: \(connection.info["model"] ?? "—")\nUSB identifier: \(connection.selected)").font(.caption).textSelection(.enabled)}
                    Picker("Screen source",selection:$screen.selectedSource){Text("Choose USB screen source").tag("");ForEach(screen.sources,id:\.uniqueID){device in Text(device.localizedName).tag(device.uniqueID)}}.disabled(screen.active)
                    HStack {
                        Button("Allow access & find screen"){Task{await screen.authorizeSources()}}.disabled(screen.active)
                        Button("Refresh sources"){screen.discover()}.disabled(screen.active)
                    }
                    if screen.sources.isEmpty {Text("Unlock the iPhone and refresh. macOS Camera permission is required for this USB video input.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                    Toggle("I acknowledge that live screen viewing may change device state",isOn:$screen.acknowledged).disabled(screen.active)
                    Text("Preview may change displayed time/battery indicators. Unlocking and interaction can affect device artifacts.").font(.caption).foregroundStyle(LawlietTheme.secondary)
                    Button("Open connection session log"){auditShown=true}.disabled(connection.auditPath.isEmpty)
                }.padding(.top,10)
            }
            DisclosureGroup("Apple iPhone Mirroring") {
                Text("Apple's separate app requires the same Apple Account, Wi-Fi/Bluetooth, and a nearby locked iPhone.").font(.caption)
                Button("Open Apple iPhone Mirroring") {if let url=NSWorkspace.shared.urlForApplication(withBundleIdentifier:"com.apple.ScreenContinuity"){NSWorkspace.shared.openApplication(at:url,configuration:NSWorkspace.OpenConfiguration())}}
            }
        }.padding(22)}.frame(width:720,height:560).font(.system(size:12))
        .task {
            owner.panelOpened();connection.open(workspace)
            screen.firstFrame={ [weak connection,weak screen] in Task {guard let connection,let screen else{return};await connection.record("screen.first_frame",capture:screen.selectedSource)}}
            if !screen.active {screen.discover()};setupExpanded = !owner.isOpen
            while !Task.isCancelled {await connection.refresh();try? await Task.sleep(nanoseconds:5_000_000_000)}
        }
        .sheet(isPresented:$auditShown){DeviceAuditLogView(path:connection.auditPath){auditShown=false}}
        .onChange(of:connection.selected){_ in if screen.active && !owner.isOpen {owner.stop()};Task{await connection.refresh(force:true)}}
        .onChange(of:owner.isOpen){open in if !open {setupExpanded=true}}
        .onDisappear{owner.panelClosed()}
        .onReceive(NotificationCenter.default.publisher(for:AVCaptureDevice.wasConnectedNotification)){_ in if !screen.active {screen.discover()}}
    }
}
