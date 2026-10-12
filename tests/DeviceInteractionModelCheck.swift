import Foundation
import AppKit

@MainActor final class DeviceTestClient: @preconcurrency DeviceInteractionClient {
    var pending=[CheckedContinuation<[String:Any],Error>]()
    var actions=[String]()
    var closed=false
    func request(_ value:[String:Any]) async throws -> [String:Any] {
        actions.append(value["action"] as? String ?? "")
        return try await withCheckedThrowingContinuation {pending.append($0)}
    }
    func close() {closed=true}
    func reply(_ value:[String:Any]) {pending.removeFirst().resume(returning:value)}
    func fail(_ message:String) {pending.removeFirst().resume(throwing:NSError(domain:"test",code:1,userInfo:[NSLocalizedDescriptionKey:message]))}
    func waitFor(_ count:Int) async {
        for _ in 0..<1000 {if actions.count>=count {return};await Task.yield()}
        fatalError("Request did not arrive")
    }
}

@MainActor final class IPhoneTestClient: @preconcurrency DeviceInteractionClient {
    var closed=false
    var devices=[[String:Any]]()
    func request(_ value:[String:Any]) async throws -> [String:Any] {return ["devices":devices]}
    func close() {closed=true}
}

@main struct DeviceInteractionModelCheck {
    @MainActor static func main() async {
        func snapshot(_ status:String="stopped",devices:[[String:Any]]=[])->[String:Any] {
            ["session":["status":status,"serial":"TEST-DEVICE"],"devices":devices]
        }
        let client=DeviceTestClient(),model=DeviceInteractionModel(client:client)
        let poll=Task {await model.refresh()}
        await client.waitFor(1)
        precondition(!model.busy,"Background poll must leave controls available")
        let start=Task {await model.send(["action":"start"])}
        await client.waitFor(2)
        precondition(model.busy && client.actions==["status","start"],"Action must not be dropped during polling")
        client.reply(snapshot("failed"))
        await poll.value
        precondition(model.status=="stopped","Late poll must not overwrite an action in progress")
        client.reply(snapshot("running"))
        await start.value
        precondition(model.active && !model.busy)
        print("passed: polling-action race")

        let action=Task {await model.send(["action":"key"])}
        await client.waitFor(3);client.fail("Navigation failed");await action.value
        let healthyPoll=Task {await model.refresh()}
        await client.waitFor(4);client.reply(snapshot("running"));await healthyPoll.value
        precondition(model.error.contains("Navigation failed"),"Poll must not erase an action failure")
        let retry=Task {await model.send(["action":"stop"])}
        await client.waitFor(5);client.reply(snapshot());await retry.value
        precondition(model.error.isEmpty)
        print("passed: persistent action errors and retry")

        model.selected="DISCONNECTED"
        let disconnectedPoll=Task {await model.refresh()}
        await client.waitFor(6);client.reply(snapshot());await disconnectedPoll.value
        precondition(model.selected.isEmpty,"Disconnected inactive selection must be cleared")
        print("passed: disconnected selection")

        let closingPoll=Task {await model.refresh()}
        await client.waitFor(7);model.close();client.reply(snapshot("running"));await closingPoll.value
        precondition(client.closed && !model.active,"Response after close must be ignored")
        print("passed: closed panel ignores late responses")

        _ = NSApplication.shared
        let iosClient=IPhoneTestClient(),iosConnection=IPhoneConnectionModel(client:iosClient)
        let preview=IPhonePreviewWindow(connection:iosConnection,screen:IPhoneScreenModel())
        preview.panelOpened();preview.open()
        precondition(preview.isOpen)
        preview.panelClosed()
        for _ in 0..<10 {await Task.yield()}
        precondition(preview.isOpen && !iosClient.closed,"Closing setup must preserve the separate preview and connection")
        preview.close()
        for _ in 0..<100 {if iosClient.closed {break};await Task.yield()}
        precondition(!preview.isOpen && iosClient.closed && !preview.screen.active,"Closing preview must stop and close its worker")
        print("passed: detached preview owns connection lifetime")

        let panelClient=IPhoneTestClient()
        let panelPreview=IPhonePreviewWindow(connection:IPhoneConnectionModel(client:panelClient),screen:IPhoneScreenModel())
        panelPreview.panelOpened();panelPreview.open();panelPreview.close()
        precondition(!panelClient.closed,"Closing preview while setup is visible must keep controls usable")
        panelPreview.panelClosed()
        for _ in 0..<100 {if panelClient.closed {break};await Task.yield()}
        precondition(panelClient.closed)
        print("passed: setup remains usable after preview closes")

        let transientClient=IPhoneTestClient()
        let transientConnection=IPhoneConnectionModel(client:transientClient)
        transientConnection.selected="TEST-IPHONE"
        let transientPreview=IPhonePreviewWindow(connection:transientConnection,screen:IPhoneScreenModel())
        transientPreview.panelOpened();transientPreview.open();transientPreview.screen.active=true
        await transientPreview.pollConnection()
        precondition(transientPreview.screen.active && transientConnection.selected=="TEST-IPHONE","Transient discovery loss must preserve stream and audit identity")
        transientClient.devices=[["serial":"TEST-IPHONE"]]
        await transientPreview.pollConnection()
        transientClient.devices=[]
        await transientPreview.pollConnection();await transientPreview.pollConnection()
        precondition(transientPreview.screen.active,"Recovery must reset missing-device count")
        await transientPreview.pollConnection()
        precondition(!transientPreview.screen.active,"Persistent USB disappearance must stop preview")
        transientPreview.close();transientPreview.panelClosed()
        print("passed: transient USB discovery versus sustained disconnection")
    }
}
