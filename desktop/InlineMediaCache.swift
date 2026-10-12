import Foundation
import Combine
import ImageIO
import CryptoKit

struct InlineMediaKey:Hashable {
    let workspace:String;let caseID:String;let artifactID:String;let fingerprint:String;let expectedHash:String
    var pixelSize:Int=256
    var casePath:String {URL(fileURLWithPath:workspace).appendingPathComponent(caseID).standardizedFileURL.path}
}
struct VerifiedPreviewReceipt {
    let path:String;let mime:String;let sha256:String;let bytes:Int
    init(_ values:[String:Any]) throws {
        guard let path=values["path"] as? String,let mime=values["mime"] as? String,
              let hash=values["sha256"] as? String,hash.range(of:"^[a-f0-9]{64}$",options:.regularExpression) != nil,
              let bytes=values["bytes"] as? Int,bytes>=0 else {throw InlineMediaError.invalid("Preview returned an unsupported receipt.")}
        self.path=path;self.mime=mime;sha256=hash;self.bytes=bytes
    }
}
enum InlineMediaError:LocalizedError {
    case invalid(String)
    var errorDescription:String? {if case .invalid(let message)=self {return message};return nil}
}
struct InlineMediaImage {let image:CGImage;let receipt:VerifiedPreviewReceipt}
enum InlineMediaState {
    case waiting,loading,ready(InlineMediaImage),failed(String)
}

/// One audited preview request at a time; only retained/visible requests are queued.
@MainActor final class InlineMediaCache:ObservableObject {
    typealias Loader=(InlineMediaKey) async throws -> VerifiedPreviewReceipt
    @Published private(set) var states=[InlineMediaKey:InlineMediaState]()
    private let loader:Loader
    private let itemLimit:Int;private let byteLimit:Int
    private var references=[InlineMediaKey:Int](),pending=[InlineMediaKey](),lru=[InlineMediaKey]()
    private var costs=[InlineMediaKey:Int](),generation=0
    private var scope="",paused=false
    private var worker:Task<Void,Never>?
    private var idle=[CheckedContinuation<Void,Never>]()
    init(itemLimit:Int=48,byteLimit:Int=32*1024*1024,loader:@escaping Loader) {
        self.itemLimit=itemLimit;self.byteLimit=byteLimit;self.loader=loader
    }
    func setScope(_ value:String) {
        guard value != scope else {return};scope=value;generation+=1
        references=[:];pending=[];states=[:];lru=[];costs=[:]
        // A running subprocess may finish, but cannot publish into the new scope.
    }
    func attach(_ key:InlineMediaKey,priority:Bool=false) {
        references[key,default:0]+=1
        if states[key] != nil {
            if priority,let index=pending.firstIndex(of:key) {pending.remove(at:index);pending.insert(key,at:0)}
            touch(key);return
        }
        guard pending.count<128 else {states[key] = .failed("Preview queue is full. Select this image again to retry.");return}
        states[key] = .waiting
        if priority {pending.insert(key,at:0)} else {pending.append(key)}
        drain()
    }
    func detach(_ key:InlineMediaKey) {
        references[key]=max(0,references[key,default:0]-1)
        if references[key]==0,let index=pending.firstIndex(of:key) {pending.remove(at:index);states.removeValue(forKey:key)}
        if references[key]==0 {references.removeValue(forKey:key)}
        trim()
    }
    func pause(_ value:Bool) {paused=value;if !value {drain()}}
    func waitUntilIdle() async {
        guard worker != nil else {return}
        await withCheckedContinuation {idle.append($0)}
    }
    func retry(_ key:InlineMediaKey) {
        guard case .failed? = states[key],references[key,default:0]>0 else {return}
        states[key] = .waiting;pending.insert(key,at:0);drain()
    }
    private func touch(_ key:InlineMediaKey) {lru.removeAll{$0==key};lru.append(key)}
    private func trim() {
        while costs.count>itemLimit || costs.values.reduce(0,+)>byteLimit {
            guard let key=lru.first(where:{references[$0,default:0]==0 && costs[$0] != nil}) else {break}
            states.removeValue(forKey:key);costs.removeValue(forKey:key);lru.removeAll{$0==key}
        }
        // Failed entries are also bounded; never evict a visible item.
        if states.count>128 {for key in lru where states.count>128 && references[key,default:0]==0 {states.removeValue(forKey:key);costs.removeValue(forKey:key)}}
    }
    private func drain() {
        guard worker==nil,!paused,!pending.isEmpty else {return}
        worker=Task {
            while !paused,!pending.isEmpty {
                let key=pending.removeFirst(),version=generation
                guard references[key,default:0]>0 else {states.removeValue(forKey:key);continue}
                states[key] = .loading
                do {
                    try await Task.detached(priority:.utility) {try Self.validatePreviewDirectory(key)}.value
                    let receipt=try await loader(key)
                    guard version==generation,references[key,default:0]>0 else {if version==generation {states.removeValue(forKey:key)};continue}
                    let image=try await Task.detached(priority:.utility) {try Self.decode(receipt,key:key)}.value
                    guard version==generation else {continue}
                    states[key] = .ready(InlineMediaImage(image:image,receipt:receipt))
                    costs[key]=image.bytesPerRow*image.height;touch(key);trim()
                } catch {
                    guard version==generation else {continue}
                    states[key] = .failed(error.localizedDescription);touch(key);trim()
                }
            }
            worker=nil
            let waiting=idle;idle=[];for continuation in waiting {continuation.resume()}
        }
    }
    nonisolated static func validatePreviewDirectory(_ key:InlineMediaKey) throws {
        let directory=URL(fileURLWithPath:key.casePath).appendingPathComponent("previews").standardizedFileURL
        guard directory.resolvingSymlinksInPath().path==directory.path else {throw InlineMediaError.invalid("Preview directory is a symlink. Automatic preview was not started.")}
        if FileManager.default.fileExists(atPath:directory.path) {
            let files=try FileManager.default.contentsOfDirectory(at:directory,includingPropertiesForKeys:[.isSymbolicLinkKey])
            guard files.count<=10000,try files.allSatisfy({try $0.resourceValues(forKeys:[.isSymbolicLinkKey]).isSymbolicLink != true}) else {throw InlineMediaError.invalid("Preview directory contains unsafe files or exceeds automatic preview limits.")}
        }
    }
    nonisolated static func decode(_ receipt:VerifiedPreviewReceipt,key:InlineMediaKey) throws -> CGImage {
        guard receipt.mime.hasPrefix("image/"),receipt.bytes<=64*1024*1024,16...800 ~= key.pixelSize else {throw InlineMediaError.invalid("Automatic previews support images up to 64 MiB. Use Open larger preview for other media.")}
        let file=URL(fileURLWithPath:receipt.path).standardizedFileURL
        let previews=URL(fileURLWithPath:key.casePath).appendingPathComponent("previews").resolvingSymlinksInPath().path
        let attributes=try FileManager.default.attributesOfItem(atPath:file.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              file.resolvingSymlinksInPath().path==file.path,file.path.hasPrefix(previews+"/"),
              (attributes[.size] as? NSNumber)?.intValue==receipt.bytes else {throw InlineMediaError.invalid("Verified preview copy is unavailable or unsafe.")}
        // Decode a stable byte snapshot, not a mutable URL after the hash check.
        let data=try Data(contentsOf:file)
        guard data.count==receipt.bytes,SHA256.hash(data:data).map({String(format:"%02x",$0)}).joined()==receipt.sha256,
              key.expectedHash.isEmpty || key.expectedHash==receipt.sha256 else {throw InlineMediaError.invalid("Preview copy does not match its recorded SHA-256.")}
        guard let source=CGImageSourceCreateWithData(data as CFData,[kCGImageSourceShouldCache:false] as CFDictionary),
              let properties=CGImageSourceCopyPropertiesAtIndex(source,0,nil) as? [CFString:Any],
              let width=properties[kCGImagePropertyPixelWidth] as? Int,let height=properties[kCGImagePropertyPixelHeight] as? Int,
              width>0,height>0,width<=20000,height<=20000,width*height<=100_000_000 else {throw InlineMediaError.invalid("Image is unsupported or exceeds automatic preview limits (100 megapixels).")}
        guard let image=CGImageSourceCreateThumbnailAtIndex(source,0,[kCGImageSourceCreateThumbnailFromImageAlways:true,kCGImageSourceThumbnailMaxPixelSize:key.pixelSize,kCGImageSourceCreateThumbnailWithTransform:true,kCGImageSourceShouldCacheImmediately:true] as CFDictionary),
              let bitmap=CGContext(data:nil,width:image.width,height:image.height,bitsPerComponent:8,bytesPerRow:image.width*4,space:CGColorSpaceCreateDeviceRGB(),bitmapInfo:CGImageAlphaInfo.premultipliedLast.rawValue) else {throw InlineMediaError.invalid("macOS could not decode this image. Original evidence remains available.")}
        bitmap.draw(image,in:CGRect(x:0,y:0,width:image.width,height:image.height))
        guard let decoded=bitmap.makeImage() else {throw InlineMediaError.invalid("Image preview could not be rendered.")}
        return decoded
    }
}
