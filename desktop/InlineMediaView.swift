import SwiftUI
import AppKit

struct InlineMediaView:View {
    @ObservedObject var cache:InlineMediaCache
    let key:InlineMediaKey
    var compact=false
    var body:some View {
        VStack(alignment:.leading,spacing:6) {
            Group {
                switch cache.states[key] {
                case .ready(let value)?:
                    Image(nsImage:NSImage(cgImage:value.image,size:.zero)).resizable().scaledToFit()
                        .accessibilityLabel("Verified image preview")
                case .failed(let error)?:
                    if compact {Image(systemName:"photo.badge.exclamationmark").foregroundStyle(LawlietTheme.secondary).help(error).accessibilityLabel("Image preview unavailable")}
                    else {VStack(alignment:.leading,spacing:8){Label("Preview unavailable",systemImage:"photo.badge.exclamationmark");Text(error).font(.caption).textSelection(.enabled);Button("Retry preview"){cache.retry(key)}}}
                default:ProgressView(compact ? "":"Verifying image…").controlSize(.small)
                }
            }.frame(maxWidth:.infinity,minHeight:compact ? 54:100,maxHeight:compact ? 64:300)
            if !compact,case .ready?=cache.states[key] {Text("Verified image · first frame · fit to pane").font(.caption2).foregroundStyle(LawlietTheme.secondary)}
        }.frame(width:compact ? 92:nil).padding(compact ? 2:8).background(LawlietTheme.panel).cornerRadius(5)
        .onAppear{cache.attach(key,priority:!compact)}.onDisappear{cache.detach(key)}
    }
}
