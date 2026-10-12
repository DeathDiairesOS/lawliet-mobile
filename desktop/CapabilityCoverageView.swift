import SwiftUI
import WebKit

/// Temporary bundled capability reference. Does not query case data or execute tools.
struct CapabilityCoverageView:View {
    var body:some View {
        VStack(alignment:.leading,spacing:0) {
            VStack(alignment:.leading,spacing:6) {
                Text("Coverage").font(.system(size:22,weight:.semibold)).foregroundStyle(LawlietTheme.text)
                Text("Temporary pipeline capability map · case-specific coverage remains in Coverage & review")
                    .font(.caption).foregroundStyle(LawlietTheme.secondary)
            }.padding(20)
            Divider().overlay(LawlietTheme.border)
            if Bundle.main.url(forResource:"coverage-map",withExtension:"html") != nil {
                CapabilityMapWebView().frame(maxWidth:.infinity,maxHeight:.infinity)
            } else {
                Text("The capability map was not included in this build. Rebuild Lawliet to restore it.")
                    .foregroundStyle(LawlietTheme.secondary).padding(20)
                Spacer()
            }
        }.background(LawlietTheme.background)
    }
}

private struct CapabilityMapWebView:NSViewRepresentable {
    @Environment(\.colorScheme) private var colorScheme
    private var theme:String {colorScheme == .dark ? "dark":"light"}
    func makeCoordinator()->Coordinator {Coordinator()}
    func makeNSView(context:Context)->WKWebView {
        let config=WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        config.preferences.javaScriptCanOpenWindowsAutomatically=false
        let view=WKWebView(frame:.zero,configuration:config)
        view.navigationDelegate=context.coordinator
        if let url=Bundle.main.url(forResource:"coverage-map",withExtension:"html"),
           let html=try? String(contentsOf:url,encoding:.utf8) {
            context.coordinator.theme=theme
            view.loadHTMLString(html.replacingOccurrences(of:"<html lang=\"en\">",with:"<html lang=\"en\" data-theme=\"\(theme)\">"),baseURL:nil)
        }
        return view
    }
    func updateNSView(_ view:WKWebView,context:Context) {
        guard context.coordinator.theme != theme else {return}
        context.coordinator.theme=theme
        context.coordinator.applyTheme(to:view)
    }
    final class Coordinator:NSObject,WKNavigationDelegate {
        var theme="dark"
        func applyTheme(to view:WKWebView) {
            // Value is one of two constants; preserve expanded branches and scroll.
            view.evaluateJavaScript("document.documentElement.dataset.theme='"+theme+"'")
        }
        func webView(_ webView:WKWebView,didFinish navigation:WKNavigation!) {applyTheme(to:webView)}
        func webView(_ webView:WKWebView,decidePolicyFor action:WKNavigationAction,decisionHandler:@escaping (WKNavigationActionPolicy)->Void) {
            // Only the initial inline bundled document is navigable. No browser links.
            let url=action.request.url
            decisionHandler(action.navigationType == .other && (url == nil || url?.absoluteString == "about:blank") ? .allow:.cancel)
        }
    }
}
