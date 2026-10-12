import SwiftUI
import AppKit

/// Charcoal dark surfaces and pale lavender light surfaces with restrained accents.
/// Dynamic AppKit colors follow SwiftUI's selected appearance, including sheets.
enum LawlietTheme {
    private static func adaptive(light:UInt32,dark:UInt32)->Color {
        Color(nsColor:NSColor(name:nil) { appearance in
            let hex=appearance.bestMatch(from:[.darkAqua,.aqua]) == .darkAqua ? dark:light
            return NSColor(srgbRed:Double((hex >> 16) & 255)/255,
                           green:Double((hex >> 8) & 255)/255,
                           blue:Double(hex & 255)/255,alpha:1)
        })
    }
    static let background = adaptive(light:0xF3EFF8,dark:0x191B20)
    static let panel = adaptive(light:0xFCFAFE,dark:0x22252C)
    static let accent = adaptive(light:0x7938A7,dark:0xB89ADE)
    static let border = adaptive(light:0xDED6E9,dark:0x363A44)
    static let text = adaptive(light:0x24212B,dark:0xE9EBF0)
    static let secondary = adaptive(light:0x6B6375,dark:0xA3AAB6)
    static let selection = adaptive(light:0xE8DDF4,dark:0x353042)
    static let logo = adaptive(light:0x0B070F,dark:0xFFFFFF)
}
