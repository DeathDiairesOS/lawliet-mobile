import SwiftUI
import AppKit

struct SQLiteResultReviewView: View {
    let scope: SQLiteResultScope
    @Environment(\.dismiss) private var dismiss
    @State private var page: SQLiteResultPage?
    @State private var error = ""
    @State private var loading = false
    @State private var selection: Int?
    @State private var requestID = UUID()
    @State private var requestedOffset = 0
    private let pageSize = 100

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("SQLite query results").font(.title3).fontWeight(.semibold)
                    Text("Case \(scope.caseID) · run \(scope.runID)").font(.caption).textSelection(.enabled)
                }
                Spacer()
                if loading { ProgressView().controlSize(.small) }
                Button("Close") { requestID = UUID(); dismiss() }.keyboardShortcut(.cancelAction)
            }
            Text("Retained result rows, in query order. Opening this view does not run SQL or add forensic artifacts.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            Divider()
            if !error.isEmpty {
                Text("Results unavailable").fontWeight(.semibold)
                Text(error).textSelection(.enabled)
                Button("Retry loading results") { load(requestedOffset) }.disabled(loading)
                Spacer()
            } else if let page = page {
                if page.queryTruncated { Text("The query reached a collection limit. These retained rows are incomplete.").foregroundStyle(.orange) }
                else if page.state == "limited" { Text("This run has recorded limitations. Review its processing details before interpreting the rows.").foregroundStyle(.orange) }
                if page.rows.isEmpty { Text("The retained query returned no rows on this page.").foregroundStyle(LawlietTheme.secondary); Spacer() }
                else {
                    HSplitView {
                        SQLiteResultTable(page: page, selection: $selection).frame(minWidth: 420)
                        ScrollView {
                            VStack(alignment: .leading, spacing: 12) {
                                if let row = selection, page.rows.indices.contains(row) {
                                    Text("ROW \(page.offset + row + 1)").font(.caption).foregroundStyle(LawlietTheme.secondary)
                                    ForEach(page.columns.indices, id: \.self) { index in
                                        let cell = page.rows[row][index]
                                        Text(page.columnTitle(index)).fontWeight(.medium).textSelection(.enabled)
                                        Text(cell.kind).font(.caption).foregroundStyle(LawlietTheme.secondary)
                                        Text(cell.kind == "NULL" ? "NULL" : cell.value.isEmpty ? "[Empty value]" : String(cell.value.prefix(4096)))
                                            .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                                        if cell.value.count > 4096 { Text("Showing the first 4,096 of \(cell.value.count.formatted()) characters.").font(.caption) }
                                        if cell.kind != "NULL" { Button("Copy complete value") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(cell.value, forType: .string) }.controlSize(.mini) }
                                        Divider()
                                    }
                                } else { Text("Select a row to inspect values and SQLite types.").foregroundStyle(LawlietTheme.secondary) }
                            }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                        }.frame(minWidth: 260, idealWidth: 300, maxWidth: 420)
                    }
                }
                HStack {
                    Button("Previous") { load(max(0, page.offset - pageSize)) }.disabled(loading || page.offset == 0)
                    Spacer(); Text(page.rangeLabel + (page.totalRows.map { " of \($0.formatted()) retained" } ?? "")).font(.caption); Spacer()
                    Button("Next") { load(page.offset + pageSize) }.disabled(loading || !page.hasMore)
                }
                if let hash = page.resultHash {
                    Text("Result SHA-256 · \(hash)").font(.system(size: 10, design: .monospaced)).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)
                }
                if let scope = page.metadata["integrity_scope"] as? String {
                    Text(scope).font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled)
                }
            } else { Text("Loading retained results…").foregroundStyle(LawlietTheme.secondary); Spacer() }
        }.padding(20).frame(minWidth: 880, idealWidth: 1040, minHeight: 560, idealHeight: 680)
            .background(LawlietTheme.background).foregroundStyle(LawlietTheme.text)
            .task(id: scope.id) { load(0) }
            .onDisappear { requestID = UUID(); page = nil; selection = nil }
    }
    private func load(_ offset: Int) {
        let ticket = UUID(); requestID = ticket; requestedOffset = offset
        page = nil; selection = nil; error = ""; loading = true
        Task { @MainActor in
            do {
                let result = try await AppModel.bridge(["action": "sqlite-query-result", "workspace": scope.workspace, "case": scope.caseID, "run_id": scope.runID, "offset": offset, "limit": pageSize])
                guard ticket == requestID else { return }
                guard let reply = result as? [String: Any] else { throw SQLiteResultReviewError.invalid("Invalid result response.") }
                page = try SQLiteResultPage(reply, expectedOffset: offset, pageSize: pageSize, expectedRunID: scope.runID)
            } catch {
                guard ticket == requestID else { return }
                page = nil; selection = nil; self.error = error.localizedDescription
            }
            if ticket == requestID { loading = false }
        }
    }
}

// Ordinal column identifiers preserve duplicate SQL names and original order.
private struct SQLiteResultTable: NSViewRepresentable {
    let page: SQLiteResultPage
    @Binding var selection: Int?
    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView(); let table = NSTableView()
        table.delegate = context.coordinator; table.dataSource = context.coordinator
        table.usesAlternatingRowBackgroundColors = true; table.rowHeight = 30
        table.allowsMultipleSelection = false; table.columnAutoresizingStyle = .noColumnAutoresizing
        scroll.hasHorizontalScroller = true; scroll.hasVerticalScroller = true; scroll.documentView = table
        return scroll
    }
    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let table = scroll.documentView as? NSTableView else { return }
        let c = context.coordinator; c.parent = self; c.updating = true
        if table.tableColumns.map({ $0.title }) != page.columns.indices.map(page.columnTitle) {
            for column in table.tableColumns { table.removeTableColumn(column) }
            for index in page.columns.indices {
                let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(String(index)))
                column.title = page.columnTitle(index); column.width = 200; column.minWidth = 80; table.addTableColumn(column)
            }
        }
        table.reloadData()
        if let selected = selection, page.rows.indices.contains(selected) { table.selectRowIndexes(IndexSet(integer: selected), byExtendingSelection: false) }
        else { table.deselectAll(nil) }
        c.updating = false
    }
    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
        var parent: SQLiteResultTable; var updating = false
        init(_ parent: SQLiteResultTable) { self.parent = parent }
        func numberOfRows(in tableView: NSTableView) -> Int { parent.page.rows.count }
        func tableView(_ tableView: NSTableView, viewFor column: NSTableColumn?, row: Int) -> NSView? {
            guard let column = column, let index = Int(column.identifier.rawValue), parent.page.rows.indices.contains(row), parent.page.rows[row].indices.contains(index) else { return nil }
            let cell = parent.page.rows[row][index]
            let text = NSTextField(labelWithString: cell.preview)
            text.font = .systemFont(ofSize: 12); text.lineBreakMode = .byTruncatingTail
            text.toolTip = "\(cell.kind) · \(cell.preview)"; text.setAccessibilityLabel("\(parent.page.columnTitle(index)): \(cell.kind), \(cell.preview)")
            return text
        }
        func tableViewSelectionDidChange(_ notification: Notification) {
            guard !updating, let table = notification.object as? NSTableView else { return }
            parent.selection = table.selectedRow >= 0 ? table.selectedRow : nil
        }
    }
}
