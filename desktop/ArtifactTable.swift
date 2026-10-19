import AppKit
import SwiftUI

private final class ArtifactTableScrollView: NSScrollView {
    var onLayout: ((CGFloat) -> Void)?
    override func layout() {
        super.layout()
        onLayout?(contentSize.width)
    }
}

/// A compact view of the current backend page. Column headers never sort a page
/// independently of the case-wide query; ordering stays with the query controls.
struct ArtifactTable: NSViewRepresentable {
    static let defaultColumns = ["time", "type", "summary", "parser", "source"]
    static let columnChoices: [(id: String, title: String)] = [
        ("time", "Time"), ("type", "Type / App"), ("summary", "Summary"),
        ("parser", "Parser"), ("source", "Source")
    ]

    let rows: [Artifact]
    @Binding var selection: String?
    var visibleColumns: [String] = ArtifactTable.defaultColumns

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = ArtifactTableScrollView()
        let table = NSTableView()
        table.delegate = context.coordinator
        table.dataSource = context.coordinator
        table.rowHeight = 30
        table.intercellSpacing = NSSize(width: 1, height: 0)
        table.usesAlternatingRowBackgroundColors = true
        table.allowsMultipleSelection = false
        table.allowsEmptySelection = true
        table.allowsColumnResizing = true
        table.allowsColumnReordering = true
        table.columnAutoresizingStyle = .noColumnAutoresizing
        table.selectionHighlightStyle = .regular
        table.headerView = NSTableHeaderView()
        table.setAccessibilityLabel("Forensic artifacts")
        table.setAccessibilityIdentifier("lawliet-artifact-table")
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.documentView = table
        scroll.onLayout = { [weak coordinator = context.coordinator, weak table] width in
            guard let table else { return }
            coordinator?.fitInitialColumns(table, availableWidth: width)
        }
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let table = scroll.documentView as? NSTableView else { return }
        let coordinator = context.coordinator
        coordinator.parent = self
        coordinator.updating = true
        defer { coordinator.updating = false }

        var seen = Set<String>()
        let known = Set(Self.defaultColumns)
        var requested = visibleColumns.filter { known.contains($0) && seen.insert($0).inserted }
        // An accidental empty preference must not produce an unselectable table.
        if requested.isEmpty { requested = ["summary"] }
        if requested != coordinator.requestedColumns {
            for column in table.tableColumns where !requested.contains(column.identifier.rawValue) {
                table.removeTableColumn(column)
            }
            for identifier in requested {
                if table.tableColumns.contains(where: { $0.identifier.rawValue == identifier }) { continue }
                let column = coordinator.column(identifier)
                table.addTableColumn(column)
            }
            for (target, identifier) in requested.enumerated() {
                if let current = table.tableColumns.firstIndex(where: { $0.identifier.rawValue == identifier }), current != target {
                    table.moveColumn(current, toColumn: target)
                }
            }
            coordinator.requestedColumns = requested
        }
        coordinator.fitInitialColumns(table, availableWidth: scroll.contentSize.width)

        let rendered = rows.map(RenderedRow.init)
        if rendered != coordinator.renderedRows {
            coordinator.renderedRows = rendered
            table.reloadData()
        }
        let selectedIndex = rows.firstIndex(where: { $0.id == selection })
        if let selectedIndex {
            if table.selectedRow != selectedIndex {
                table.selectRowIndexes(IndexSet(integer: selectedIndex), byExtendingSelection: false)
                table.scrollRowToVisible(selectedIndex)
            }
        } else if table.selectedRow != -1 {
            table.deselectAll(nil)
        }
    }

    fileprivate struct RenderedRow: Equatable {
        let id: String
        let values: [String: String]
        let tooltips: [String: String]

        init(_ artifact: Artifact) {
            id = artifact.id
            let categoryNames = ["apps": "Applications", "logs": "System logs", "device": "Device",
                                 "messages": "Messages", "message_events": "Message events", "contacts": "Contacts",
                                 "calls": "Calls", "media": "Media", "browser": "Browser activity",
                                 "recovery": "Recovery candidates", "agent_findings": "AI findings"]
            let category = categoryNames[artifact.category] ?? artifact.category.replacingOccurrences(of: "_", with: " ").capitalized
            let appName = ["whatsapp":"WhatsApp", "discord":"Discord", "signal":"Signal"][artifact.app] ?? artifact.app
            let kind = artifact.app.isEmpty || artifact.app == artifact.category
                ? category : artifact.category == "messages" ? appName : category + " · " + appName
            let summary = artifact.body.isEmpty || artifact.body == artifact.title
                ? artifact.title : artifact.title.isEmpty ? artifact.body : artifact.title + " — " + artifact.body
            let source = artifact.sourceRef.isEmpty ? artifact.sourceFile
                : artifact.sourceFile + " · " + artifact.sourceRef
            let rawValues = [
                "time": artifact.dateLabel.replacingOccurrences(of: #"(\.\d*?[1-9])0+(?= UTC$)"#, with: "$1", options: .regularExpression)
                    .replacingOccurrences(of: #"\.0+(?= UTC$)"#, with: "", options: .regularExpression),
                "type": kind.isEmpty ? "Uncategorized" : kind,
                "summary": summary.isEmpty ? "[Empty in source]" : summary,
                "parser": artifact.parser.isEmpty ? "Not recorded" : artifact.parser,
                "source": source.isEmpty ? "Not recorded" : source
            ]
            values = rawValues.mapValues { value in
                value.replacingOccurrences(of: "\r\n", with: " ↵ ")
                    .replacingOccurrences(of: "\n", with: " ↵ ")
                    .replacingOccurrences(of: "\r", with: " ↵ ")
                    .replacingOccurrences(of: "\t", with: "  ")
            }
            var details = rawValues
            details["time"] = artifact.timestamp.isEmpty || artifact.timestamp == "Undated"
                ? "No normalized timestamp. Inspect record details for original values and timestamp limitations."
                : artifact.dateLabel + "\nNormalized source value: " + artifact.timestamp
            details["source"] = source + "\nSHA-256: " + artifact.sourceHash
            tooltips = details
        }
    }

    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
        var parent: ArtifactTable
        var updating = false
        fileprivate var renderedRows: [RenderedRow] = []
        var requestedColumns: [String] = []
        private var cachedColumns: [String: NSTableColumn] = [:]
        private var didInitialFit = false

        init(_ parent: ArtifactTable) { self.parent = parent }

        func column(_ identifier: String) -> NSTableColumn {
            if let existing = cachedColumns[identifier] { return existing }
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(identifier))
            column.title = ArtifactTable.columnChoices.first(where: { $0.id == identifier })?.title ?? identifier
            column.headerCell.font = .systemFont(ofSize: 12, weight: .medium)
            column.minWidth = ["time": 170.0, "type": 90.0, "summary": 180.0, "parser": 95.0, "source": 140.0][identifier] ?? 90
            column.maxWidth = 2400
            column.width = ["time": 215.0, "type": 120.0, "summary": 285.0, "parser": 125.0, "source": 190.0][identifier] ?? 180
            column.resizingMask = .userResizingMask
            // No sortDescriptorPrototype: a page-local sort would misrepresent
            // the order of the full filtered result set.
            cachedColumns[identifier] = column
            return column
        }

        func fitInitialColumns(_ table: NSTableView, availableWidth: CGFloat) {
            guard !didInitialFit, availableWidth > 0, !table.tableColumns.isEmpty else { return }
            didInitialFit = true
            let columns = table.tableColumns
            let available = availableWidth - CGFloat(columns.count) * table.intercellSpacing.width
            let total = columns.reduce(CGFloat(0)) { $0 + $1.width }
            let flexible = columns.filter { ["summary", "source"].contains($0.identifier.rawValue) }
            if available > total, let target = flexible.first(where: { $0.identifier.rawValue == "summary" }) ?? flexible.first {
                target.width += available - total
            } else if available < total {
                let capacity = flexible.reduce(CGFloat(0)) { $0 + max(0, $1.width - $1.minWidth) }
                let reduction = min(total - available, capacity)
                if capacity > 0 {
                    for column in flexible {
                        column.width -= reduction * max(0, column.width - column.minWidth) / capacity
                    }
                }
            }
            // Preserve these widths after first layout. Further window resizing
            // uses horizontal scrolling and never replaces examiner adjustments.
        }

        func numberOfRows(in tableView: NSTableView) -> Int { renderedRows.count }

        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
            guard renderedRows.indices.contains(row), let tableColumn else { return nil }
            let reuseID = NSUserInterfaceItemIdentifier("artifact-table-cell")
            let cell = (tableView.makeView(withIdentifier: reuseID, owner: self) as? NSTableCellView) ?? NSTableCellView()
            if cell.textField == nil {
                cell.identifier = reuseID
                let text = NSTextField(labelWithString: "")
                text.translatesAutoresizingMaskIntoConstraints = false
                text.maximumNumberOfLines = 1
                text.usesSingleLineMode = true
                cell.addSubview(text)
                cell.textField = text
                NSLayoutConstraint.activate([
                    text.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 8),
                    text.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -8),
                    text.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
                ])
            }
            let column = tableColumn.identifier.rawValue
            let record = renderedRows[row]
            cell.textField?.font = column == "time" ? .monospacedDigitSystemFont(ofSize: 12, weight: .regular) : .systemFont(ofSize: 12)
            cell.textField?.lineBreakMode = column == "source" ? .byTruncatingMiddle : .byTruncatingTail
            cell.textField?.stringValue = record.values[column] ?? ""
            cell.textField?.setAccessibilityLabel(record.tooltips[column])
            cell.toolTip = record.tooltips[column]
            return cell
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard !updating, let table = notification.object as? NSTableView else { return }
            parent.selection = renderedRows.indices.contains(table.selectedRow) ? renderedRows[table.selectedRow].id : nil
        }
    }
}
