import SwiftUI

struct CoverageReviewView:View {
    @ObservedObject var m:AppModel
    @State private var page:CoveragePage?
    @State private var axis=""
    @State private var state=""
    @State private var evidence=""
    @State private var selection:String?
    @State private var loading=false
    @State private var error=""
    @State private var requestID=UUID()
    @State private var showingScenarioAssessment=false
    private var filters:[String:String] {
        var result:[String:String]=[:]
        if !axis.isEmpty {result["axis"]=axis}
        if !state.isEmpty {result["state"]=state}
        if !evidence.isEmpty {result["evidence_id"]=evidence}
        return result
    }
    private let states=["requested","collected","excluded","inaccessible","collection-unresolved","decryption-succeeded","decryption-failed","parsed","parsed-empty","unsupported","parser-failed","unresolved","reviewed","verified","searched-with-no-finding"]
    private var selected:CoverageObservation? {page?.entries.first{$0.id==selection}}
    private func load(_ offset:Int=0) {
        let identifier=UUID();requestID=identifier
        let caseID=m.caseID,workspace=m.workspace,submitted=filters
        page=nil;selection=nil;error="";loading=true
        Task {
            do {
                let response=try await m.request("coverage-ledger",["case":caseID,"offset":offset,"limit":100,"filters":submitted])
                guard requestID==identifier,m.caseID==caseID,m.workspace==workspace else {return}
                guard let values=response as? [String:Any] else {throw CoverageReviewError.malformed}
                let result=try CoveragePage(values,expectedOffset:offset,expectedFilters:submitted)
                page=result;selection=result.entries.first?.id
            } catch {
                guard requestID==identifier,m.caseID==caseID,m.workspace==workspace else {return}
                self.error=error.localizedDescription
            }
            if requestID==identifier {loading=false}
        }
    }
    var body:some View {
        VStack(alignment:.leading,spacing:10) {
            HStack {
                VStack(alignment:.leading,spacing:4) {
                    Text("Coverage & review").font(.system(size:18,weight:.semibold))
                    Text(m.caseName).font(.system(size:11)).foregroundStyle(LawlietTheme.secondary)
                }
                Spacer();Button("Assess customer question…"){showingScenarioAssessment=true}.disabled(m.caseID.isEmpty || m.busy)
                Button("Refresh"){load()}.disabled(loading || m.busy)
            }
            Text("Collection, parsing and examiner decisions are independent. Counts describe recorded observations; they do not measure phone completeness.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            if let page=page {
                LazyVGrid(columns:Array(repeating:GridItem(.flexible(),alignment:.leading),count:3),alignment:.leading,spacing:8) {
                    ForEach(CoverageAxis.all) {item in
                        VStack(alignment:.leading,spacing:4) {
                            Text(item.label).font(.system(size:11,weight:.medium))
                            Text(page.countLabel(item.id)).font(.system(size:12)).monospacedDigit()
                        }.frame(maxWidth:.infinity,alignment:.leading).padding(10).background(LawlietTheme.panel).cornerRadius(5)
                    }
                }
            }
            HStack {
                Picker("Axis",selection:$axis){Text("All axes").tag("");ForEach(CoverageAxis.all){Text($0.label).tag($0.id)}}.frame(width:220)
                Picker("State",selection:$state){Text("All states").tag("");ForEach(states,id:\.self){Text($0.replacingOccurrences(of:"-",with:" ")).tag($0)}}.frame(width:240)
                Picker("Evidence",selection:$evidence){Text("All evidence").tag("");ForEach(m.evidenceItems){Text($0.label).tag($0.id)}}.frame(maxWidth:320)
                Spacer();Button("Clear"){axis="";state="";evidence=""}.disabled(filters.isEmpty)
            }.disabled(loading || m.busy)
            if loading {
                VStack(spacing:10){ProgressView();Text("Loading coverage observations…").foregroundStyle(LawlietTheme.secondary)}.frame(maxWidth:.infinity,maxHeight:.infinity)
            } else if !error.isEmpty {
                VStack(alignment:.leading,spacing:10){Label("Coverage unavailable",systemImage:"exclamationmark.triangle").font(.headline);Text(error).textSelection(.enabled);Button("Retry"){load()}}.frame(maxWidth:.infinity,maxHeight:.infinity,alignment:.topLeading)
            } else if let page=page {
                Text("\(page.total.formatted()) observations in case · \(page.filteredTotal.formatted()) match these filters").font(.caption).foregroundStyle(LawlietTheme.secondary)
                HSplitView {
                    if page.entries.isEmpty {
                        Text("No recorded observations match these filters. Missing observations do not establish that data was absent or examined.").foregroundStyle(LawlietTheme.secondary).padding(20).frame(maxWidth:.infinity,maxHeight:.infinity)
                    } else {
                        Table(page.entries,selection:$selection) {
                            TableColumn("Axis"){Text(CoverageAxis.label($0.axis)).font(.system(size:11))}.width(min:90,ideal:130)
                            TableColumn("State"){entry in Text(entry.state.replacingOccurrences(of:"-",with:" ")).foregroundStyle(entry.isLimited ? .orange:.primary).help(entry.state)}.width(min:110,ideal:150)
                            TableColumn("Source"){Text($0.source).lineLimit(2).help($0.source)}.width(min:180,ideal:280)
                            TableColumn("Category"){Text($0.text("category")).lineLimit(1)}.width(min:80,ideal:100)
                        }.frame(minWidth:510)
                    }
                    ScrollView {
                        if let entry=selected {
                            VStack(alignment:.leading,spacing:10) {
                                Text("OBSERVATION DETAILS").font(.system(size:10,weight:.medium)).foregroundStyle(LawlietTheme.secondary)
                                Text(entry.state.replacingOccurrences(of:"-",with:" ")).font(.headline)
                                Text(entry.source).textSelection(.enabled)
                                Text(entry.reason).font(.system(size:12)).textSelection(.enabled)
                                Divider()
                                ForEach(["category","profile","schema","input_tier","tool_version","device_build","device_state","validation_basis","origin","actor","recorded_at","reference","evidence_id","run_id"],id:\.self) {key in
                                    VStack(alignment:.leading,spacing:3){Text(key.replacingOccurrences(of:"_",with:" ").capitalized).font(.caption).foregroundStyle(LawlietTheme.secondary);Text(entry.text(key)).font(.system(size:11)).textSelection(.enabled)}
                                }
                                if let count=entry.values["records"] as? Int {Text("\(count.formatted()) indexed rows reported for this observation").font(.caption)}
                                if entry.text("origin")=="explicit" {Text("Attributed operator assertion. Identity and independent signoff are not authenticated by this record.").font(.caption).foregroundStyle(LawlietTheme.secondary)}
                                DisclosureGroup("Original observation fields"){Text(entry.raw).font(.system(size:10,design:.monospaced)).textSelection(.enabled)}
                            }.padding(14).frame(maxWidth:.infinity,alignment:.leading)
                        } else {Text("Select an observation").foregroundStyle(LawlietTheme.secondary).padding(20)}
                    }.frame(minWidth:260,idealWidth:300,maxWidth:400)
                }
                HStack {Button("Previous"){load(max(0,page.offset-100))}.disabled(loading || page.offset==0);Spacer();Text(page.rangeLabel).font(.caption).monospacedDigit();Spacer();Button("Next"){if let next=page.nextOffset {load(next)}}.disabled(loading || !page.hasMore)}
                DisclosureGroup("Coverage limitations"){ForEach(page.limitations,id:\.self){Text($0).font(.caption).foregroundStyle(LawlietTheme.secondary).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading)}}
                Text("Recorded review and verification observations are separate from independent examiner signoff or report-release approval.").font(.caption).foregroundStyle(LawlietTheme.secondary)
            }
        }.font(.system(size:12)).controlSize(.small).padding(16)
        .task {load()}
        .onChange(of:filters){_ in load()}
        .sheet(isPresented:$showingScenarioAssessment){ScenarioAssessmentView(m:m,initialEvidence:evidence)}
    }
}
