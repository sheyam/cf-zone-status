import SwiftUI

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTab = 0
    
    var body: some View {
        VStack(spacing: 0) {
            if !appState.isAuthenticated {
                NotAuthenticatedView()
            } else {
                // Zone Selector
                HStack {
                    Text("Zone:")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    
                    Picker("Select Zone", selection: $appState.selectedZone) {
                        Text("All Zones")
                            .tag(nil as Zone?)
                        ForEach(appState.zones) { zone in
                            Text(zone.name)
                                .tag(zone as Zone?)
                        }
                    }
                    .pickerStyle(.menu)
                    .frame(width: 200)
                    
                    Spacer()
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
                
                Divider()
                
                TabView(selection: $selectedTab) {
                    OverviewView()
                        .tabItem {
                            Label("Overview", systemImage: "chart.bar.fill")
                        }
                        .tag(0)
                    
                    TopBlocksView()
                        .tabItem {
                            Label("Top Blocks", systemImage: "shield.fill")
                        }
                        .tag(1)
                    
                    IPHitsView()
                        .tabItem {
                            Label("IP Hits", systemImage: "network")
                        }
                        .tag(2)
                    
                    DDOSView()
                        .tabItem {
                            Label("DDoS", systemImage: "exclamationmark.triangle.fill")
                        }
                        .tag(3)
                }
                .frame(width: 700, height: 500)
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: {
                    appState.refresh()
                }) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(appState.isLoading)
            }
        }
        .sheet(isPresented: $appState.showSettings) {
            SettingsView()
                .environmentObject(appState)
        }
    }
}


