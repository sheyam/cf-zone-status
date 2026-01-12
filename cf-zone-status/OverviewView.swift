import SwiftUI

struct OverviewView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if appState.isLoading {
                    ProgressView("Loading...")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    // Summary Cards
                    if appState.selectedZone != nil {
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 15) {
                            SummaryCard(
                                title: "Blocked Requests (7d)",
                                value: "\(appState.blockedRequestsCount)",
                                icon: "shield.slash.fill",
                                color: .red
                            )
                            
                            SummaryCard(
                                title: "Top Malicious Domains",
                                value: "\(appState.topBlocks.count)",
                                icon: "globe",
                                color: .orange
                            )
                            
                            SummaryCard(
                                title: "Top Malicious IPs",
                                value: "\(appState.ipHits.count)",
                                icon: "network",
                                color: .purple
                            )
                            
                            SummaryCard(
                                title: "DDoS Events (30d)",
                                value: "\(appState.ddosEvents.count)",
                                icon: "exclamationmark.triangle.fill",
                                color: .red
                            )
                        }
                        .padding()
                    } else {
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 15) {
                            SummaryCard(
                                title: "Total Zones",
                                value: "\(appState.zones.count)",
                                icon: "cloud.fill",
                                color: .blue
                            )
                            
                            SummaryCard(
                                title: "Select a Zone",
                                value: "→",
                                icon: "arrow.right.circle.fill",
                                color: .secondary
                            )
                        }
                        .padding()
                    }
                    
                    Divider()
                    
                    // Zones List
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Zones")
                            .font(.headline)
                            .padding(.horizontal)
                        
                        ForEach(appState.zones.prefix(10)) { zone in
                            ZoneRow(zone: zone)
                        }
                    }
                    .padding(.vertical)
                }
            }
        }
    }
}

struct SummaryCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(color)
                    .font(.title2)
                Spacer()
            }
            
            Text(value)
                .font(.system(size: 32, weight: .bold))
            
            Text(title)
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }
}

struct ZoneRow: View {
    let zone: Zone
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(zone.name)
                    .font(.headline)
                
                HStack(spacing: 12) {
                    StatusBadge(status: zone.status)
                    if let plan = zone.plan {
                        Text(plan.name)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            
            Spacer()
            
            Button(action: {
                if let url = URL(string: "https://dash.cloudflare.com/\(zone.id)") {
                    NSWorkspace.shared.open(url)
                }
            }) {
                Image(systemName: "arrow.up.right.square")
                    .foregroundColor(.blue)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
        .cornerRadius(6)
        .padding(.horizontal)
    }
}

struct StatusBadge: View {
    let status: String
    
    var color: Color {
        switch status.lowercased() {
        case "active":
            return .green
        default:
            return .orange
        }
    }
    
    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)
            Text(status.capitalized)
                .font(.caption)
        }
    }
}

