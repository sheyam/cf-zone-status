import SwiftUI

struct IPHitsView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        VStack(spacing: 0) {
            if appState.isLoading {
                ProgressView("Loading IP hits...")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if appState.ipHits.isEmpty {
                EmptyStateView(
                    icon: "network",
                    title: "No IP Hits",
                    message: appState.selectedZone != nil
                        ? "No IP hit data for \(appState.selectedZone!.name)"
                        : "Select a zone to view IP hit data"
                )
            } else {
                List {
                    ForEach(appState.ipHits) { hit in
                        IPHitRow(hit: hit)
                    }
                }
                .listStyle(.plain)
            }
        }
    }
}

struct IPHitRow: View {
    let hit: IPHit
    
    var blockedPercentage: Double {
        guard hit.requestCount > 0 else { return 0 }
        return Double(hit.blockedCount) / Double(hit.requestCount) * 100
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(hit.ipAddress)
                        .font(.system(.headline, design: .monospaced))
                    
                    Text(hit.zoneName)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                VStack(alignment: .trailing, spacing: 4) {
                    Text("\(hit.requestCount)")
                        .font(.title3)
                        .fontWeight(.bold)
                    
                    Text("requests")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            HStack {
                if hit.blockedCount > 0 {
                    HStack(spacing: 4) {
                        Image(systemName: "shield.fill")
                            .foregroundColor(.red)
                            .font(.caption)
                        Text("\(hit.blockedCount) blocked")
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                }
                
                if let country = hit.country {
                    Label(country, systemImage: "location.fill")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                if blockedPercentage > 0 {
                    Text(String(format: "%.1f%% blocked", blockedPercentage))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

