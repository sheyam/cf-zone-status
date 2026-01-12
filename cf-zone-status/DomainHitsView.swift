import SwiftUI

struct DomainHitsView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        VStack(spacing: 0) {
            if appState.isLoading {
                ProgressView("Loading domain hits...")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if appState.domainHits.isEmpty {
                EmptyStateView(
                    icon: "globe",
                    title: "No Domain Hits",
                    message: "No domain hit data available"
                )
            } else {
                List {
                    ForEach(appState.domainHits) { hit in
                        DomainHitRow(hit: hit)
                    }
                }
                .listStyle(.plain)
            }
        }
    }
}

struct DomainHitRow: View {
    let hit: DomainHit
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(hit.domain)
                        .font(.headline)
                    
                    Text(hit.zoneName)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                VStack(alignment: .trailing, spacing: 4) {
                    if hit.requestCount > 0 {
                        Text("\(hit.requestCount)")
                            .font(.title3)
                            .fontWeight(.bold)
                        
                        Text("requests")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            
            if hit.bandwidth > 0 {
                HStack {
                    Label(formatBandwidth(hit.bandwidth), systemImage: "arrow.down.circle.fill")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Spacer()
                }
            }
        }
        .padding(.vertical, 4)
    }
    
    private func formatBandwidth(_ bytes: Int64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        return formatter.string(fromByteCount: bytes)
    }
}

