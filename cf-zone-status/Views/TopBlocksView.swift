import SwiftUI

struct TopBlocksView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        VStack(spacing: 0) {
            if appState.isLoading {
                ProgressView("Loading top blocks...")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if appState.topBlocks.isEmpty {
                EmptyStateView(
                    icon: "shield.slash.fill",
                    title: "No Blocks Found",
                    message: appState.selectedZone != nil 
                        ? "No blocked requests for \(appState.selectedZone!.name) in the last 7 days"
                        : "Select a zone to view blocked requests"
                )
            } else {
                List {
                    ForEach(appState.topBlocks) { block in
                        TopBlockRow(block: block)
                    }
                }
                .listStyle(.plain)
            }
        }
    }
}

struct TopBlockRow: View {
    let block: TopBlock
    
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 6) {
                    // Domain (Zone Name)
                    HStack(spacing: 4) {
                        Image(systemName: "globe")
                            .foregroundColor(.blue)
                            .font(.caption)
                        Text(block.zoneName)
                            .font(.headline)
                            .foregroundColor(.primary)
                    }
                    
                    // Path
                    HStack(spacing: 4) {
                        Image(systemName: "link")
                            .foregroundColor(.secondary)
                            .font(.caption)
                        Text(block.displayPath)
                            .font(.system(.subheadline, design: .monospaced))
                            .foregroundColor(.secondary)
                            .lineLimit(2)
                    }
                    
                    // IP Address
                    HStack(spacing: 4) {
                        Image(systemName: "network")
                            .foregroundColor(.secondary)
                            .font(.caption)
                        Text(block.ipAddress)
                            .font(.system(.subheadline, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                }
                
                Spacer()
                
                VStack(alignment: .trailing, spacing: 4) {
                    Text("\(block.count)")
                        .font(.title2)
                        .fontWeight(.bold)
                        .foregroundColor(.red)
                    
                    Text("blocks")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    Text("Last: \(formatDate(block.lastSeen))")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .padding(.top, 4)
                }
            }
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 4)
    }
    
    private func formatDate(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

