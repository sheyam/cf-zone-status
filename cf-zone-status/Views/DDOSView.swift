import SwiftUI

struct DDOSView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        VStack(spacing: 0) {
            if appState.isLoading {
                ProgressView("Loading DDoS events...")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if appState.ddosEvents.isEmpty {
                EmptyStateView(
                    icon: "checkmark.shield.fill",
                    title: "No DDoS Events",
                    message: appState.selectedZone != nil
                        ? "No DDoS attacks detected for \(appState.selectedZone!.name) in the last 30 days"
                        : "Select a zone to view DDoS events"
                )
            } else {
                List {
                    ForEach(appState.ddosEvents) { event in
                        DDOSEventRow(event: event)
                    }
                }
                .listStyle(.plain)
            }
        }
    }
}

struct DDOSEventRow: View {
    let event: DDOSEvent
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(event.zoneName)
                        .font(.headline)
                    
                    Text(event.attackType)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                if event.mitigated {
                    HStack(spacing: 4) {
                        Image(systemName: "checkmark.shield.fill")
                            .foregroundColor(.green)
                        Text("Mitigated")
                            .font(.caption)
                            .foregroundColor(.green)
                            .fontWeight(.medium)
                    }
                }
            }
            
            HStack(spacing: 20) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Peak RPS")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text("\(event.peakRps)")
                        .font(.headline)
                        .foregroundColor(.orange)
                }
                
                VStack(alignment: .leading, spacing: 2) {
                    Text("Total Requests")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(formatNumber(event.totalRequests))
                        .font(.headline)
                }
                
                Spacer()
            }
            
            HStack {
                Label(formatDate(event.startTime), systemImage: "clock.fill")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                if let endTime = event.endTime {
                    Text("→")
                        .foregroundColor(.secondary)
                    Label(formatDate(endTime), systemImage: "clock.fill")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Button(action: {
                    if let url = URL(string: "https://dash.cloudflare.com/\(event.zoneId)/security/events") {
                        NSWorkspace.shared.open(url)
                    }
                }) {
                    Text("View Details")
                        .font(.caption)
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(.vertical, 8)
    }
    
    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
    
    private func formatNumber(_ number: Int64) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        return formatter.string(from: NSNumber(value: number)) ?? "\(number)"
    }
}

struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String
    
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: icon)
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            
            Text(title)
                .font(.headline)
            
            Text(message)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

