import SwiftUI
import AppKit

@main
struct CloudflareStatusBarApp: App {
    @StateObject private var appState = AppState()
    
    var body: some Scene {
        MenuBarExtra("Cloudflare Status", systemImage: "cloud.fill") {
            VStack(spacing: 0) {
                ContentView()
                    .environmentObject(appState)
                
                Divider()
                
                // Menu items
                Button(action: {
                    appState.showSettings = true
                }) {
                    Label("Settings", systemImage: "gearshape")
                }
                .buttonStyle(.plain)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                
                Button(action: {
                    NSApplication.shared.terminate(nil)
                }) {
                    Label("Quit", systemImage: "power")
                }
                .buttonStyle(.plain)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
        }
        .menuBarExtraStyle(.window)
    }
}

