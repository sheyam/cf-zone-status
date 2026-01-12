import SwiftUI

struct NotAuthenticatedView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.fill")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            
            Text("Not Authenticated")
                .font(.title2)
                .fontWeight(.bold)
            
            Text("Please configure your Cloudflare API token")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            
            Button(action: {
                appState.showSettings = true
            }) {
                Text("Open Settings")
                    .font(.headline)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 8)
            }
            .buttonStyle(.borderedProminent)
            .padding(.top, 8)
            
            Text("You can also set CLOUDFLARE_API_TOKEN environment variable or configure Wrangler credentials")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
        .padding(40)
        .frame(width: 400, height: 350)
    }
}

