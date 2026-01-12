import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var apiToken: String = ""
    @State private var showingToken: Bool = false
    @State private var isLoading: Bool = false
    @State private var errorMessage: String?
    @State private var successMessage: String?
    @Environment(\.dismiss) var dismiss
    
    var body: some View {
        VStack(spacing: 20) {
            // Header
            HStack {
                Text("Settings")
                    .font(.title2)
                    .fontWeight(.bold)
                Spacer()
                Button(action: { dismiss() }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal)
            .padding(.top)
            
            Divider()
            
            // API Token Configuration
            VStack(alignment: .leading, spacing: 12) {
                Text("Cloudflare API Token")
                    .font(.headline)
                
                Text("Enter your Cloudflare API token to authenticate with the API.")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                
                HStack {
                    if showingToken {
                        TextField("API Token", text: $apiToken)
                            .textFieldStyle(.roundedBorder)
                    } else {
                        SecureField("API Token", text: $apiToken)
                            .textFieldStyle(.roundedBorder)
                    }
                    
                    Button(action: { showingToken.toggle() }) {
                        Image(systemName: showingToken ? "eye.slash" : "eye")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
                
                if let error = errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                }
                
                if let success = successMessage {
                    Text(success)
                        .font(.caption)
                        .foregroundColor(.green)
                }
                
                // Help text
                VStack(alignment: .leading, spacing: 8) {
                    Text("How to get your API token:")
                        .font(.caption)
                        .fontWeight(.semibold)
                    
                    Link("Create API Token on Cloudflare Dashboard", 
                         destination: URL(string: "https://dash.cloudflare.com/profile/api-tokens")!)
                        .font(.caption)
                    
                    Text("Required permissions:")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .padding(.top, 4)
                    
                    Text("• Zone:Read\n• Zone:Analytics:Read\n• Zone:Security Events:Read")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding()
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(8)
            }
            .padding(.horizontal)
            
            Spacer()
            
            // Action buttons
            HStack(spacing: 12) {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                
                Button("Save") {
                    saveToken()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(isLoading)
                .help("Save and validate API token")
                
                if isLoading {
                    ProgressView()
                        .scaleEffect(0.8)
                }
            }
            .padding()
        }
        .frame(width: 500, height: 450)
        .onAppear {
            loadStoredToken()
        }
    }
    
    @State private var actualToken: String = ""
    
    private func loadStoredToken() {
        // Load token from UserDefaults (masked)
        if let storedToken = UserDefaults.standard.string(forKey: "CloudflareAPIToken"), !storedToken.isEmpty {
            // Store actual token for validation
            actualToken = storedToken
            // Show masked version in the field
            apiToken = String(repeating: "•", count: min(storedToken.count, 20))
        }
    }
    
    private func saveToken() {
        isLoading = true
        errorMessage = nil
        successMessage = nil
        
        // Determine which token to save
        let tokenToSave: String
        if showingToken {
            // User entered token in visible field
            tokenToSave = apiToken.trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            // Using secure field - check if user typed something new
            let trimmedToken = apiToken.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmedToken.allSatisfy({ $0 == "•" }) && !actualToken.isEmpty {
                // Field still shows masked value, user didn't change it - use stored token
                tokenToSave = actualToken
            } else if trimmedToken.isEmpty && !actualToken.isEmpty {
                // Field is empty but we have stored token - keep using stored token
                tokenToSave = actualToken
            } else {
                // User typed something new in secure field
                tokenToSave = trimmedToken
            }
        }
        
        // Validate token is not empty
        guard !tokenToSave.isEmpty else {
            isLoading = false
            errorMessage = "Please enter an API token"
            return
        }
        
        // Validate token by testing authentication
        Task {
            do {
                // Use the app's API client and set the token
                appState.apiClient.setAPIToken(tokenToSave)
                let isValid = try await appState.apiClient.checkAuthentication()
                
                await MainActor.run {
                    isLoading = false
                    
                    if isValid {
                        // Save to UserDefaults
                        UserDefaults.standard.set(tokenToSave, forKey: "CloudflareAPIToken")
                        successMessage = "Token saved successfully!"
                        errorMessage = nil
                        
                        // Reload authentication in AppState
                        appState.checkAuthentication()
                        
                        // Dismiss after a brief delay
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                            dismiss()
                        }
                    } else {
                        errorMessage = "Invalid token. Please check your API token and try again."
                        successMessage = nil
                        // Remove invalid token
                        UserDefaults.standard.removeObject(forKey: "CloudflareAPIToken")
                    }
                }
            } catch {
                await MainActor.run {
                    isLoading = false
                    errorMessage = "Failed to validate token: \(error.localizedDescription)"
                    successMessage = nil
                    UserDefaults.standard.removeObject(forKey: "CloudflareAPIToken")
                }
            }
        }
    }
}

