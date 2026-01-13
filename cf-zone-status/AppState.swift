import Foundation
import Combine

@MainActor
class AppState: ObservableObject {
    @Published var zones: [Zone] = []
    @Published var topBlocks: [TopBlock] = []
    @Published var ipHits: [IPHit] = []
    @Published var domainHits: [DomainHit] = []
    @Published var ddosEvents: [DDOSEvent] = []
    @Published var blockedRequestsCount: Int = 0
    @Published var isLoading = false
    @Published var isAuthenticated = false
    @Published var errorMessage: String?
    @Published var selectedZone: Zone? = nil
    @Published var showSettings = false
    
    let apiClient = CloudflareAPIClient() // Changed to let so SettingsView can access it
    private var refreshTimer: Timer?
    
    private var zoneSelectionCancellable: AnyCancellable?
    
    init() {
        checkAuthentication()
        startAutoRefresh()
        
        // Observe zone selection changes and fetch data when zone is selected
        zoneSelectionCancellable = $selectedZone
            .dropFirst() // Skip initial nil value
            .debounce(for: .milliseconds(300), scheduler: RunLoop.main)
            .sink { [weak self] selectedZone in
                Task { @MainActor [weak self] in
                    await self?.loadZoneData(for: selectedZone)
                }
            }
    }
    
    func checkAuthentication() {
        // Reload credentials in case they changed
        apiClient.reloadCredentials()
        
        Task { @MainActor [weak self] in
            guard let self = self else { return }
            do {
                self.isAuthenticated = try await self.apiClient.checkAuthentication()
                if self.isAuthenticated {
                    await self.loadData()
                }
            } catch {
                self.isAuthenticated = false
                self.errorMessage = "Authentication failed: \(error.localizedDescription)"
            }
        }
    }
    
    func loadData() async {
        // Only load zones list initially, not all data
        isLoading = true
        errorMessage = nil
        
        do {
            self.zones = try await apiClient.fetchZones()
            // Clear existing data when loading zones
            self.topBlocks = []
            self.ipHits = []
            self.domainHits = []
            self.ddosEvents = []
        } catch {
            errorMessage = "Failed to load zones: \(error.localizedDescription)"
            print("Error loading zones: \(error)")
            if let apiError = error as? APIError {
                print("API Error details: \(apiError.localizedDescription)")
            }
        }
        
        isLoading = false
    }
    
    func loadZoneData(for zone: Zone?) async {
        isLoading = true
        errorMessage = nil
        
        do {
            // Fetch domain hits for all zones (doesn't require zone selection)
            async let domainHitsTask = apiClient.fetchDomainHits(limit: 50)
            
            if let zone = zone {
                // Fetch data for selected zone only
                async let blocksTask = apiClient.fetchTopBlocks(limit: 10, forZone: zone)
                async let ipHitsTask = apiClient.fetchIPHits(limit: 10, forZone: zone)
                async let ddosTask = apiClient.fetchDDOSEvents(days: 30, forZone: zone)
                async let blockedCountTask = apiClient.fetchBlockedRequestsCount(forZone: zone)
                
                self.topBlocks = try await blocksTask
                self.ipHits = try await ipHitsTask
                self.ddosEvents = try await ddosTask
                self.blockedRequestsCount = try await blockedCountTask
            } else {
                // No zone selected - clear zone-specific data
                self.topBlocks = []
                self.ipHits = []
                self.ddosEvents = []
                self.blockedRequestsCount = 0
            }
            
            // Always fetch domain hits regardless of zone selection
            self.domainHits = try await domainHitsTask
        } catch {
            let errorDesc = error.localizedDescription
            errorMessage = "Failed to load zone data: \(errorDesc)"
            print("Error loading zone data: \(error)")
            print("Error type: \(type(of: error))")
            if let apiError = error as? APIError {
                print("API Error details: \(apiError.localizedDescription)")
            }
            // Clear data on error
            self.topBlocks = []
            self.ipHits = []
            self.domainHits = []
            self.ddosEvents = []
            self.blockedRequestsCount = 0
        }
        
        isLoading = false
    }
    
    func refresh() {
        Task {
            if selectedZone != nil {
                await loadZoneData(for: selectedZone)
            } else {
                await loadZoneData(for: nil)
            }
        }
    }
    
    private func startAutoRefresh() {
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refresh()
            }
        }
    }
    
    deinit {
        refreshTimer?.invalidate()
    }
}
