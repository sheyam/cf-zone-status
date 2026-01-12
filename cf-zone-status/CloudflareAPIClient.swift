import Foundation

class CloudflareAPIClient {
    private let baseURL = "https://api.cloudflare.com/client/v4"
    private let graphQLURL = "https://api.cloudflare.com/client/v4/graphql"
    private var apiToken: String?
    private var accountId: String?
    
    init() {
        loadCredentials()
    }
    
    private func loadCredentials() {
        // First, try UserDefaults (in-app settings)
        if let storedToken = UserDefaults.standard.string(forKey: "CloudflareAPIToken"), !storedToken.isEmpty {
            apiToken = storedToken
            return
        }
        
        // Second, try environment variable (for development/testing)
        if let envToken = ProcessInfo.processInfo.environment["CLOUDFLARE_API_TOKEN"], !envToken.isEmpty {
            apiToken = envToken
            return
        }
        
        // Fallback to Wrangler config files
        let configPaths = [
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Preferences/.wrangler/config/default.toml"),
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".wrangler/config/default.toml"),
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/.wrangler/config/default.toml"),
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/wrangler/config/default.toml")
        ]
        
        for configPath in configPaths {
            if let config = loadTOML(from: configPath) {
                if let token = config["api_token"] as? String, !token.isEmpty {
                    apiToken = token
                    return
                }
            }
        }
    }
    
    // Public method to set API token programmatically (for settings UI)
    func setAPIToken(_ token: String) {
        apiToken = token
    }
    
    // Method to reload credentials (call after settings change)
    func reloadCredentials() {
        loadCredentials()
    }
    
    private func loadTOML(from path: URL) -> [String: Any]? {
        guard let data = try? Data(contentsOf: path),
              let content = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        var config: [String: Any] = [:]
        for line in content.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.contains("=") && !trimmed.starts(with: "#") {
                let parts = trimmed.split(separator: "=", maxSplits: 1)
                if parts.count == 2 {
                    let key = parts[0].trimmingCharacters(in: .whitespaces)
                    var value = parts[1].trimmingCharacters(in: .whitespaces)
                    // Remove quotes if present
                    if value.hasPrefix("\"") && value.hasSuffix("\"") {
                        value = String(value.dropFirst().dropLast())
                    }
                    config[key] = value
                }
            }
        }
        return config
    }
    
    func checkAuthentication() async throws -> Bool {
        guard apiToken != nil else { return false }
        let response: APIResponse<[Zone]> = try await performRequest(endpoint: "/zones?per_page=1")
        return response.success
    }
    
    func fetchZones() async throws -> [Zone] {
        var allZones: [Zone] = []
        var page = 1
        let perPage = 50
        
        while true {
            let response: APIResponse<[Zone]> = try await performRequest(
                endpoint: "/zones?per_page=\(perPage)&page=\(page)"
            )
            
            if let zones = response.result {
                allZones.append(contentsOf: zones)
                if zones.count < perPage {
                    break
                }
            } else {
                break
            }
            
            page += 1
        }
        
        return allZones
    }
    
    // Fetch top 10 malicious hits to zone domains (subdomains)
    func fetchTopBlocks(limit: Int = 10, forZone zone: Zone) async throws -> [TopBlock] {
        var allBlocks: [TopBlock] = []
        
        // Fetch firewall events for last 7 days using GraphQL
        let endDate = Date()
        let startDate = Calendar.current.date(byAdding: .day, value: -7, to: endDate)!
        let startTime = formatISO8601DateTime(startDate)
        let endTime = formatISO8601DateTime(endDate)
        
        do {
            // Query based on Cloudflare documentation - using firewallEventsAdaptiveGroups
            let query = """
            query GetSecurityEvents($zoneTag: String!, $since: Time!, $until: Time!) {
              viewer {
                zones(filter: { zoneTag: $zoneTag }) {
                  firewallEventsAdaptiveGroups(
                    filter: {
                      datetime_geq: $since
                      datetime_leq: $until
                      action_in: ["block", "challenge"]
                    }
                    limit: \(limit * 2)
                    orderBy: [count_DESC]
                  ) {
                    count
                    dimensions {
                      clientRequestPath
                      clientRequestHTTPHost
                      clientIP
                      action
                    }
                  }
                }
              }
            }
            """
            
            let variables: [String: AnyCodable] = [
                "zoneTag": AnyCodable(zone.id),
                "since": AnyCodable(startTime),
                "until": AnyCodable(endTime)
            ]
            
            let response: GraphQLResponse<GraphQLData> = try await performGraphQLRequest(query: query, variables: variables)
            
            // Log response for debugging
            print("GraphQL Response for zone \(zone.name) (\(zone.id)):")
            print("  - Has data: \(response.data != nil)")
            print("  - Has errors: \(response.errors != nil)")
            if let errors = response.errors {
                for error in errors {
                    print("  - Error: \(error.message)")
                }
            }
            
            guard let data = response.data else {
                print("  - No data in response")
                print("  - Response.data is nil")
                return []
            }
            
            let viewer = data.viewer
            print("  - Viewer decoded successfully")
            print("  - viewer.zones is nil: \(viewer.zones == nil)")
            if let zones = viewer.zones {
                print("  - Zones array has \(zones.count) zones")
            }
            
            guard let zones = viewer.zones else {
                print("  - No zones array in viewer")
                // Try using Mirror to inspect the actual object
                let mirror = Mirror(reflecting: viewer)
                print("  - Viewer type: \(type(of: viewer))")
                print("  - Viewer properties: \(mirror.children.count)")
                for child in mirror.children {
                    print("  - Property: \(child.label ?? "nil") = \(child.value)")
                }
                return []
            }
            
            guard let zoneData = zones.first else {
                print("  - No zone data (zones array is empty)")
                return []
            }
            
            guard let events = zoneData.firewallEventsAdaptiveGroups else {
                print("  - No firewallEventsAdaptiveGroups (property is nil)")
                print("  - Zone data has \(zones.count) zones")
                return []
            }
            
            print("  - Found \(events.count) firewall event groups")
            
            // Convert to TopBlock array
            for eventGroup in events {
                let dimensions = eventGroup.dimensions
                let host = dimensions?.clientRequestHTTPHost ?? zone.name
                let path = dimensions?.clientRequestPath ?? "/"
                let ip = dimensions?.clientIP ?? "unknown"
                let action = dimensions?.action ?? "block"
                let count = eventGroup.count
                
                allBlocks.append(TopBlock(
                    id: "\(zone.id)-\(host)-\(path)-\(ip)",
                    zoneName: host,
                    path: path,
                    ipAddress: ip,
                    action: action,
                    ruleId: nil,
                    count: count,
                    lastSeen: Date() // Groups don't have datetime, use current date
                ))
            }
            
        } catch {
            print("Error fetching blocks for zone \(zone.name): \(error)")
            throw error
        }
        
        // Sort by count and return top N
        return Array(allBlocks.sorted { $0.count > $1.count }.prefix(limit))
    }
    
    // Fetch top 10 traffic generating malicious IPs
    func fetchIPHits(limit: Int = 10, forZone zone: Zone) async throws -> [IPHit] {
        var allIPHits: [IPHit] = []
        
        // Fetch firewall events for last 7 days
        let endDate = Date()
        let startDate = Calendar.current.date(byAdding: .day, value: -7, to: endDate)!
        let startTime = formatISO8601DateTime(startDate)
        let endTime = formatISO8601DateTime(endDate)
        
        do {
            let query = """
            query GetSecurityEvents($zoneTag: String!, $since: Time!, $until: Time!) {
              viewer {
                zones(filter: { zoneTag: $zoneTag }) {
                  firewallEventsAdaptiveGroups(
                    filter: {
                      datetime_geq: $since
                      datetime_leq: $until
                      action_in: ["block", "challenge"]
                    }
                    limit: \(limit * 2)
                    orderBy: [count_DESC]
                  ) {
                    count
                    dimensions {
                      clientIP
                      clientCountryName
                      action
                    }
                  }
                }
              }
            }
            """
            
            let variables: [String: AnyCodable] = [
                "zoneTag": AnyCodable(zone.id),
                "since": AnyCodable(startTime),
                "until": AnyCodable(endTime)
            ]
            
            let response: GraphQLResponse<GraphQLData> = try await performGraphQLRequest(query: query, variables: variables)
            
            guard let data = response.data,
                  let zones = data.viewer.zones,
                  let zoneData = zones.first,
                  let events = zoneData.firewallEventsAdaptiveGroups else {
                return []
            }
            
            print("  - Found \(events.count) malicious IP event groups")
            
            // Convert to IPHit array
            for eventGroup in events {
                let dimensions = eventGroup.dimensions
                guard let ip = dimensions?.clientIP else { continue }
                let count = eventGroup.count
                
                allIPHits.append(IPHit(
                    id: "\(zone.id)-\(ip)",
                    ipAddress: ip,
                    zoneName: zone.name,
                    requestCount: count,
                    blockedCount: count,
                    country: dimensions?.clientCountryName,
                    lastSeen: Date() // Groups don't have datetime
                ))
            }
            
        } catch {
            print("Error fetching IP hits for zone \(zone.name): \(error)")
            throw error
        }
        
        // Sort by request count (traffic generating) and return top N
        return Array(allIPHits.sorted { $0.requestCount > $1.requestCount }.prefix(limit))
    }
    
    // Fetch top 10 contributing paths (malicious by IPs)
    func fetchTopPaths(limit: Int = 10, forZone zone: Zone) async throws -> [TopBlock] {
        var allPaths: [TopBlock] = []
        
        let endDate = Date()
        let startDate = Calendar.current.date(byAdding: .day, value: -7, to: endDate)!
        let startTime = formatISO8601DateTime(startDate)
        let endTime = formatISO8601DateTime(endDate)
        
        do {
            let query = """
            query GetSecurityEvents($zoneTag: String!, $since: Time!, $until: Time!) {
              viewer {
                zones(filter: { zoneTag: $zoneTag }) {
                  firewallEventsAdaptiveGroups(
                    filter: {
                      datetime_geq: $since
                      datetime_leq: $until
                      action_in: ["block", "challenge"]
                    }
                    limit: \(limit * 2)
                    orderBy: [count_DESC]
                  ) {
                    count
                    dimensions {
                      clientRequestPath
                      clientRequestHTTPHost
                      clientIP
                    }
                  }
                }
              }
            }
            """
            
            let variables: [String: AnyCodable] = [
                "zoneTag": AnyCodable(zone.id),
                "since": AnyCodable(startTime),
                "until": AnyCodable(endTime)
            ]
            
            let response: GraphQLResponse<GraphQLData> = try await performGraphQLRequest(query: query, variables: variables)
            
            guard let data = response.data,
                  let zones = data.viewer.zones,
                  let zoneData = zones.first,
                  let events = zoneData.firewallEventsAdaptiveGroups else {
                return []
            }
            
            // Convert to TopBlock array
            for eventGroup in events {
                let dimensions = eventGroup.dimensions
                let path = dimensions?.clientRequestPath ?? "/"
                let host = dimensions?.clientRequestHTTPHost ?? zone.name
                let ip = dimensions?.clientIP ?? "unknown"
                let count = eventGroup.count
                
                allPaths.append(TopBlock(
                    id: "\(zone.id)-\(path)-\(ip)",
                    zoneName: host,
                    path: path,
                    ipAddress: ip,
                    action: "block",
                    ruleId: nil,
                    count: count,
                    lastSeen: Date()
                ))
            }
            
        } catch {
            print("Error fetching top paths for zone \(zone.name): \(error)")
            throw error
        }
        
        // Sort by count and return top N
        return Array(allPaths.sorted { $0.count > $1.count }.prefix(limit))
    }
    
    // Fetch overall blocked requests count
    func fetchBlockedRequestsCount(forZone zone: Zone) async throws -> Int {
        let endDate = Date()
        let startDate = Calendar.current.date(byAdding: .day, value: -7, to: endDate)!
        let startTime = formatISO8601DateTime(startDate)
        let endTime = formatISO8601DateTime(endDate)
        
        do {
            let query = """
            query GetSecurityEvents($zoneTag: String!, $since: Time!, $until: Time!) {
              viewer {
                zones(filter: { zoneTag: $zoneTag }) {
                  firewallEventsAdaptiveGroups(
                    filter: {
                      datetime_geq: $since
                      datetime_leq: $until
                      action_in: ["block", "challenge"]
                    }
                    limit: 10000
                    orderBy: [count_DESC]
                  ) {
                    count
                  }
                }
              }
            }
            """
            
            let variables: [String: AnyCodable] = [
                "zoneTag": AnyCodable(zone.id),
                "since": AnyCodable(startTime),
                "until": AnyCodable(endTime)
            ]
            
            let response: GraphQLResponse<GraphQLData> = try await performGraphQLRequest(query: query, variables: variables)
            
            guard let data = response.data,
                  let zones = data.viewer.zones,
                  let zoneData = zones.first,
                  let events = zoneData.firewallEventsAdaptiveGroups else {
                return 0
            }
            
            // Sum all counts
            let totalCount = events.reduce(0) { $0 + $1.count }
            return totalCount
            
        } catch {
            print("Error fetching blocked requests count for zone \(zone.name): \(error)")
            throw error
        }
    }
    
    func fetchDomainHits(limit: Int) async throws -> [DomainHit] {
        let zones = try await fetchZones()
        var allDomainHits: [DomainHit] = []
        
        // Use Analytics API for domain statistics
        for zone in zones {
            // Simplified implementation - in production use GraphQL Analytics API
            allDomainHits.append(DomainHit(
                id: zone.id,
                domain: zone.name,
                zoneName: zone.name,
                requestCount: 0, // Would be populated from Analytics API
                bandwidth: 0,
                lastSeen: Date()
            ))
        }
        
        return Array(allDomainHits.prefix(limit))
    }
    
    // Fetch DDoS data by zone
    func fetchDDOSEvents(days: Int = 30, forZone zone: Zone) async throws -> [DDOSEvent] {
        var allDDOSEvents: [DDOSEvent] = []
        
        let endDate = Date()
        let startDate = Calendar.current.date(byAdding: .day, value: -days, to: endDate)!
        let startTime = formatISO8601DateTime(startDate)
        let endTime = formatISO8601DateTime(endDate)
        
        do {
            // Use firewallEventsAdaptiveGroups to get aggregated data by time
            let query = """
            query GetSecurityEvents($zoneTag: String!, $since: Time!, $until: Time!) {
              viewer {
                zones(filter: { zoneTag: $zoneTag }) {
                  firewallEventsAdaptiveGroups(
                    filter: {
                      datetime_geq: $since
                      datetime_leq: $until
                      action_in: ["block", "challenge"]
                    }
                    limit: 1000
                    orderBy: [count_DESC]
                  ) {
                    count
                    dimensions {
                      datetime
                      clientIP
                    }
                  }
                }
              }
            }
            """
            
            let variables: [String: AnyCodable] = [
                "zoneTag": AnyCodable(zone.id),
                "since": AnyCodable(startTime),
                "until": AnyCodable(endTime)
            ]
            
            let response: GraphQLResponse<GraphQLData> = try await performGraphQLRequest(query: query, variables: variables)
            
            guard let data = response.data,
                  let zones = data.viewer.zones,
                  let zoneData = zones.first,
                  let events = zoneData.firewallEventsAdaptiveGroups else {
                return []
            }
            
            print("  - Found \(events.count) blocked event groups for DDoS analysis")
            
            // Group by 15-minute intervals
            var eventGroupsByInterval: [String: (count: Int, uniqueIPs: Set<String>)] = [:]
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            
            for eventGroup in events {
                guard let datetimeString = eventGroup.dimensions?.datetime,
                      let eventDate = formatter.date(from: datetimeString) else { continue }
                
                // Round to 15-minute interval
                let calendar = Calendar.current
                let minute = calendar.component(.minute, from: eventDate)
                let roundedMinute = (minute / 15) * 15
                let roundedDate = calendar.date(bySetting: .minute, value: roundedMinute, of: eventDate) ?? eventDate
                let intervalKey = formatter.string(from: roundedDate)
                
                let ip = eventGroup.dimensions?.clientIP ?? "unknown"
                let count = eventGroup.count
                
                if var existing = eventGroupsByInterval[intervalKey] {
                    existing.count += count
                    existing.uniqueIPs.insert(ip)
                    eventGroupsByInterval[intervalKey] = existing
                } else {
                    eventGroupsByInterval[intervalKey] = (
                        count: count,
                        uniqueIPs: Set([ip])
                    )
                }
            }
            
            // Identify potential DDoS events (high volume in short time)
            for (intervalKey, data) in eventGroupsByInterval where data.count > 50 {
                guard let startTime = formatter.date(from: intervalKey) else { continue }
                let endTime = Calendar.current.date(byAdding: .minute, value: 15, to: startTime) ?? startTime
                let peakRps = data.count / 900 // Approximate requests per second (15 minutes = 900 seconds)
                
                let attackType = data.uniqueIPs.count > 100 ? "Distributed" : "Volumetric"
                
                allDDOSEvents.append(DDOSEvent(
                    id: "\(zone.id)-\(startTime.timeIntervalSince1970)",
                    zoneName: zone.name,
                    zoneId: zone.id,
                    attackType: "\(attackType) DDoS (\(data.uniqueIPs.count) unique IPs)",
                    startTime: startTime,
                    endTime: endTime,
                    peakRps: peakRps,
                    totalRequests: Int64(data.count),
                    mitigated: true
                ))
            }
            
        } catch {
            print("Error fetching DDoS events for zone \(zone.name): \(error)")
            throw error
        }
        
        return allDDOSEvents.sorted { $0.startTime > $1.startTime }
    }
    
    // MARK: - Helper Methods
    
    private func performRequest<T: Codable>(endpoint: String) async throws -> APIResponse<T> {
        guard let token = apiToken else {
            throw APIError.notAuthenticated
        }
        
        guard let url = URL(string: "\(baseURL)\(endpoint)") else {
            throw APIError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }
        
        guard (200...299).contains(httpResponse.statusCode) else {
            let responseString = String(data: data, encoding: .utf8) ?? "Unable to decode response"
            print("API Error for \(endpoint): HTTP \(httpResponse.statusCode)")
            print("Response: \(responseString)")
            
            if let errorResponse = try? JSONDecoder().decode(APIErrorResponse.self, from: data) {
                let errorMsg = errorResponse.errors.first?.message ?? "Unknown error"
                print("API Error message: \(errorMsg)")
                throw APIError.apiError(errorMsg)
            }
            throw APIError.httpError(httpResponse.statusCode)
        }
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        do {
            let decoded = try decoder.decode(APIResponse<T>.self, from: data)
            print("Successfully decoded API response for \(endpoint)")
            return decoded
        } catch {
            let responseString = String(data: data, encoding: .utf8) ?? "Unable to decode"
            print("Failed to decode API response for \(endpoint)")
            print("Response string (first 500 chars): \(String(responseString.prefix(500)))")
            print("Decoding error: \(error)")
            throw error
        }
    }
    
    private func formatDate(daysAgo: Int) -> String {
        let date = Calendar.current.date(byAdding: .day, value: -daysAgo, to: Date()) ?? Date()
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate]
        return formatter.string(from: date)
    }
    
    // MARK: - GraphQL Methods
    
    private func performGraphQLRequest<T: Codable>(query: String, variables: [String: AnyCodable]? = nil) async throws -> GraphQLResponse<T> {
        guard let token = apiToken else {
            throw APIError.notAuthenticated
        }
        
        guard let url = URL(string: graphQLURL) else {
            throw APIError.invalidURL
        }
        
        let graphQLRequest = GraphQLRequest(query: query, variables: variables)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            request.httpBody = try JSONEncoder().encode(graphQLRequest)
            // Log the request for debugging
            if let body = request.httpBody, let bodyString = String(data: body, encoding: .utf8) {
                print("GraphQL Request: \(bodyString)")
            }
        } catch {
            print("Failed to encode GraphQL request: \(error)")
            throw APIError.invalidURL
        }
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }
        
        // Log raw response for debugging
        let responseString = String(data: data, encoding: .utf8) ?? "Unable to decode response"
        print("GraphQL Response (HTTP \(httpResponse.statusCode)): \(String(responseString.prefix(1000)))")
        
        guard (200...299).contains(httpResponse.statusCode) else {
            print("GraphQL API Error: HTTP \(httpResponse.statusCode)")
            print("Response: \(responseString)")
            throw APIError.httpError(httpResponse.statusCode)
        }
        
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        
        do {
            let graphQLResponse = try decoder.decode(GraphQLResponse<T>.self, from: data)
            
            if let errors = graphQLResponse.errors, !errors.isEmpty {
                let errorMessages = errors.map { $0.message }.joined(separator: "; ")
                print("GraphQL errors: \(errorMessages)")
                // Don't throw immediately - log and continue to see what data we got
            }
            
            // Log decoded structure for debugging
            print("GraphQL Response decoded - data is nil: \(graphQLResponse.data == nil)")
            
            return graphQLResponse
        } catch let decodingError as DecodingError {
            print("Failed to decode GraphQL response")
            print("Response string (first 1000 chars): \(String(responseString.prefix(1000)))")
            print("Decoding error type: \(type(of: decodingError))")
            
            switch decodingError {
            case .dataCorrupted(let context):
                print("Data corrupted: \(context.debugDescription)")
                print("Coding path: \(context.codingPath)")
            case .keyNotFound(let key, let context):
                print("Key not found: \(key.stringValue)")
                print("Coding path: \(context.codingPath)")
            case .typeMismatch(let type, let context):
                print("Type mismatch: expected \(type), coding path: \(context.codingPath)")
            case .valueNotFound(let type, let context):
                print("Value not found: \(type), coding path: \(context.codingPath)")
            @unknown default:
                print("Unknown decoding error: \(decodingError)")
            }
            throw decodingError
        } catch {
            print("Failed to decode GraphQL response: \(error)")
            print("Response string (first 1000 chars): \(String(responseString.prefix(1000)))")
            throw error
        }
    }
    
    private func formatISO8601DateTime(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}

// MARK: - API Response Models

struct APIResponse<T: Codable>: Codable {
    let success: Bool
    let result: T?
    let errors: [APIErrorDetail]?
    let messages: [String]?
}

struct APIErrorResponse: Codable {
    let success: Bool
    let errors: [APIErrorDetail]
}

struct APIErrorDetail: Codable {
    let code: Int
    let message: String
}

enum APIError: LocalizedError {
    case notAuthenticated
    case invalidURL
    case invalidResponse
    case httpError(Int)
    case apiError(String)
    
    var errorDescription: String? {
        switch self {
        case .notAuthenticated:
            return "Not authenticated. Please configure Cloudflare API token."
        case .invalidURL:
            return "Invalid URL"
        case .invalidResponse:
            return "Invalid response from API"
        case .httpError(let code):
            return "HTTP error: \(code)"
        case .apiError(let message):
            return message
        }
    }
}


