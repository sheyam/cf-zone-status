import Foundation

struct Zone: Identifiable, Codable, Hashable {
    let id: String
    let name: String
    let status: String
    let plan: ZonePlan?
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case status
        case plan
    }
}

struct ZonePlan: Codable, Hashable {
    let name: String
}

struct TopBlock: Identifiable {
    let id: String
    let zoneName: String
    let path: String
    let ipAddress: String
    let action: String
    let ruleId: String?
    let count: Int
    let lastSeen: Date
    
    var displayPath: String {
        path.isEmpty ? "/" : path
    }
}

struct IPHit: Identifiable {
    let id: String
    let ipAddress: String
    let zoneName: String
    let requestCount: Int
    let blockedCount: Int
    let country: String?
    let lastSeen: Date
}

struct DomainHit: Identifiable {
    let id: String
    let domain: String
    let zoneName: String
    let requestCount: Int
    let bandwidth: Int64
    let lastSeen: Date
}

struct DDOSEvent: Identifiable {
    let id: String
    let zoneName: String
    let zoneId: String
    let attackType: String
    let startTime: Date
    let endTime: Date?
    let peakRps: Int
    let totalRequests: Int64
    let mitigated: Bool
}

struct AnalyticsSummary: Identifiable {
    let id: String
    let zoneName: String
    let totalRequests: Int64
    let totalBandwidth: Int64
    let cachedRequests: Int64
    let blockedRequests: Int64
    let period: DateInterval
}

