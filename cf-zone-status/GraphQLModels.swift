import Foundation

// MARK: - GraphQL Request/Response Models

struct GraphQLRequest: Codable {
    let query: String
    let variables: [String: AnyCodable]?
    
    enum CodingKeys: String, CodingKey {
        case query
        case variables
    }
}

struct GraphQLResponse<T: Codable>: Codable {
    let data: T?
    let errors: [GraphQLError]?
}

struct GraphQLError: Codable {
    let message: String
    let locations: [GraphQLErrorLocation]?
    let path: [String]?
}

struct GraphQLErrorLocation: Codable {
    let line: Int
    let column: Int
}

struct GraphQLData: Codable {
    let viewer: GraphQLViewer
}

struct GraphQLViewer: Codable {
    let zones: [GraphQLZone]?
}

struct GraphQLZone: Codable {
    let firewallEventsAdaptiveGroups: [FirewallEventGroup]?
    let httpRequestsAdaptiveGroups: [HTTPRequestGroup]?
}

// MARK: - Firewall Events (from firewallEventsAdaptiveGroups)

struct FirewallEventGroup: Codable {
    let count: Int
    let dimensions: FirewallEventDimensions?
}

struct FirewallEventDimensions: Codable {
    let clientRequestPath: String?
    let clientRequestHTTPHost: String?
    let clientIP: String?
    let clientCountryName: String?
    let action: String?
    let datetime: String?
}

struct HTTPRequestGroup: Codable {
    let dimensions: HTTPRequestDimensions?
    let sum: HTTPRequestSum?
}

struct HTTPRequestDimensions: Codable {
    let clientIP: String?
    let clientRequestHTTPHost: String?
    let clientRequestPath: String?
    let datetimeHour: String?
    let date: String?
}

struct HTTPRequestSum: Codable {
    let requests: Int?
    let visits: Int?
    let edgeResponseBytes: Int64?
    let bytes: Int?
}

// MARK: - AnyCodable for GraphQL Variables

struct AnyCodable: Codable {
    let value: Any
    
    init(_ value: Any) {
        self.value = value
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let int = try? container.decode(Int.self) {
            value = int
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let string = try? container.decode(String.self) {
            value = string
        } else if let array = try? container.decode([AnyCodable].self) {
            value = array.map { $0.value }
        } else if let dictionary = try? container.decode([String: AnyCodable].self) {
            value = dictionary.mapValues { $0.value }
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "AnyCodable value cannot be decoded")
        }
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        
        switch value {
        case let bool as Bool:
            try container.encode(bool)
        case let int as Int:
            try container.encode(int)
        case let double as Double:
            try container.encode(double)
        case let string as String:
            try container.encode(string)
        case let array as [Any]:
            try container.encode(array.map { AnyCodable($0) })
        case let dictionary as [String: Any]:
            try container.encode(dictionary.mapValues { AnyCodable($0) })
        default:
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: encoder.codingPath, debugDescription: "AnyCodable value cannot be encoded"))
        }
    }
}

