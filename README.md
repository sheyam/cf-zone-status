# Cloudflare Zone Status

A native macOS menu bar app for monitoring your Cloudflare zones with security analytics, including top blocks, IP hits, domain hits, and DDoS attack statistics.

## Features

### Core Features

- **Zone Overview** - View all your Cloudflare zones with status and plan information
- **Top 10 Blocks** - Monitor the top blocked requests across all zones, including paths and IP addresses
- **IP Hits** - Track IP addresses with request counts, blocked counts, and blocking percentages
- **Domain Hits** - Monitor domain-level traffic statistics
- **DDoS Attacks** - View DDoS events across zones in the last 30 days with attack details
- **Auto-refresh** - Automatically refreshes data every 5 minutes
- **Quick Links** - Direct links to Cloudflare Dashboard for detailed views

### Additional Recommended Features

- **Real-time Monitoring** - Live updates on security events and traffic patterns
- **Historical Trends** - View security metrics over time
- **Custom Alerts** - Set thresholds for various metrics and receive notifications
- **Performance Metrics** - Monitor cache hit ratios, latency, and bandwidth usage
- **Zone Filtering** - Filter views by specific zones
- **Export Data** - Export analytics data for reporting

## Installation

### Homebrew (Recommended)

```bash
brew tap sheyam/cf-zone-status
brew install --cask cf-zone-status
```

### Manual Download

Download the latest release from the [Releases page](https://github.com/sheyam/cf-zone-status/releases).

1. Download the `.dmg` file
2. Open the DMG and drag `cf-zone-status.app` to Applications
3. First launch: Right-click the app > **Open** > **Open** (to bypass macOS security warning)

### Prerequisites

- macOS 13.0 (Ventura) or later
- Cloudflare API Token with appropriate permissions

### Setting Up Cloudflare API Token

The app provides an in-app settings UI to configure your API token. Alternatively:

1. Go to [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Create a custom token with the following permissions:
   - **Zone** - Zone:Read
   - **Zone** - Analytics:Read
   - **Zone** - Security Events:Read
   - **Account** - Account:Read (optional, for account-level data)

You can also use Wrangler CLI credentials:

```bash
npm install -g wrangler
wrangler login
```

The app will automatically detect Wrangler credentials or you can enter the token directly in Settings.

### Building from Source

1. Clone this repository:
```bash
git clone https://github.com/sheyam/cf-zone-status.git
cd cf-zone-status
```

2. Open the Xcode project:
```bash
open xcode/cf-zone-status/cf-zone-status.xcodeproj
```

3. Build and run:
   - In Xcode: **Cmd + R**
   - Or use the build script: `./scripts/build-release.sh 1.0.0`

4. Configure API token:
   - Use the in-app Settings (gear icon)
   - Or set `CLOUDFLARE_API_TOKEN` environment variable
   - Or configure Wrangler credentials (automatically detected)

## Configuration

The app looks for Cloudflare credentials in these locations (in order):

1. **In-app Settings** (UserDefaults) - Configure via Settings UI (gear icon) ← **Recommended**
2. Environment variable: `CLOUDFLARE_API_TOKEN`
3. Wrangler config files:
   - `~/Library/Preferences/.wrangler/config/default.toml`
   - `~/.wrangler/config/default.toml`
   - `~/.config/.wrangler/config/default.toml`
   - `~/.config/wrangler/config/default.toml`

### Using In-App Settings (Recommended)

1. Launch the app
2. Click the **gear icon** in the toolbar (or "Open Settings" if not authenticated)
3. Enter your Cloudflare API token
4. Click **Save** - the token will be validated automatically

### Environment Variable Setup

```bash
export CLOUDFLARE_API_TOKEN="your-api-token-here"
```

## Usage

1. Launch the app (it will appear in your menu bar with a cloud icon)
2. Click the cloud icon to open the status window
3. Navigate between tabs:
   - **Overview** - Summary statistics and zone list
   - **Top Blocks** - Top 10 blocked requests
   - **IP Hits** - IP address statistics
   - **Domains** - Domain hit statistics
   - **DDoS** - DDoS attack events (last 30 days)
4. Click refresh button or wait for auto-refresh (every 5 minutes)
5. Click zone names or "View Details" buttons to open Cloudflare Dashboard

## API Endpoints Used

The app uses the following Cloudflare API endpoints:

- `GET /zones` - List all zones
- `GET /zones/{zone_id}/security/events/firewall` - Firewall events (for blocks, IP hits, DDoS detection)
- Analytics API (via firewall events) - For traffic statistics

### Future Enhancements

- GraphQL Analytics API integration for more detailed analytics
- Real-time WebSocket connections for live updates
- Custom date range selection
- Advanced filtering and search
- Data visualization with charts
- Export functionality (CSV, JSON)

## Troubleshooting

### "Not Authenticated" Error

- Ensure your API token is set correctly
- Verify the token has the required permissions
- If using Wrangler, run `wrangler login` and restart the app
- Check that the token hasn't expired

### API Rate Limits

Cloudflare has rate limits on their API. If you see errors:
- The app implements automatic retry logic
- Consider reducing the number of zones being monitored
- Increase the auto-refresh interval if needed

### No Data Showing

- Ensure your zones have firewall events enabled
- Some features require Cloudflare Pro or higher plans
- Check that your API token has Analytics and Security Events permissions
- Verify zones are active and have traffic

### Performance Issues

- Large numbers of zones may take longer to load
- The app caches data to reduce API calls
- Consider filtering to specific zones if you have many zones

## Development

### Project Structure

```
cf-zone-status/
├── CloudflareStatusBarApp.swift    # App entry point
├── AppState.swift                   # App state management
├── CloudflareAPIClient.swift       # API client and networking
├── Models.swift                     # Data models
├── ContentView.swift                # Main content view
├── OverviewView.swift               # Overview tab
├── TopBlocksView.swift              # Top blocks tab
├── IPHitsView.swift                 # IP hits tab
├── DomainHitsView.swift             # Domain hits tab
└── DDOSView.swift                   # DDoS events tab
```

### Adding New Features

1. Add new models in `Models.swift`
2. Implement API calls in `CloudflareAPIClient.swift`
3. Update `AppState.swift` to manage new data
4. Create new views for displaying the data
5. Add navigation in `ContentView.swift`

## Limitations

- Currently uses Firewall Events API which has limitations on historical data
- DDoS detection is simplified (based on high-volume firewall events)
- Domain hits currently show basic information (can be enhanced with GraphQL Analytics API)
- IP geolocation data may not always be available
- Some features require Cloudflare Pro plan or higher

## Download

### Homebrew (Recommended)

```bash
brew tap sheyam/cf-zone-status
brew install --cask cf-zone-status
```

### Manual Download

Download the latest release from [GitHub Releases](https://github.com/sheyam/cf-zone-status/releases).

**Installation:**
1. Download the `.dmg` file
2. Open the DMG
3. Drag `cf-zone-status.app` to Applications
4. First launch: Right-click > Open > Open (to bypass security warning)
5. Configure your API token in Settings (gear icon)

### Building from Source

See [RELEASE.md](RELEASE.md) for detailed build instructions.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Disclaimer

This project is not affiliated with, endorsed by, or sponsored by Cloudflare, Inc. "Cloudflare" is a registered trademark of Cloudflare, Inc.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Release History

See [GitHub Releases](https://github.com/sheyam/cf-zone-status/releases) for version history and changelog.

## Updating

### Homebrew

```bash
brew upgrade --cask cf-zone-status
```

### Manual

Download the latest release from [GitHub Releases](https://github.com/sheyam/cf-zone-status/releases) and replace the app in Applications.

