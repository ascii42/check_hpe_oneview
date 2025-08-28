# check_hpe_oneview


[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-bash-green.svg)](https://www.gnu.org/software/bash/)
[![Monitoring](https://img.shields.io/badge/Monitoring-Icinga%2FNagios-blue.svg)](https://icinga.com/)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)](CHANGELOG.md)

Icinga/Nagios plugin to monitor HPE OneView infrastructure via REST API

## Description

This plugin provides comprehensive monitoring of HPE OneView managed infrastructure, with specialized support for HPE Synergy enclosures. It monitors all physical components including servers, power supplies, fans, interconnects, and management modules through the OneView REST API.

## Features

- **Comprehensive Component Monitoring**: All physical components (servers, power supplies, fans, interconnects, management modules)
- **Flexible Resource Types**: Servers, enclosures, interconnects, storage systems, networks
- **Advanced Filtering**: Include/exclude resources by name patterns or status (wildcards, regex)
- **Performance Data**: Extended performance data for trending and graphing
- **Auto-Discovery**: Automatic OneView connection detection and port discovery
- **Proxy Support**: Enterprise proxy configuration support
- **Debug Mode**: Detailed API interaction logging

## Requirements

- `curl` and `jq` utilities
- HPE OneView REST API v2000+ compatibility
- Network connectivity to OneView appliance (HTTPS)
- Valid OneView credentials with infrastructure read permissions

## Installation

```bash
git clone https://github.com/ascii42/check_hpe_oneview.git
cd check_hpe_oneview
chmod +x check_hpe_oneview.sh

# Install dependencies
# Debian/Ubuntu:
sudo apt-get install curl jq
# RHEL/CentOS:
sudo yum install curl jq
```

## Usage

### Basic Usage

```bash
# Monitor all servers
./check_hpe_oneview.sh -H oneview.example.com -u admin -p password

# Monitor specific server with verbose output
./check_hpe_oneview.sh -H oneview.example.com -u admin -p password -S "Server-001" -v -d

# Comprehensive enclosure monitoring (all components)
./check_hpe_oneview.sh -H oneview.example.com -u admin -p password -E -v
```

### Advanced Examples

```bash
# Monitor enclosures only
./check_hpe_oneview.sh -H oneview.example.com -u admin -p password -t enclosures -v

# Filter servers by wildcard pattern
./check_hpe_oneview.sh -H oneview.example.com -u admin -p password -S "SY-480-*" -v

# Include only specific resources with performance data
./check_hpe_oneview.sh -H oneview.example.com -u admin -p password -i "Server-*" -P

# Use proxy for corporate environments
./check_hpe_oneview.sh -H oneview.example.com -u admin -p password --proxy http://proxy:8080

# Debug mode for troubleshooting
./check_hpe_oneview.sh -H oneview.example.com -u admin -p password -E -D
```

## Command Line Options

### Required Parameters
- `-H, --host` - HPE OneView appliance hostname/IP
- `-u, --username` - Username for OneView authentication  
- `-p, --password` - Password for OneView authentication

### Monitoring Options
- `-S, --server-name` - Filter by specific server name pattern
- `-E, --enclosure-mode` - Enable comprehensive enclosure/frame mode
- `-t, --resource-type` - Resource type to check (default: server-hardware)
- `-v, --verbose` - Show individual resource status
- `-d, --detail` - Show resource details/description (requires --verbose)

### Performance Data
- `-P, --perfdata` - Include extended performance data in output
- `-O, --perfdata-only` - Show only performance data (no status message)
- `-j, --include-perfdata` - Include ONLY these resources in performance data
- `-g, --exclude-perfdata` - Exclude these resources from performance data

### Filtering Options
- `-i, --include` - Include ONLY resources matching name patterns
- `-I, --include-status` - Include ONLY resources matching status patterns
- `-e, --exclude` - Exclude resources by name (comma-separated patterns)
- `--exclude-status` - Exclude resources by status (comma-separated patterns)

### Connection Options
- `-V, --verify-tls` - Verify TLS certificates (default: false)
- `--timeout` - Connection timeout in seconds (default: 30)
- `--api-version` - OneView API version (default: 2000)
- `--port` - OneView HTTPS port (default: auto-detect)
- `--auto-discover` - Automatically discover OneView connection settings

### Proxy Options
- `--use-proxy` - Enable proxy settings (default: proxy is disabled)
- `--proxy` - Use specific proxy (format: http://proxy:port)

### Debug Options
- `-D, --debug` - Show detailed debug information

## Resource Types

| Type | Description |
|------|-------------|
| `server-hardware` | Physical servers (default) |
| `enclosures` | Synergy enclosures/frames |
| `interconnects` | Network interconnects |
| `logical-interconnects` | Logical interconnects |
| `storage-systems` | Storage systems |
| `storage-pools` | Storage pools |
| `networks` | Networks |
| `power-devices` | Power devices |

## Pattern Matching

The plugin supports flexible pattern matching:

- **Exact names**: `"Server-001"`
- **Wildcards**: `"Server-*"`, `"SY-480-*"`
- **Regex**: `"/^Server-[0-9]+$/"`

## Comprehensive Enclosure Mode

When using `-E` (enclosure mode), the plugin monitors all physical components:

- **Enclosure**: Frame chassis
- **Compute Modules**: Synergy compute nodes
- **Power Supplies**: Individual PSU units with serial numbers
- **Cooling Fans**: Fan modules with status
- **Management Modules**: Frame Link Modules, Synergy Composers
- **Interconnects**: Network switches and logical interconnects
- **Network Sets**: VLAN groups and network configurations

## Icinga/Nagios Integration

### Command Definition

```ini
# Icinga2 Command Definition
object CheckCommand "check_hpe_oneview" {
    import "plugin-check-command"
    command = [ PluginDir + "/check_hpe_oneview.sh" ]
    
    arguments = {
        "-H" = "$oneview_host$"
        "-u" = "$oneview_username$"
        "-p" = "$oneview_password$"
        "-S" = "$oneview_server_filter$"
        "-E" = {
            set_if = "$oneview_enclosure_mode$"
        }
        "-t" = "$oneview_resource_type$"
        "-v" = {
            set_if = "$oneview_verbose$"
        }
        "-d" = {
            set_if = "$oneview_detail$"
        }
        "-P" = {
            set_if = "$oneview_perfdata$"
        }
        "--timeout" = "$oneview_timeout$"
    }
}
```

### Service Definition

```ini
# Individual Server Monitoring
apply Service "HPE-Server-" for (server in host.vars.oneview_servers) {
    import "generic-service"
    check_command = "check_hpe_oneview"
    vars.oneview_host = host.vars.oneview_appliance
    vars.oneview_username = host.vars.oneview_user
    vars.oneview_password = host.vars.oneview_pass
    vars.oneview_server_filter = server
    vars.oneview_verbose = true
    vars.oneview_detail = true
    assign where host.vars.oneview_servers
}

# Comprehensive Enclosure Monitoring
apply Service "HPE-Enclosure-All-Components" {
    import "generic-service"
    check_command = "check_hpe_oneview"
    vars.oneview_host = host.vars.oneview_appliance
    vars.oneview_username = host.vars.oneview_user
    vars.oneview_password = host.vars.oneview_pass
    vars.oneview_enclosure_mode = true
    vars.oneview_verbose = true
    vars.oneview_detail = true
    vars.oneview_perfdata = true
    assign where host.vars.oneview_enclosure_monitoring
}
```

### Host Variables

```ini
object Host "synergy-frame-001" {
    import "generic-host"
    address = "172.16.1.10"
    vars.oneview_appliance = "oneview.company.com"
    vars.oneview_user = "monitoring"
    vars.oneview_pass = "secure_password"
    vars.oneview_enclosure_monitoring = true
    vars.oneview_servers = [ "SY-480-Gen10-001", "SY-480-Gen10-002" ]
}
```

## Output Examples

### Normal Operation
```
[OK] - All 35 enclosure components (comprehensive mode) OK (OneView) | total=35 ok=35 warning=0 critical=0 unknown=0
```

### Verbose Output
```
[OK] - All 35 enclosure components (comprehensive mode) OK (OneView) | total=35 ok=35 warning=0 critical=0 unknown=0
[OK]: CZJC2D1234 (OK) - S/N: CZJC2D1234,Type: enclosures
[OK]: CZJC2D1234, bay 1 (OK) - Model: Synergy 480 Gen11,S/N: CZJD1V00WY,Power: On,Type: server-hardware
[OK]: CZJC2D1234 Power Supply 1 (OK) - Model: HPE 2200W Flex Slot Titanium Hot Plug Power Supply,S/N: 5YCHT0B4DJX5G9,Type: power-supply-bays
[OK]: CZJC2D1234 Fan 1 (OK) - Model: HPE Synergy 12000 HC Fan,S/N: 7C64264180,Type: fan-bays
...
```

### Warning/Critical States
```
[WARNING] - 1 warning enclosure components (comprehensive mode) (OneView) | total=35 ok=34 warning=1 critical=0 unknown=0
[WARNING]: CZJC2D1234 Power Supply 3 (Degraded) - Model: HPE 2200W Flex Slot Titanium Hot Plug Power Supply,S/N: 5YCHT0B4DJX5DJ,Type: power-supply-bays
```

## Status Mapping

| OneView Status | Plugin Status | Exit Code |
|----------------|---------------|-----------|
| OK, Normal, Connected, Configured | OK | 0 |
| Warning, Degraded, Minor | WARNING | 1 |
| Critical, Error, Failed, Disconnected, Major | CRITICAL | 2 |
| Unknown, Other | UNKNOWN | 3 |

## Troubleshooting

### Common Issues

**Authentication Failed**
```
UNKNOWN - Authentication failed: Invalid username or password
```
- Verify credentials
- Check user permissions in OneView
- Ensure user has infrastructure read access

**Connection Issues**
```
UNKNOWN - Cannot establish connection to OneView: hostname
```
- Use `--auto-discover` for automatic port detection
- Try specifying `--port 8443` manually
- Check network connectivity and firewall rules

**API Version Mismatch**
```
UNKNOWN - Bad request: Check API version (current: 2000)
```
- Try different API versions: `--api-version 1800` or `--api-version 2400`
- Check your OneView version compatibility

**Proxy Issues**
```bash
# Disable proxy (default)
./check_hpe_oneview.sh -H oneview.company.com -u admin -p password

# Use corporate proxy
./check_hpe_oneview.sh -H oneview.company.com -u admin -p password --proxy http://proxy.company.com:8080
```

### Debug Mode

Enable debug mode to see detailed API interactions:

```bash
./check_hpe_oneview.sh -H oneview.company.com -u admin -p password -E -D
```

## Performance Data

The plugin provides comprehensive performance data when using `-P` or `-O`:

```
total=35 ok=35 warning=0 critical=0 unknown=0 Server-001=0;status=OK;power=On Fan-1=0;status=OK Power-Supply-1=0;status=OK
```

This data can be used with tools like:
- Grafana with InfluxDB
- PNP4Nagios
- Nagiosgraph

## Security Considerations

- Store credentials securely (use encrypted storage or environment variables)
- Use dedicated monitoring service accounts with minimal privileges
- Enable TLS verification in production: `-V`
- Consider certificate-based authentication where supported
- Implement proper access controls for the monitoring system

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-08-24 | Initial release with comprehensive Synergy support |

## Author

**Felix Longardt**  
GitHub: [@ascii42](https://github.com/ascii42)

## Related Projects

- [check_vmware_cve](https://github.com/ascii42/check_vmware_cve) - VMware CVE monitoring plugin

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License.

## Support

- **Issues**: Report bugs and feature requests via [GitHub Issues](https://github.com/ascii42/check_hpe_oneview/issues)
- **Discussions**: Use [GitHub Discussions](https://github.com/ascii42/check_hpe_oneview/discussions) for questions
- **Documentation**: Include debug output (`-D`) when reporting issues
