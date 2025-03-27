# CHANGELOG

## Version 1.0.0 - Initial Release

### Implemented Functionality
- **TCP SYN Scanning**:
  - Sends TCP SYN packets to target ports.
  - Determines port states as `open`, `closed`, or `filtered` based on responses (SYN-ACK, RST, or no response).
- **UDP Scanning**:
  - Sends empty UDP packets to target ports.
  - Determines port states as `open` or `closed` based on ICMP responses (Type 3, Code 3) or lack of response.
- **Interface Binding**:
  - Allows scanning through a specific network interface using the `-i` or `--interface` option.
- **Domain Name Resolution**:
  - Resolves domain names to IPv4 addresses for scanning.
- **Timeout Configuration**:
  - Allows specifying a timeout for responses in milliseconds using the `-w` or `--wait` option.
- **Active Interface Listing**:
  - Lists active network interfaces if no parameters are provided or if the interface option is specified without a value.
- **Multithreaded Scanning**:
  - Scans multiple ports simultaneously using threads for better performance.

### Known Limitations
- **IPv4 Only**:
  - The application currently supports only IPv4 addresses. IPv6 is not implemented.
- **Firewall and Network Restrictions**:
  - Ports may be incorrectly marked as `filtered` if firewalls or network configurations block responses.
- **Limited Error Handling**:
  - Some edge cases (e.g., malformed packets or unexpected network behavior) may not be handled gracefully.
