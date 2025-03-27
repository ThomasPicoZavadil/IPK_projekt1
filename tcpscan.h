#ifndef TCPSCAN_H
#define TCPSCAN_H

#include <cstdint>
#include <string>

// Structure representing a pseudo-header for TCP checksum calculation
// This is used to calculate the checksum for the TCP header and data
struct PseudoHeader
{
    uint32_t source_ip;  // Source IP address
    uint32_t dest_ip;    // Destination IP address
    uint8_t reserved;    // Reserved field (must be 0)
    uint8_t protocol;    // Protocol type (e.g., TCP)
    uint16_t tcp_length; // Length of the TCP header and data
};

// Function to calculate the checksum for TCP packets
// Takes a pointer to the data and its length as input
uint16_t checksum(void *data, int len);

// Class representing a TCP SYN scanner
// This class is responsible for performing TCP SYN scans on a target
class TCPSYNScanner
{
public:
    // Constructor to initialize the scanner with target details
    // Parameters:
    // - target_ip: The IP address of the target
    // - target_port: The port to scan
    // - timeout_ms: Timeout for responses in milliseconds
    // - interface: The network interface to use for scanning
    TCPSYNScanner(const std::string &target_ip, int target_port, int timeout_ms, const std::string &interface);

    // Function to perform the TCP SYN scan
    void scan();

private:
    std::string ip;        // Target IP address
    int port;              // Target port
    int timeout_ms;        // Timeout for responses in milliseconds
    std::string interface; // Network interface to use for scanning
};

#endif // TCPSCAN_H