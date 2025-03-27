#ifndef UDPSCAN_H
#define UDPSCAN_H

#include <string>

// Class representing a UDP scanner
// This class is responsible for performing UDP scans on a target
class UDPScanner
{
public:
    // Constructor to initialize the scanner with target details
    // Parameters:
    // - ip: The IP address of the target
    // - port: The port to scan
    // - interface: The network interface to use for scanning
    UDPScanner(const std::string &ip, int port, const std::string &interface);

    // Function to perform the UDP scan
    void scan();

private:
    // Function to send a UDP packet to the target
    // Returns true if the packet was sent successfully, false otherwise
    bool send_udp_packet();

    // Function to listen for ICMP responses after sending a UDP packet
    void listen_for_icmp();

    std::string ip_address; // Target IP address
    int port;               // Target port
    std::string interface;  // Network interface to use for scanning
};

#endif // UDPSCAN_H