#include "udpscan.h"
#include "common.h"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <mutex>
#include <ifaddrs.h>
#include <net/if.h>

#define TIMEOUT_SEC 2 // Timeout for receiving ICMP responses in seconds

// Constructor for the UDPScanner class
// Initializes the target IP, port, and network interface
UDPScanner::UDPScanner(const std::string &ip, int port, const std::string &interface)
    : ip_address(ip), port(port), interface(interface) {}

// Function to send a UDP packet to the target
bool UDPScanner::send_udp_packet()
{
    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);

    // Convert the target IP address from string to binary form
    if (inet_pton(AF_INET, ip_address.c_str(), &dest_addr.sin_addr) <= 0)
    {
        perror("Invalid address/Address not supported");
        return false;
    }

    // Dynamically determine the source IP address
    struct sockaddr_in source_addr{};
    socklen_t addr_len = sizeof(source_addr);
    memset(&source_addr, 0, sizeof(source_addr));

    // Create a temporary UDP socket to determine the source IP
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_sock < 0)
    {
        perror("Temporary socket creation failed");
        return false;
    }

    // Connect to a public IP to determine the source IP
    struct sockaddr_in temp_dest{};
    temp_dest.sin_family = AF_INET;
    temp_dest.sin_port = htons(80);                     // Arbitrary port
    inet_pton(AF_INET, "8.8.8.8", &temp_dest.sin_addr); // Public DNS server

    if (connect(temp_sock, (struct sockaddr *)&temp_dest, sizeof(temp_dest)) < 0)
    {
        perror("Temporary socket connection failed");
        close(temp_sock);
        return false;
    }

    // Retrieve the source IP address of the temporary socket
    if (getsockname(temp_sock, (struct sockaddr *)&source_addr, &addr_len) < 0)
    {
        perror("Failed to get source IP address");
        close(temp_sock);
        return false;
    }

    close(temp_sock); // Close the temporary socket

    // Convert the source IP address to a string for debugging purposes
    char source_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &source_addr.sin_addr, source_ip, sizeof(source_ip));

    // Create a UDP socket for sending the packet
    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock < 0)
    {
        perror("UDP socket creation failed");
        return false;
    }

    // Bind the socket to a specific network interface if provided
    if (!interface.empty())
    {
        if (setsockopt(udp_sock, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), interface.size()) < 0)
        {
            perror("Binding to interface failed");
            close(udp_sock);
            return false;
        }
    }

    // Send an empty UDP packet to the target
    if (sendto(udp_sock, nullptr, 0, 0, reinterpret_cast<struct sockaddr *>(&dest_addr), sizeof(dest_addr)) < 0)
    {
        perror("Send failed");
        close(udp_sock);
        return false;
    }

    close(udp_sock); // Close the UDP socket
    return true;
}

// Function to listen for ICMP responses after sending a UDP packet
void UDPScanner::listen_for_icmp()
{
    // Create a raw socket to listen for ICMP responses
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0)
    {
        perror("Raw socket creation failed (need root privileges?)");
        return;
    }

    // Bind the socket to a specific network interface if provided
    if (!interface.empty())
    {
        if (setsockopt(icmp_sock, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), interface.size()) < 0)
        {
            perror("Binding to interface failed");
            close(icmp_sock);
            return;
        }
    }

    // Set a timeout for receiving ICMP responses
    timeval timeout{TIMEOUT_SEC, 0};
    setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    char buffer[1024]; // Buffer to store received packets
    sockaddr_in source_addr{};
    socklen_t addr_len = sizeof(source_addr);

    // Receive an ICMP response
    int recv_len = recvfrom(icmp_sock, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&source_addr), &addr_len);
    close(icmp_sock); // Close the ICMP socket

    if (recv_len < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // Timeout occurred, assume the port is open
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << ip_address << " " << port << " udp" << " open\n";
        }
        else
        {
            perror("Receive failed");
        }
    }
    else
    {
        // Parse the received ICMP packet
        auto *ip_header = reinterpret_cast<struct iphdr *>(buffer);
        int ip_header_length = ip_header->ihl * 4;

        // Ensure the packet is large enough to contain an ICMP header
        if (recv_len < ip_header_length + static_cast<int>(sizeof(struct icmphdr)))
        {
            std::cerr << "Received packet too short to contain ICMP header\n";
            return;
        }

        auto *icmp_header = reinterpret_cast<struct icmphdr *>(buffer + ip_header_length);

        // Lock the mutex to ensure thread-safe printing
        std::lock_guard<std::mutex> lock(print_mutex);
        if (icmp_header->type == 3 && icmp_header->code == 3)
        {
            // ICMP Type 3, Code 3 indicates the port is closed
            std::cout << ip_address << " " << port << " udp" << " closed\n";
        }
        else
        {
            // Handle unexpected ICMP responses
            std::cout << "Received unexpected ICMP response (Type: " << icmp_header->type << ", Code: " << icmp_header->code << ")\n";
        }
    }
}

// Function to perform the UDP scan
void UDPScanner::scan()
{
    // Send a UDP packet and listen for ICMP responses
    if (send_udp_packet())
    {
        listen_for_icmp();
    }
}