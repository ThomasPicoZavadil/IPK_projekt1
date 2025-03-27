#include "tcpscan.h"
#include "common.h"
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <mutex>
#include <ifaddrs.h>
#include <net/if.h>

// Function to calculate the checksum for TCP packets
uint16_t checksum(void *data, int len)
{
    uint16_t *ptr = (uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }
    if (len)
    {
        sum += *(uint8_t *)ptr;
    }
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

// Constructor for the TCPSYNScanner class
TCPSYNScanner::TCPSYNScanner(const std::string &target_ip, int target_port, int timeout_ms, const std::string &interface)
    : ip(target_ip), port(target_port), timeout_ms(timeout_ms), interface(interface) {}

// Function to perform the TCP SYN scan
void TCPSYNScanner::scan()
{
    // Create a raw socket for sending TCP packets
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
        perror("Raw socket creation failed (need root privileges?)");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to a specific network interface if provided
    if (!interface.empty())
    {
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), interface.size()) < 0)
        {
            perror("Binding to interface failed");
            close(sock);
            exit(EXIT_FAILURE);
        }
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
        close(sock);
        exit(EXIT_FAILURE);
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
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Retrieve the source IP address of the temporary socket
    if (getsockname(temp_sock, (struct sockaddr *)&source_addr, &addr_len) < 0)
    {
        perror("Failed to get source IP address");
        close(temp_sock);
        close(sock);
        exit(EXIT_FAILURE);
    }

    close(temp_sock); // Close the temporary socket

    // Convert the source IP address to a string
    char source_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &source_addr.sin_addr, source_ip, sizeof(source_ip));

    // Set up the destination address for the scan
    struct sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);

    // Create the TCP SYN packet
    char packet[40];
    memset(packet, 0, sizeof(packet));

    struct tcphdr *tcp = (struct tcphdr *)(packet);
    tcp->source = htons(rand() % 65535); // Random source port
    tcp->dest = htons(port);             // Target port
    tcp->seq = htonl(0);                 // Sequence number
    tcp->syn = 1;                        // SYN flag
    tcp->doff = 5;                       // Data offset
    tcp->window = htons(1024);           // Window size

    // Create the pseudo-header for checksum calculation
    struct PseudoHeader pseudo{};
    inet_pton(AF_INET, source_ip, &pseudo.source_ip); // Use dynamically determined source IP
    pseudo.dest_ip = dest_addr.sin_addr.s_addr;
    pseudo.reserved = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_length = htons(sizeof(struct tcphdr));

    // Calculate the checksum
    char checksum_buffer[60];
    memset(checksum_buffer, 0, sizeof(checksum_buffer));
    memcpy(checksum_buffer, &pseudo, sizeof(PseudoHeader));
    memcpy(checksum_buffer + sizeof(PseudoHeader), tcp, sizeof(struct tcphdr));
    tcp->check = checksum(checksum_buffer, sizeof(PseudoHeader) + sizeof(struct tcphdr));

    // Send the TCP SYN packet
    if (sendto(sock, packet, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
    {
        perror("Send failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Set up for receiving responses
    fd_set readfds;
    struct timeval timeout_val;
    timeout_val.tv_sec = timeout_ms / 1000;
    timeout_val.tv_usec = (timeout_ms % 1000) * 1000;

    char buffer[1024];
    struct sockaddr_in recv_source_addr;
    socklen_t recv_addr_len = sizeof(recv_source_addr);

    bool response_received = false;
    bool port_open = false;
    bool port_closed = false;
    bool port_filtered = false;
    int sent_counter = 0;

    // Wait for responses or timeout
    while (true)
    {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        int select_result = select(sock + 1, &readfds, NULL, NULL, &timeout_val);
        if (select_result < 0)
        {
            perror("Select failed");
            break;
        }
        else if (select_result == 0)
        {
            // Timeout occurred
            if (!response_received && sent_counter < 1)
            {
                // Resend the packet if no response was received
                if (sendto(sock, packet, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
                {
                    perror("Send failed");
                    close(sock);
                    exit(EXIT_FAILURE);
                }
                sent_counter++;
                timeout_val.tv_sec = timeout_ms / 1000;
                timeout_val.tv_usec = (timeout_ms % 1000) * 1000;
                continue;
            }
            else if (sent_counter >= 1)
            {
                port_filtered = true;
                break;
            }
            else
            {
                std::lock_guard<std::mutex> lock(print_mutex);
                std::cout << ip << " " << port << " tcp" << " filtered\n";
                break;
            }
        }
        else
        {
            // Packet received
            int recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_source_addr, &recv_addr_len);
            if (recv_len < 0)
            {
                perror("Receive failed");
                break;
            }

            struct iphdr *ip_header = (struct iphdr *)buffer;
            struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ihl * 4));

            char recv_source_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &recv_source_addr.sin_addr, recv_source_ip, sizeof(recv_source_ip));

            // Check if the response matches the target IP and port
            if (ip == recv_source_ip && ntohs(tcp_header->source) == port)
            {
                if (tcp_header->syn && tcp_header->ack)
                {
                    port_open = true;
                }
                else if (tcp_header->rst)
                {
                    port_closed = true;
                }
                response_received = true;
                break;
            }
        }
    }

    // Print the result based on the response
    {
        std::lock_guard<std::mutex> lock(print_mutex);
        if (port_open)
        {
            std::cout << ip << " " << port << " tcp" << " open\n";
        }
        else if (port_closed)
        {
            std::cout << ip << " " << port << " tcp" << " closed\n";
        }
        else if (port_filtered)
        {
            std::cout << ip << " " << port << " tcp" << " filtered\n";
        }
    }

    close(sock); // Close the raw socket
}