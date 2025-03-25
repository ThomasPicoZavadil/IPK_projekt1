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

#define TIMEOUT_SEC 2

UDPScanner::UDPScanner(const std::string &ip, int port) : ip_address(ip), port(port) {}

bool UDPScanner::send_udp_packet()
{
    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_address.c_str(), &dest_addr.sin_addr) <= 0)
    {
        perror("Invalid address/Address not supported");
        return false;
    }

    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock < 0)
    {
        perror("UDP socket creation failed");
        return false;
    }

    if (sendto(udp_sock, nullptr, 0, 0, reinterpret_cast<struct sockaddr *>(&dest_addr), sizeof(dest_addr)) < 0)
    {
        perror("Send failed");
        close(udp_sock);
        return false;
    }

    close(udp_sock);
    return true;
}

void UDPScanner::listen_for_icmp()
{
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0)
    {
        perror("Raw socket creation failed (need root privileges?)");
        return;
    }

    timeval timeout{TIMEOUT_SEC, 0};
    setsockopt(icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    char buffer[1024];
    sockaddr_in source_addr{};
    socklen_t addr_len = sizeof(source_addr);
    int recv_len = recvfrom(icmp_sock, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&source_addr), &addr_len);
    close(icmp_sock);

    if (recv_len < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
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
        auto *ip_header = reinterpret_cast<struct iphdr *>(buffer);
        int ip_header_length = ip_header->ihl * 4;

        if (recv_len < ip_header_length + static_cast<int>(sizeof(struct icmphdr)))
        {
            std::cerr << "Received packet too short to contain ICMP header\n";
            return;
        }

        auto *icmp_header = reinterpret_cast<struct icmphdr *>(buffer + ip_header_length);

        std::lock_guard<std::mutex> lock(print_mutex);
        if (icmp_header->type == 3 && icmp_header->code == 3)
        {
            std::cout << ip_address << " " << port << " udp" << " closed\n";
        }
        else
        {
            std::cout << "Received unexpected ICMP response (Type: " << icmp_header->type << ", Code: " << icmp_header->code << ")\n";
        }
    }
}

void UDPScanner::scan()
{
    if (send_udp_packet())
    {
        listen_for_icmp();
    }
}