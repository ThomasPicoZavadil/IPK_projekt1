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

TCPSYNScanner::TCPSYNScanner(const std::string &target_ip, int target_port, int timeout_ms) : ip(target_ip), port(target_port), timeout_ms(timeout_ms) {}

void TCPSYNScanner::scan()
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0)
    {
        perror("Raw socket creation failed (need root privileges?)");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);

    char packet[40];
    memset(packet, 0, sizeof(packet));

    struct tcphdr *tcp = (struct tcphdr *)(packet);
    tcp->source = htons(rand() % 65535);
    tcp->dest = htons(port);
    tcp->seq = htonl(0);
    tcp->syn = 1;
    tcp->doff = 5;
    tcp->window = htons(1024);

    struct PseudoHeader pseudo{};
    inet_pton(AF_INET, "172.21.41.54", &pseudo.source_ip); // Change this to your actual source IP
    pseudo.dest_ip = dest_addr.sin_addr.s_addr;
    pseudo.reserved = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_length = htons(sizeof(struct tcphdr));

    char checksum_buffer[60];
    memset(checksum_buffer, 0, sizeof(checksum_buffer));
    memcpy(checksum_buffer, &pseudo, sizeof(PseudoHeader));
    memcpy(checksum_buffer + sizeof(PseudoHeader), tcp, sizeof(struct tcphdr));

    tcp->check = checksum(checksum_buffer, sizeof(PseudoHeader) + sizeof(struct tcphdr));

    if (sendto(sock, packet, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
    {
        perror("Send failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    fd_set readfds;
    struct timeval timeout_val;
    timeout_val.tv_sec = timeout_ms / 1000;
    timeout_val.tv_usec = (timeout_ms % 1000) * 1000;

    char buffer[1024];
    struct sockaddr_in source_addr;
    socklen_t addr_len = sizeof(source_addr);

    bool response_received = false;
    bool port_open = false;
    bool port_closed = false;
    bool port_filtered = false;
    int sent_counter = 0;

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
            if (!response_received && sent_counter < 1)
            {
                // No response, send another packet to verify
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
            int recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &addr_len);
            if (recv_len < 0)
            {
                perror("Receive failed");
                break;
            }

            struct iphdr *ip_header = (struct iphdr *)buffer;
            struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ihl * 4));

            char source_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &source_addr.sin_addr, source_ip, sizeof(source_ip));

            if (ip == source_ip && ntohs(tcp_header->source) == port)
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

    close(sock);
}