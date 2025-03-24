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

#define TIMEOUT_SEC 2

struct PseudoHeader
{
    uint32_t source_ip;
    uint32_t dest_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

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

class TCPSYNScanner
{
public:
    TCPSYNScanner(const std::string &target_ip, int target_port) : ip(target_ip), port(target_port) {}
    void scan();

private:
    std::string ip;
    int port;
};

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

    struct timeval timeout = {TIMEOUT_SEC, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    char buffer[1024];
    struct sockaddr_in source_addr;
    socklen_t addr_len = sizeof(source_addr);

    bool response_received = false;
    bool port_open = false;
    bool port_closed = false;

    while (true)
    {
        int recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &addr_len);
        if (recv_len < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (!response_received)
                {
                    // No response, send another packet to verify
                    if (sendto(sock, packet, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
                    {
                        perror("Send failed");
                        close(sock);
                        exit(EXIT_FAILURE);
                    }

                    recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &addr_len);
                    if (recv_len < 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            std::cout << "Port " << port << " on " << ip << " is filtered (no response)\n";
                        }
                        else
                        {
                            perror("Receive failed");
                        }
                    }
                    else
                    {
                        response_received = true;
                    }
                }
                else
                {
                    std::cout << "Port " << port << " on " << ip << " is filtered (no response)\n";
                }
                break;
            }
            else
            {
                perror("Receive failed");
                break;
            }
        }
        else
        {
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

    if (port_open)
    {
        std::cout << "Port " << port << " on " << ip << " is open (SYN-ACK received)\n";
    }
    else if (port_closed)
    {
        std::cout << "Port " << port << " on " << ip << " is closed (RST received)\n";
    }
    else if (!response_received)
    {
        std::cout << "Port " << port << " on " << ip << " is filtered (no response)\n";
    }

    close(sock);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <IP> <port>\n";
        return EXIT_FAILURE;
    }

    std::string ip = argv[1];
    int port = std::atoi(argv[2]);

    TCPSYNScanner scanner(ip, port);
    scanner.scan();

    return EXIT_SUCCESS;
}