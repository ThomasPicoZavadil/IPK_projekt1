#include <iostream>
#include <vector>
#include <sstream>
#include <cstring>
#include <thread>
#include <mutex>
#include <netdb.h>
#include <arpa/inet.h>
#include "tcpscan.h"
#include "udpscan.h"
#define TIMEOUT_MS 5000 // Default timeout in milliseconds

std::mutex print_mutex;

void parse_port_ranges(const std::string &range_str, std::vector<int> &ports)
{
    std::stringstream ss(range_str);
    std::string token;
    while (std::getline(ss, token, ','))
    {
        size_t dash_pos = token.find('-');
        if (dash_pos != std::string::npos)
        {
            int start = std::stoi(token.substr(0, dash_pos));
            int end = std::stoi(token.substr(dash_pos + 1));
            for (int port = start; port <= end; ++port)
            {
                ports.push_back(port);
            }
        }
        else
        {
            ports.push_back(std::stoi(token));
        }
    }
}

std::string resolve_domain(const std::string &domain)
{
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    if (getaddrinfo(domain.c_str(), nullptr, &hints, &res) != 0)
    {
        std::cerr << "Error: Unable to resolve domain name " << domain << "\n";
        exit(EXIT_FAILURE);
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ip_str, sizeof(ip_str));
    freeaddrinfo(res);

    return std::string(ip_str);
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        std::cerr << "Usage: " << argv[0] << " [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-w timeout} [hostname | ip-address]\n";
        return EXIT_FAILURE;
    }

    std::vector<int> tcp_ports;
    std::vector<int> udp_ports;
    std::string target;
    int timeout = TIMEOUT_MS; // Default timeout in milliseconds

    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "--pu") == 0 || strcmp(argv[i], "-u") == 0)
        {
            if (i + 1 < argc)
            {
                parse_port_ranges(argv[++i], udp_ports);
            }
            else
            {
                std::cerr << "Error: Missing port ranges for " << argv[i - 1] << "\n";
                return EXIT_FAILURE;
            }
        }
        else if (strcmp(argv[i], "--pt") == 0 || strcmp(argv[i], "-t") == 0)
        {
            if (i + 1 < argc)
            {
                parse_port_ranges(argv[++i], tcp_ports);
            }
            else
            {
                std::cerr << "Error: Missing port ranges for " << argv[i - 1] << "\n";
                return EXIT_FAILURE;
            }
        }
        else if (strcmp(argv[i], "-w") == 0)
        {
            if (i + 1 < argc)
            {
                timeout = std::stoi(argv[++i]);
            }
            else
            {
                std::cerr << "Error: Missing timeout value for -w\n";
                return EXIT_FAILURE;
            }
        }
        else
        {
            target = argv[i];
        }
    }

    if (target.empty())
    {
        std::cerr << "Error: Missing target hostname or IP address\n";
        return EXIT_FAILURE;
    }

    std::string ip_address = resolve_domain(target);

    std::vector<std::thread> threads;

    if (!tcp_ports.empty())
    {
        for (int port : tcp_ports)
        {
            threads.emplace_back([ip_address, port, timeout]()
                                 {
                TCPSYNScanner scanner(ip_address, port, timeout);
                scanner.scan(); });
        }
    }

    if (!udp_ports.empty())
    {
        for (int port : udp_ports)
        {
            threads.emplace_back([ip_address, port]()
                                 {
                UDPScanner scanner(ip_address, port);
                scanner.scan(); });
        }
    }

    for (auto &thread : threads)
    {
        thread.join();
    }

    return EXIT_SUCCESS;
}