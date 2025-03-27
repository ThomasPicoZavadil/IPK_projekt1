#include <iostream>
#include <vector>
#include <sstream>
#include <cstring>
#include <thread>
#include <mutex>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "tcpscan.h"
#include "udpscan.h"
#define TIMEOUT_MS 5000 // Default timeout in milliseconds

std::mutex print_mutex; // Mutex to ensure thread-safe printing

// Function to parse port ranges (e.g., "80,443,1000-2000") into a vector of integers
void parse_port_ranges(const std::string &range_str, std::vector<int> &ports)
{
    std::stringstream ss(range_str);
    std::string token;
    while (std::getline(ss, token, ','))
    {
        size_t dash_pos = token.find('-');
        if (dash_pos != std::string::npos)
        {
            // Handle range (e.g., "1000-2000")
            int start = std::stoi(token.substr(0, dash_pos));
            int end = std::stoi(token.substr(dash_pos + 1));
            for (int port = start; port <= end; ++port)
            {
                ports.push_back(port);
            }
        }
        else
        {
            // Handle single port (e.g., "80")
            ports.push_back(std::stoi(token));
        }
    }
}

// Function to resolve a domain name to an IPv4 address
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

// Function to list all active network interfaces
void list_active_interfaces()
{
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    std::cout << "Active interfaces:\n";
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == nullptr)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            std::cout << ifa->ifa_name << "\n";
        }
    }

    freeifaddrs(ifaddr);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        // If no arguments are provided, list active interfaces
        list_active_interfaces();
        return EXIT_FAILURE;
    }

    std::vector<int> tcp_ports; // Vector to store TCP ports to scan
    std::vector<int> udp_ports; // Vector to store UDP ports to scan
    std::string target;         // Target hostname or IP address
    std::string interface;      // Network interface to use for scanning
    int timeout = TIMEOUT_MS;   // Timeout for responses in milliseconds

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            // Print usage instructions and terminate
            std::cout << "Usage: " << argv[0] << " [-i interface | --interface interface] [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-w timeout} [hostname | ip-address]\n";
            std::cout << "\nOptions:\n";
            std::cout << "  -h, --help           Show this help message and exit\n";
            std::cout << "  -i, --interface      Specify the network interface to use for scanning\n";
            std::cout << "  --pu, -u             Specify UDP port ranges to scan (e.g., 53,80-100)\n";
            std::cout << "  --pt, -t             Specify TCP port ranges to scan (e.g., 22,443-445)\n";
            std::cout << "  -w, --wait           Specify timeout in milliseconds for responses\n";
            std::cout << "  hostname | ip-address Target hostname or IP address to scan\n";
            return EXIT_SUCCESS;
        }
        else if (strcmp(argv[i], "--pu") == 0 || strcmp(argv[i], "-u") == 0)
        {
            // Parse UDP port ranges
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
            // Parse TCP port ranges
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
        else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--wait") == 0)
        {
            // Parse timeout value
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
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0)
        {
            // Parse network interface
            if (i + 1 >= argc || argv[i + 1][0] == '-')
            {
                list_active_interfaces();
                return EXIT_FAILURE;
            }
            else
            {
                interface = argv[++i];
            }
        }
        else
        {
            // Assume the argument is the target hostname or IP address
            target = argv[i];
        }
    }

    // Check if no port ranges were specified
    if (tcp_ports.empty() && udp_ports.empty())
    {
        std::cerr << "Error: No port ranges specified. Use -t/--pt for TCP ports or -u/--pu for UDP ports\n";
        return EXIT_FAILURE;
    }

    if (target.empty())
    {
        // If no target is specified, show an error
        std::cerr << "Error: Missing target hostname or IP address\n";
        return EXIT_FAILURE;
    }

    // Resolve the target hostname to an IP address
    std::string ip_address = resolve_domain(target);

    std::vector<std::thread> threads; // Vector to store threads for parallel scanning

    // Launch TCP scanning threads
    if (!tcp_ports.empty())
    {
        for (int port : tcp_ports)
        {
            threads.emplace_back([ip_address, port, timeout, interface]()
                                 {
                TCPSYNScanner scanner(ip_address, port, timeout, interface);
                scanner.scan(); });
        }
    }

    // Launch UDP scanning threads
    if (!udp_ports.empty())
    {
        for (int port : udp_ports)
        {
            threads.emplace_back([ip_address, port, interface]()
                                 {
                UDPScanner scanner(ip_address, port, interface);
                scanner.scan(); });
        }
    }

    // Wait for all threads to complete
    for (auto &thread : threads)
    {
        thread.join();
    }

    return EXIT_SUCCESS;
}