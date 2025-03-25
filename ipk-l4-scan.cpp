#include <iostream>
#include <vector>
#include <sstream>
#include <cstring>
#include <thread>
#include <mutex>
#include "tcpscan.h"
#include "udpscan.h"

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
                // int timeout = std::stoi(argv[++i]);
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

    std::vector<std::thread> threads;

    if (!tcp_ports.empty())
    {
        for (int port : tcp_ports)
        {
            threads.emplace_back([target, port]()
                                 {
                TCPSYNScanner scanner(target, port);
                scanner.scan(); });
        }
    }

    if (!udp_ports.empty())
    {
        for (int port : udp_ports)
        {
            threads.emplace_back([target, port]()
                                 {
                UDPScanner scanner(target, port);
                scanner.scan(); });
        }
    }

    for (auto &thread : threads)
    {
        thread.join();
    }

    return EXIT_SUCCESS;
}