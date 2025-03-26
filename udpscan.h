#ifndef UDPSCAN_H
#define UDPSCAN_H

#include <string>

class UDPScanner
{
public:
    UDPScanner(const std::string &ip, int port, const std::string &interface);
    void scan();

private:
    bool send_udp_packet();
    void listen_for_icmp();

    std::string ip_address;
    int port;
    std::string interface;
};

#endif // UDPSCAN_H