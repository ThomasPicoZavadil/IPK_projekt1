#ifndef UDPSCAN_H
#define UDPSCAN_H

#include <string>

class UDPScanner
{
public:
    UDPScanner(const std::string &ip, int port);
    void scan();

private:
    bool send_udp_packet();
    void listen_for_icmp();

    std::string ip_address;
    int port;
};

#endif // UDPSCAN_H