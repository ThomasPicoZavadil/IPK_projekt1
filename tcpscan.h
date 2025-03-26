#ifndef TCPSCAN_H
#define TCPSCAN_H

#include <cstdint>
#include <string>

struct PseudoHeader
{
    uint32_t source_ip;
    uint32_t dest_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t checksum(void *data, int len);

class TCPSYNScanner
{
public:
    TCPSYNScanner(const std::string &target_ip, int target_port, int timeout_ms, const std::string &interface);
    void scan();

private:
    std::string ip;
    int port;
    int timeout_ms;
    std::string interface;
};

#endif // TCPSCAN_H