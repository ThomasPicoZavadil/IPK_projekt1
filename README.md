# README - IPK Layer 4 Scanner

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Application Overview](#application-overview)
3. [Code Structure and Explanation](#code-structure-and-explanation)
4. [Testing](#testing)
5. [Extra Features](#extra-features)
6. [Bibliography](#bibliography)

---

## Executive Summary

This project implements a Layer 4 network scanner capable of scanning TCP and UDP ports on a target host. The scanner uses raw sockets to send TCP SYN packets and UDP packets to specified ports and listens for responses to determine the state of the ports. For TCP if the scanner recieves response SYN-ACK the port is marked as open, if it recieves RST response, the port is marked as closed and if the scanner doesn't recieve a response after a set period of time, another packet is sent for verification and then the port is marked as filtered. For UDP if the scanner recieves ICMP response type 3, code 3 the port is marked as closed, if there is no response, the port is marked as open. The application supports scanning through a specific network interface and resolving domain names to IP addresses.

The scanner is implemented in C++ and requires root privileges to run due to the use of raw sockets. It provides functionality similar to tools like `nmap`, but with a focus on simplicity and educational purposes.

---

## Application Overview

### Features
- **TCP SYN Scanning**: Sends TCP SYN packets to target ports and determines if the port is open, closed, or filtered based on the response.
- **UDP Scanning**: Sends UDP packets to target ports and listens for ICMP responses to determine the port state.
- **Interface Binding**: Allows scanning through a specific network interface using the `-i` or `--interface` option.
- **Domain Name Resolution**: Resolves domain names to IP addresses for scanning.
- **Timeout Configuration**: Allows specifying a timeout for responses in milliseconds using the `-w` or `--wait` option.
- **Active Interface Listing**: Lists active network interfaces if no parameters are provided or if the interface option is specified without a value.

### Usage
```bash
sudo ./ipk-l4-scan [-i interface | --interface interface] [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-w timeout} [hostname | ip-address]
```

### Requirements
- **Operating System**: Linux
- **Compiler**: GCC with C++20 support
- **Privileges**: Root privileges are required to use raw sockets.

---

## Code Structure and Explanation

### File Structure
- **`ipk-l4-scan.cpp`**: Main entry point of the application. Handles argument parsing, domain resolution, and thread management for scanning.
- **`tcpscan.cpp` and `tcpscan.h`**: Implements the TCP SYN scanning functionality.
- **`udpscan.cpp` and `udpscan.h`**: Implements the UDP scanning functionality.
- **`common.h`**: Contains shared resources like the `print_mutex`.
- **`Makefile`**: Build script for compiling the application.

### Interesting Code Sections
#### 1. **Interface Binding**
The application binds sockets to a specific interface using the `SO_BINDTODEVICE` socket option. This ensures that packets are sent and received through the specified interface.

```cpp
if (!interface.empty())
{
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface.c_str(), interface.size()) < 0)
    {
        perror("Binding to interface failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
}
```

#### 2. **Domain Name Resolution**
The `resolve_domain` function converts a domain name into an IPv4 address using the `getaddrinfo` and `inet_ntop` functions.

```cpp
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
```

#### 3. **Sending and Receiving TCP Packets**
The TCP scanner sends a TCP SYN packet to the target port and waits for a response. Based on the response, it determines whether the port is open, closed, or filtered.

**Sending TCP SYN Packet**:
```cpp
if (sendto(sock, packet, sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
{
    perror("Send failed");
    close(sock);
    exit(EXIT_FAILURE);
}
```

**Receiving TCP Response**:
```cpp
int recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_source_addr, &recv_addr_len);
if (recv_len < 0)
{
    perror("Receive failed");
    break;
}

struct iphdr *ip_header = (struct iphdr *)buffer;
struct tcphdr *tcp_header = (struct tcphdr *)(buffer + (ip_header->ihl * 4));

if (tcp_header->syn && tcp_header->ack)
{
    port_open = true;
}
else if (tcp_header->rst)
{
    port_closed = true;
}
```

#### 4. **Sending and Receiving UDP Packets**
The UDP scanner sends an empty UDP packet to the target port and listens for ICMP responses to determine the port state.

**Sending UDP Packet**:
```cpp
if (sendto(udp_sock, nullptr, 0, 0, reinterpret_cast<struct sockaddr *>(&dest_addr), sizeof(dest_addr)) < 0)
{
    perror("Send failed");
    close(udp_sock);
    return false;
}
```

**Receiving ICMP Response**:
```cpp
int recv_len = recvfrom(icmp_sock, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&source_addr), &addr_len);
if (recv_len < 0)
{
    if (errno == EAGAIN || errno == EWOULDBLOCK)
    {
        std::cout << ip_address << " " << port << " udp" << " open\n";
    }
    else
    {
        perror("Receive failed");
    }
}
else
{
    auto *icmp_header = reinterpret_cast<struct icmphdr *>(buffer + ip_header_length);
    if (icmp_header->type == 3 && icmp_header->code == 3)
    {
        std::cout << ip_address << " " << port << " udp" << " closed\n";
    }
}
```

---

## Testing


### Testing Environment
- **Operating System**: Ubuntu 22.04 LTS
- **Hardware**: Intel Core i5, 8GB RAM
- **Network Setup**: Single machine with a loopback interface and an Ethernet interface (`eth0`).

### Test Cases
All of the tests were done manually, correctness of these tests was verified by using Wireshark.
#### 1. **Listing Active Interfaces**
These tests were done to confirm listing of active interfaces in cases where the `-i` or `--interface` options aren't specified, or all other arguments aren't provided.
- **Commands**: `sudo ./ipk-l4-scan`, `sudo ./ipk-l4-scan --interface --pt 90 1.1.1.1`
- **Expected Output**:
```bash
Active interfaces:
lo
eth0
```
- **Actual Output**: Matches the expected output.

#### 2. **TCP Port Scanning**
- **Command**: `sudo ./ipk-l4-scan --interface eth0 --pt 80 8.8.8.8`
- **Expected Output**:
```bash
8.8.8.8 80 tcp filtered     #if no response was recieved
```
- **Actual Output**: Matches the expected output.

#### 3. **Multiple TCP Port Scanning**
- **Commands**:`sudo ./ipk-l4-scan --interface eth0 --pt 80,81,82,83,84,85 1.1.1.1`, `sudo ./ipk-l4-scan --interface eth0 --pt 80-85 1.1.1.1`
- **Expected Output**:
```bash
1.1.1.1 80 tcp open
1.1.1.1 85 tcp filtered
1.1.1.1 83 tcp filtered
1.1.1.1 81 tcp filtered
1.1.1.1 84 tcp filtered
1.1.1.1 82 tcp filtered
```
- **Actual Output**: Matches the expected output.

#### 4. **UDP Port Scanning**
- **Command**: `sudo ./ipk-l4-scan --interface eth0 --pu 80 8.8.8.8`
- **Expected Output**:
```bash
8.8.8.8 80 udp open     #if no ICMP response
```
- **Actual Output**: Matches the expected output.

#### 5. **Multiple UDP Port Scanning**
- **Commands**:`sudo ./ipk-l4-scan --interface eth0 --pu 80,81,82,83,84,85 1.1.1.1`, `sudo ./ipk-l4-scan --interface eth0 --pu 80-85 1.1.1.1`
- **Expected Output**:
```bash
1.1.1.1 83 udp open
1.1.1.1 84 udp open
1.1.1.1 81 udp open
1.1.1.1 80 udp open
1.1.1.1 85 udp open
1.1.1.1 82 udp open
```
- **Actual Output**: Matches the expected output.

### 6. Edge Cases
- **Command options**: Invalid IP address, Missing IP address, Missing port argument, Port argument not specified, Timeout argument not specified.
- **Expected Outputs (for each case)**:
```
Error: Missing target hostname or IP address
Error: Unable to resolve domain name <Domain_name>
Error: No port ranges specified. Use -t/--pt for TCP ports or -u/--pu for UDP ports
Error: Missing port ranges for <IP_address>
Error: Missing timeout value for -w
```
- **Actual Output**: Matches the expected output, except when the invalid argument is located right before IP address, then the error for missing IP addres is displayed.

---

## Extra Features
- **Threaded Scanning**: Uses multithreading to scan multiple ports simultaneously for better performance.

---

## Bibliography
1. **Linux Man Pages**:
   - `man 7 raw`
   - `man 3 getaddrinfo`
   - `man 3 inet_ntop`
   - `man 3 getifaddrs`
2. **RFC 793**: Transmission Control Protocol Specification.
3. **RFC 768**: User Datagram Protocol Specification.
