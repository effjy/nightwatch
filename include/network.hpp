#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

struct NetworkSocket {
    std::string protocol;
    std::string local_address;
    unsigned int local_port{};
    std::string remote_address;
    unsigned int remote_port{};
    std::string state;
    std::string role;
    std::uint64_t inode{};
    unsigned int uid{};
    unsigned int interface_index{};
};

struct NetworkPattern {
    std::string executable;
    std::string protocol;
    std::string role;
    std::string bind_scope;
    unsigned int local_port{};
    unsigned int remote_port{};

    bool operator<(const NetworkPattern& other) const;
};

std::vector<NetworkSocket> parse_inet_socket_table(
    const std::string& contents, const std::string& protocol, bool ipv6);
std::vector<NetworkSocket> parse_packet_socket_table(const std::string& contents);
NetworkPattern network_pattern(const std::string& executable,
                               const NetworkSocket& socket);
NetworkPattern normalize_network_pattern(NetworkPattern pattern);
bool externally_reachable(const NetworkSocket& socket);
bool ephemeral_wildcard_udp_bind(const NetworkSocket& socket);
bool defer_external_bind_alert(const NetworkSocket& socket,
                               bool executable_trusted);
bool external_bind_persistence_reached(
    std::chrono::steady_clock::duration elapsed);
std::string format_network_endpoint(const std::string& address, unsigned int port);
