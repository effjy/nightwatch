#include "network.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace {
bool parse_hex(const std::string& value, std::uint64_t& result) {
    try {
        std::size_t consumed = 0;
        result = std::stoull(value, &consumed, 16);
        return consumed == value.size();
    } catch (const std::exception&) {
        return false;
    }
}

bool parse_decimal(const std::string& value, std::uint64_t& result) {
    try {
        std::size_t consumed = 0;
        result = std::stoull(value, &consumed, 10);
        return consumed == value.size();
    } catch (const std::exception&) {
        return false;
    }
}

std::string decode_address(const std::string& encoded, bool ipv6) {
    const std::size_t expected = ipv6 ? 32U : 8U;
    if (encoded.size() != expected ||
        !std::all_of(encoded.begin(), encoded.end(), [](unsigned char character) {
            return std::isxdigit(character) != 0;
        })) {
        return {};
    }
    std::array<unsigned char, 16> bytes{};
    const std::size_t words = ipv6 ? 4U : 1U;
    for (std::size_t word = 0; word < words; ++word) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            const std::size_t source = word * 8 + (3 - byte) * 2;
            std::uint64_t value = 0;
            if (!parse_hex(encoded.substr(source, 2), value)) {
                return {};
            }
            bytes[word * 4 + byte] = static_cast<unsigned char>(value);
        }
    }
    std::array<char, INET6_ADDRSTRLEN> output{};
    const int family = ipv6 ? AF_INET6 : AF_INET;
    return inet_ntop(family, bytes.data(), output.data(), output.size()) == nullptr
        ? std::string{}
        : std::string(output.data());
}

bool parse_endpoint(const std::string& encoded, bool ipv6,
                    std::string& address, unsigned int& port) {
    const std::size_t separator = encoded.rfind(':');
    if (separator == std::string::npos) {
        return false;
    }
    address = decode_address(encoded.substr(0, separator), ipv6);
    std::uint64_t parsed_port = 0;
    if (address.empty() || !parse_hex(encoded.substr(separator + 1), parsed_port) ||
        parsed_port > 65535) {
        return false;
    }
    port = static_cast<unsigned int>(parsed_port);
    return true;
}

std::string tcp_state(const std::string& encoded) {
    static const std::array<const char*, 13> names = {
        "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
        "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK",
        "LISTEN", "CLOSING", "NEW_SYN_RECV"
    };
    std::uint64_t value = 0;
    if (!parse_hex(encoded, value) || value >= names.size()) {
        return "UNKNOWN(" + encoded + ")";
    }
    return names[static_cast<std::size_t>(value)];
}

bool unspecified(const std::string& address) {
    return address == "0.0.0.0" || address == "::";
}

bool loopback(const std::string& address) {
    return address == "::1" || address.rfind("127.", 0) == 0;
}

std::pair<unsigned int, unsigned int> ephemeral_port_range() {
    static const std::pair<unsigned int, unsigned int> range = [] {
        std::ifstream input("/proc/sys/net/ipv4/ip_local_port_range");
        unsigned int first = 32768;
        unsigned int last = 60999;
        if (!(input >> first >> last) || first == 0 || first > last || last > 65535) {
            return std::make_pair(32768U, 60999U);
        }
        return std::make_pair(first, last);
    }();
    return range;
}
}  // namespace

bool NetworkPattern::operator<(const NetworkPattern& other) const {
    return std::tie(executable, protocol, role, bind_scope, local_port, remote_port) <
           std::tie(other.executable, other.protocol, other.role, other.bind_scope,
                    other.local_port, other.remote_port);
}

std::vector<NetworkSocket> parse_inet_socket_table(
    const std::string& contents, const std::string& protocol, bool ipv6) {
    std::vector<NetworkSocket> result;
    std::istringstream input(contents);
    std::string line;
    std::getline(input, line);  // column header
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::vector<std::string> values;
        std::string value;
        while (fields >> value) {
            values.push_back(value);
        }
        if (values.size() < 10) {
            continue;
        }
        NetworkSocket socket;
        socket.protocol = protocol + (ipv6 ? "6" : "4");
        if (!parse_endpoint(values[1], ipv6, socket.local_address,
                            socket.local_port) ||
            !parse_endpoint(values[2], ipv6, socket.remote_address,
                            socket.remote_port)) {
            continue;
        }
        std::uint64_t uid = 0;
        if (!parse_decimal(values[7], uid) || uid > 0xffffffffULL ||
            !parse_decimal(values[9], socket.inode)) {
            continue;
        }
        socket.uid = static_cast<unsigned int>(uid);
        if (protocol == "TCP") {
            socket.state = tcp_state(values[3]);
            socket.role = socket.state == "LISTEN" ? "listener" : "connected";
        } else if (protocol == "UDP") {
            socket.state = values[3] == "07" ? "UNCONN" : values[3];
            socket.role = unspecified(socket.remote_address) && socket.remote_port == 0
                ? "bound" : "connected";
        } else {
            socket.state = values[3];
            socket.role = "raw";
        }
        if (socket.inode != 0) {
            result.push_back(std::move(socket));
        }
    }
    return result;
}

NetworkPattern normalize_network_pattern(NetworkPattern pattern) {
    // Browsers and real-time communication clients bind random UDP ports from
    // the kernel's ephemeral range. Preserve the executable, protocol, role,
    // and bind scope, but do not turn each random local port into a new alert.
    if (pattern.protocol.rfind("UDP", 0) == 0 && pattern.role == "bound") {
        const auto [first, last] = ephemeral_port_range();
        if (pattern.local_port >= first && pattern.local_port <= last) {
            pattern.local_port = 0;
        }
    }
    return pattern;
}

std::vector<NetworkSocket> parse_packet_socket_table(const std::string& contents) {
    std::vector<NetworkSocket> result;
    std::istringstream input(contents);
    std::string line;
    std::getline(input, line);
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::vector<std::string> values;
        std::string value;
        while (fields >> value) {
            values.push_back(value);
        }
        if (values.size() < 9) {
            continue;
        }
        std::uint64_t interface_index = 0;
        std::uint64_t uid = 0;
        NetworkSocket socket;
        if (!parse_decimal(values[4], interface_index) ||
            interface_index > 0xffffffffULL ||
            !parse_decimal(values[7], uid) || uid > 0xffffffffULL ||
            !parse_decimal(values[8], socket.inode) || socket.inode == 0) {
            continue;
        }
        socket.protocol = "PACKET";
        socket.role = "packet";
        socket.state = "ACTIVE";
        socket.interface_index = static_cast<unsigned int>(interface_index);
        socket.uid = static_cast<unsigned int>(uid);
        result.push_back(std::move(socket));
    }
    return result;
}

NetworkPattern network_pattern(const std::string& executable,
                               const NetworkSocket& socket) {
    NetworkPattern result;
    result.executable = executable;
    result.protocol = socket.protocol;
    result.role = socket.role;
    if (socket.role == "listener" || socket.role == "bound") {
        result.bind_scope = externally_reachable(socket) ? "external" : "loopback";
        result.local_port = socket.local_port;
    } else if (socket.role == "connected") {
        result.remote_port = socket.remote_port;
    } else if (socket.role == "packet") {
        result.local_port = socket.interface_index;
    } else {
        result.local_port = socket.local_port;
    }
    return normalize_network_pattern(std::move(result));
}

bool externally_reachable(const NetworkSocket& socket) {
    if (socket.role != "listener" && socket.role != "bound") {
        return false;
    }
    return unspecified(socket.local_address) || !loopback(socket.local_address);
}

bool ephemeral_wildcard_udp_bind(const NetworkSocket& socket) {
    if (socket.protocol.rfind("UDP", 0) != 0 || socket.role != "bound" ||
        !unspecified(socket.local_address)) {
        return false;
    }
    const auto [first, last] = ephemeral_port_range();
    return socket.local_port >= first && socket.local_port <= last;
}

bool defer_external_bind_alert(const NetworkSocket& socket,
                               bool executable_trusted) {
    return executable_trusted && ephemeral_wildcard_udp_bind(socket);
}

bool external_bind_persistence_reached(
    std::chrono::steady_clock::duration elapsed) {
    return elapsed >= std::chrono::seconds(5);
}

std::string format_network_endpoint(const std::string& address, unsigned int port) {
    if (address.empty()) {
        return "[none]";
    }
    const bool ipv6 = address.find(':') != std::string::npos;
    return (ipv6 ? "[" + address + "]" : address) + ":" + std::to_string(port);
}
