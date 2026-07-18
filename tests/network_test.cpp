#include "network.hpp"

#include <iostream>
#include <set>
#include <string>

namespace {
bool expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
    }
    return condition;
}
}  // namespace

int main() {
    bool passed = true;
    const std::string header =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode\n";
    const std::string tcp4 = header +
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 "
        "00:00000000 00000000 1000 0 12345 1\n";
    const auto listeners = parse_inet_socket_table(tcp4, "TCP", false);
    passed &= expect(listeners.size() == 1, "one IPv4 listener should parse");
    if (!listeners.empty()) {
        passed &= expect(listeners[0].local_address == "127.0.0.1" &&
                             listeners[0].local_port == 8080,
                         "IPv4 address and port should decode");
        passed &= expect(listeners[0].role == "listener" &&
                             listeners[0].state == "LISTEN",
                         "TCP state should identify a listener");
        passed &= expect(!externally_reachable(listeners[0]),
                         "loopback listener should not be externally reachable");
    }

    const std::string tcp6 = header +
        "   1: 00000000000000000000000001000000:C001 "
        "00000000000000000000000002000000:01BB 01 "
        "00000000:00000000 00:00000000 00000000 1000 0 54321 1\n";
    const auto connections = parse_inet_socket_table(tcp6, "TCP", true);
    passed &= expect(connections.size() == 1, "one IPv6 connection should parse");
    if (!connections.empty()) {
        passed &= expect(connections[0].local_address == "::1" &&
                             connections[0].remote_address == "::2" &&
                             connections[0].remote_port == 443,
                         "IPv6 endpoints should decode");
        const NetworkPattern first = network_pattern("/usr/bin/client", connections[0]);
        NetworkSocket changed_address = connections[0];
        changed_address.remote_address = "2001:db8::10";
        const NetworkPattern second = network_pattern("/usr/bin/client", changed_address);
        std::set<NetworkPattern> patterns{first, second};
        passed &= expect(patterns.size() == 1,
                         "connected patterns should ignore volatile remote addresses");
        passed &= expect(first.local_port == 0 && first.remote_port == 443,
                         "connected patterns should retain only the service port");
    }

    const std::string udp4 = header +
        "   2: 00000000:14E9 00000000:0000 07 00000000:00000000 "
        "00:00000000 00000000 0 0 77777 1\n";
    const auto bound = parse_inet_socket_table(udp4, "UDP", false);
    passed &= expect(bound.size() == 1 && bound[0].role == "bound" &&
                         externally_reachable(bound[0]),
                     "wildcard UDP bind should be externally reachable");
    if (!bound.empty()) {
        passed &= expect(network_pattern("/usr/bin/service", bound[0]).local_port ==
                             5353,
                         "well-known UDP bind ports should remain exact");
        NetworkSocket ephemeral = bound[0];
        ephemeral.local_port = 54501;
        NetworkSocket another_ephemeral = ephemeral;
        another_ephemeral.local_port = 35412;
        std::set<NetworkPattern> udp_patterns{
            network_pattern("/usr/bin/browser", ephemeral),
            network_pattern("/usr/bin/browser", another_ephemeral)};
        passed &= expect(udp_patterns.size() == 1 &&
                             udp_patterns.begin()->local_port == 0,
                         "ephemeral UDP binds should share one stable pattern");
        passed &= expect(ephemeral_wildcard_udp_bind(ephemeral),
                         "wildcard UDP binds in the ephemeral range should be identified");
        passed &= expect(defer_external_bind_alert(ephemeral, true),
                         "a trusted ephemeral wildcard UDP bind should defer its alert");
        passed &= expect(!defer_external_bind_alert(ephemeral, false),
                         "an unreviewed executable's UDP bind must not be deferred");
        passed &= expect(!defer_external_bind_alert(bound[0], true),
                         "a fixed service-port UDP bind must remain immediately high");
        NetworkSocket loopback_ephemeral = ephemeral;
        loopback_ephemeral.local_address = "127.0.0.1";
        passed &= expect(!defer_external_bind_alert(loopback_ephemeral, true),
                         "a loopback UDP bind is not an external-bind candidate");
        passed &= expect(!external_bind_persistence_reached(
                             std::chrono::milliseconds(4999)),
                         "an ephemeral bind below five seconds should remain deferred");
        passed &= expect(external_bind_persistence_reached(
                             std::chrono::seconds(5)),
                         "an ephemeral bind at five seconds should escalate to high");
    }

    const std::string packet =
        "sk RefCnt Type Proto Iface R Rmem User Inode\n"
        "0000000000000000 3 3 0003 2 1 0 0 88888\n";
    const auto packets = parse_packet_socket_table(packet);
    passed &= expect(packets.size() == 1 && packets[0].role == "packet" &&
                         packets[0].interface_index == 2 && packets[0].inode == 88888,
                     "packet socket attribution fields should parse");

    const auto malformed = parse_inet_socket_table(
        header + "bad truncated line\n", "TCP", false);
    passed &= expect(malformed.empty(), "malformed rows should be ignored safely");

    if (!passed) {
        return 1;
    }
    std::cout << "Network parser and pattern tests passed\n";
    return 0;
}
