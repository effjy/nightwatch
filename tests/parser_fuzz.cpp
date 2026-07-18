#include "authentication.hpp"
#include "kernel.hpp"
#include "network.hpp"
#include "script.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

extern "C" void __sanitizer_set_death_callback(void (*callback)(void));

namespace {
constexpr std::size_t MAX_INPUT_SIZE = 8192;
std::uint64_t active_seed = 0;
std::uint64_t active_case = 0;

void sanitizer_death() {
    char message[256]{};
    const int length = std::snprintf(
        message, sizeof(message),
        "\nReproduce with: build/fuzz/parser_fuzz --seed %llu --case %llu\n",
        static_cast<unsigned long long>(active_seed),
        static_cast<unsigned long long>(active_case));
    if (length > 0) {
        const std::size_t count = std::min(
            static_cast<std::size_t>(length), sizeof(message) - 1);
        const ssize_t ignored = write(STDERR_FILENO, message, count);
        (void)ignored;
    }
}

std::uint64_t mix(std::uint64_t value) {
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31U);
}

class Random {
public:
    explicit Random(std::uint64_t seed) : state_(seed == 0 ? 1 : seed) {}

    std::uint64_t next() {
        state_ ^= state_ >> 12U;
        state_ ^= state_ << 25U;
        state_ ^= state_ >> 27U;
        return state_ * 0x2545f4914f6cdd1dULL;
    }

    std::size_t below(std::size_t limit) {
        return limit == 0 ? 0 : static_cast<std::size_t>(next() % limit);
    }

    char byte() {
        return static_cast<char>(next() & 0xffU);
    }

private:
    std::uint64_t state_;
};

std::vector<std::string> seed_inputs() {
    return {
        {},
        "  sl  local_address rem_address st tx_queue rx_queue tr tm->when "
        "retrnsmt uid timeout inode\n"
        "0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 "
        "00:00000000 00000000 1000 0 12345 1\n",
        "  sl  local_address rem_address st tx_queue rx_queue tr tm->when "
        "retrnsmt uid timeout inode\n"
        "1: 00000000000000000000000001000000:C001 "
        "00000000000000000000000002000000:01BB 01 "
        "00000000:00000000 00:00000000 00000000 1000 0 54321 1\n",
        "sk RefCnt Type Proto Iface R Rmem User Inode\n"
        "0000000000000000 3 3 0003 2 1 0 0 88888\n",
        "snd 126976 3 snd_hda_intel,snd_pcm, Live 0x0\n"
        "i915 4325376 41 - Live 0x0\n",
        "filename: /lib/modules/test/example.ko\n"
        "intree: Y\nsigner: Ubuntu key\nvermagic: 7.test SMP\n",
        "none [integrity] confidentiality\n",
        "12: cgroup_device name sd_devices tag abcdef0123456789 gpl\n"
        "\tloaded_at 2026-07-15 uid 0\n\tpids systemd(1)\n"
        "19: tracepoint name burrow_send tag 1111222233334444 gpl\n"
        "\tpids burrow(42)\n",
        std::string(
            "python3\0-u\0/usr/local/libexec/helper\0argument\0",
            sizeof("python3\0-u\0/usr/local/libexec/helper\0argument\0") - 1),
        std::string(1024, 'A'),
        std::string("\0\n\r\t[]{}():/\\\xff\xfe",
                    sizeof("\0\n\r\t[]{}():/\\\xff\xfe") - 1)
    };
}

void insert_random(std::string& input, Random& random) {
    if (input.size() >= MAX_INPUT_SIZE) return;
    const std::size_t count = 1 + random.below(
        std::min<std::size_t>(32, MAX_INPUT_SIZE - input.size()));
    const std::size_t position = random.below(input.size() + 1);
    std::string addition(count, '\0');
    for (char& character : addition) character = random.byte();
    input.insert(position, addition);
}

void mutate(std::string& input, Random& random) {
    const std::size_t rounds = 1 + random.below(12);
    for (std::size_t round = 0; round < rounds; ++round) {
        switch (random.below(7)) {
        case 0:
            if (!input.empty()) input[random.below(input.size())] = random.byte();
            break;
        case 1:
            insert_random(input, random);
            break;
        case 2:
            if (!input.empty()) {
                const std::size_t start = random.below(input.size());
                const std::size_t count = 1 + random.below(input.size() - start);
                input.erase(start, count);
            }
            break;
        case 3:
            if (!input.empty() && input.size() < MAX_INPUT_SIZE) {
                const std::size_t start = random.below(input.size());
                const std::size_t available = std::min(
                    input.size() - start, MAX_INPUT_SIZE - input.size());
                if (available != 0) {
                    const std::size_t count = 1 + random.below(available);
                    input.insert(random.below(input.size() + 1),
                                 input.substr(start, count));
                }
            }
            break;
        case 4:
            if (!input.empty()) input.resize(random.below(input.size() + 1));
            break;
        case 5:
            if (input.size() < MAX_INPUT_SIZE) {
                const char tokens[] = {'\0', '\n', '\r', '\t', ' ', ':', '[',
                                       ']', '(', ')', '/', '\\', '0', 'F'};
                input.insert(random.below(input.size() + 1), 1,
                             tokens[random.below(sizeof(tokens))]);
            }
            break;
        default:
            if (input.size() < MAX_INPUT_SIZE) {
                const std::size_t count = std::min<std::size_t>(
                    1 + random.below(256), MAX_INPUT_SIZE - input.size());
                input.append(count, random.below(2) == 0 ? '0' : 'F');
            }
            break;
        }
    }
}

void consume_network(const std::string& input, std::uint64_t& checksum) {
    for (const bool ipv6 : {false, true}) {
        for (const char* protocol : {"TCP", "UDP", "RAW"}) {
            const auto sockets = parse_inet_socket_table(input, protocol, ipv6);
            checksum += sockets.size();
            for (const NetworkSocket& socket : sockets) {
                const NetworkPattern pattern = network_pattern("/fuzz/subject", socket);
                checksum += pattern.local_port + pattern.remote_port;
                checksum += externally_reachable(socket) ? 1U : 0U;
                checksum += ephemeral_wildcard_udp_bind(socket) ? 1U : 0U;
                checksum += defer_external_bind_alert(socket, true) ? 1U : 0U;
                checksum += format_network_endpoint(
                    socket.local_address, socket.local_port).size();
            }
        }
    }
    const auto packets = parse_packet_socket_table(input);
    checksum += packets.size();
    for (const NetworkSocket& socket : packets) {
        checksum += network_pattern("/fuzz/packet", socket).local_port;
    }
}

void consume_kernel(const std::string& input, std::uint64_t& checksum) {
    const auto modules = parse_loaded_modules(input);
    const KernelModule info = parse_modinfo("fuzz", input);
    const auto batched_info = parse_modinfo_batch(input);
    const std::string lockdown = parse_lockdown_mode(input);
    const auto programs = parse_bpftool_programs(input);
    checksum += modules.size() + batched_info.size() + programs.size() +
                lockdown.size();
    checksum += info.path.size() + info.signer.size() + info.version_magic.size();

    KernelSnapshot baseline;
    baseline.posture = {"fuzz", 0, true, "integrity"};
    baseline.bpf_available = true;
    baseline.bpf_programs = programs;
    KernelSnapshot current = baseline;
    current.bpf_programs.insert(
        BpfProgram{"fuzz", input.substr(0, 64), "0123456789abcdef", {}});
    checksum += compare_kernel_snapshots(baseline, current).size();
}

void consume_script(const std::string& input, Random& random,
                    std::uint64_t& checksum) {
    const std::vector<std::string> arguments = split_process_arguments(input);
    static const std::vector<std::string> interpreters{
        "/usr/bin/python3.12", "/usr/bin/bash", "/usr/bin/perl5.40",
        "/usr/bin/ruby3.2", "/usr/bin/node", "/usr/bin/php8.3",
        "/usr/bin/lua5.4", "/usr/bin/not-an-interpreter"
    };
    const std::string& executable = interpreters[random.below(interpreters.size())];
    const std::string working_directory = random.below(3) == 0
        ? std::string("relative") : std::string("/fuzz/root");
    const std::optional<std::string> script = find_script_entrypoint(
        executable, arguments, working_directory);
    checksum += arguments.size();
    if (script) checksum += script->size();
}

void consume_authentication(const std::string& input,
                            std::uint64_t& checksum) {
    const AuthenticationJournalParse journal =
        parse_authentication_journal(input, 32);
    checksum += journal.events.size() + journal.cursor.size() +
                journal.malformed_lines + (journal.truncated ? 1U : 0U);
    for (const AuthenticationEvent& event : journal.events) {
        checksum += authentication_event_summary(event).size();
    }
    const LoginSessionListParse sessions = parse_login_session_list(input, 32);
    checksum += sessions.session_ids.size() + sessions.malformed_lines +
                (sessions.truncated ? 1U : 0U);
    LoginSession session;
    std::string error;
    checksum += parse_login_session_properties(input, session, error)
                    ? session.id.size() + session.user.size()
                    : error.size();
    checksum += parse_journal_cursor(input).size();
}

std::uint64_t parse_number(const char* value, const char* option) {
    if (value == nullptr || *value == '\0' || *value == '-') {
        throw std::runtime_error(std::string("invalid value for ") + option);
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(value, &end, 0);
    if (errno != 0 || end == value || *end != '\0') {
        throw std::runtime_error(std::string("invalid value for ") + option);
    }
    return static_cast<std::uint64_t>(parsed);
}

struct Options {
    std::uint64_t seed{0x4e49474854574154ULL};
    std::uint64_t iterations{50000};
    std::optional<std::uint64_t> one_case;
};

Options options(int argc, char** argv) {
    Options result;
    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        if ((argument == "--seed" || argument == "--iterations" ||
             argument == "--case") && index + 1 < argc) {
            const std::uint64_t value = parse_number(argv[++index], argument.c_str());
            if (argument == "--seed") result.seed = value;
            else if (argument == "--iterations") result.iterations = value;
            else result.one_case = value;
        } else {
            throw std::runtime_error(
                "usage: parser_fuzz [--seed N] [--iterations N] [--case N]");
        }
    }
    if (result.iterations == 0 || result.iterations > 5000000ULL) {
        throw std::runtime_error("iterations must be between 1 and 5000000");
    }
    return result;
}

void run_case(std::uint64_t seed, std::uint64_t number,
              const std::vector<std::string>& seeds,
              std::uint64_t& checksum) {
    active_seed = seed;
    active_case = number;
    Random random(mix(seed ^ mix(number)));
    std::string input = seeds[random.below(seeds.size())];
    mutate(input, random);
    consume_network(input, checksum);
    consume_kernel(input, checksum);
    consume_script(input, random, checksum);
    consume_authentication(input, checksum);
}
}

int main(int argc, char** argv) {
    try {
        __sanitizer_set_death_callback(sanitizer_death);
        const Options selected = options(argc, argv);
        const std::vector<std::string> seeds = seed_inputs();
        std::uint64_t checksum = 0;
        if (selected.one_case) {
            run_case(selected.seed, *selected.one_case, seeds, checksum);
            std::cout << "Parser fuzz case passed: seed=" << selected.seed
                      << " case=" << *selected.one_case
                      << " checksum=" << checksum << '\n';
            return 0;
        }
        for (std::uint64_t iteration = 0; iteration < selected.iterations;
             ++iteration) {
            run_case(selected.seed, iteration, seeds, checksum);
        }
        std::cout << "Parser fuzz campaign passed: seed=" << selected.seed
                  << " cases=" << selected.iterations
                  << " maximum_input=" << MAX_INPUT_SIZE
                  << " checksum=" << checksum << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Parser fuzz failure: " << error.what() << '\n'
                  << "Reproduce with: build/fuzz/parser_fuzz --seed "
                  << active_seed << " --case " << active_case << '\n';
        return 1;
    }
}
