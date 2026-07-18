#include "monitor.hpp"
#include "paths.hpp"
#include "preflight.hpp"

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
volatile std::sig_atomic_t stop_requested = 0;

extern "C" void handle_signal(int) {
    stop_requested = 1;
}

void usage(const char* program) {
    std::cout
        << "Usage:\n"
        << "  " << program << " [monitor] [OPTIONS]\n"
        << "  " << program << " calibrate [OPTIONS]\n"
        << "  " << program << " preflight [OPTIONS]\n\n"
        << "Options:\n"
        << "  --interval SECONDS       Sampling interval (default: 1)\n"
        << "  --report-dir DIRECTORY   Report directory (default: "
        << nightwatch_paths::report_directory << ")\n"
        << "  --baseline FILE          Baseline file (default: "
        << nightwatch_paths::baseline << ")\n"
        << "  --reviewed FILE          Reviewed fingerprints (default: "
        << nightwatch_paths::reviewed_fingerprints << ")\n"
        << "  --idle-seconds SECONDS   Idle calibration length (default: 120)\n"
        << "  --media-seconds SECONDS  Media calibration length (default: 30)\n";
}

void validate_privileged_binary() {
    if (geteuid() != 0) {
        return;
    }
    struct stat details {};
    if (stat("/proc/self/exe", &details) != 0) {
        throw std::runtime_error("cannot verify the running executable");
    }
    if (details.st_uid != 0 || (details.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        throw std::runtime_error(
            "refusing to run as root from a non-root-owned or writable binary; "
            "run 'sudo make install' and use " +
            std::string(nightwatch_paths::executable));
    }
}
}  // namespace

int main(int argc, char** argv) {
    unsigned int interval = 1;
    unsigned int idle_seconds = 120;
    unsigned int media_seconds = 30;
    std::string report_directory(nightwatch_paths::report_directory);
    std::string baseline_path(nightwatch_paths::baseline);
    std::string reviewed_path(nightwatch_paths::reviewed_fingerprints);
    std::string command = "monitor";

    int first_option = 1;
    if (argc > 1 && std::string(argv[1]) == "calibrate") {
        command = "calibrate";
        first_option = 2;
    } else if (argc > 1 && std::string(argv[1]) == "preflight") {
        command = "preflight";
        first_option = 2;
    } else if (argc > 1 && std::string(argv[1]) == "monitor") {
        first_option = 2;
    }

    auto parse_seconds = [](const char* value, const char* label,
                            unsigned int maximum) -> unsigned int {
        try {
            std::size_t consumed = 0;
            const std::string input(value);
            const unsigned long parsed = std::stoul(input, &consumed);
            if (consumed != input.size() || parsed == 0 || parsed > maximum) {
                throw std::out_of_range(label);
            }
            return static_cast<unsigned int>(parsed);
        } catch (const std::exception&) {
            throw std::invalid_argument(std::string("Invalid ") + label);
        }
    };

    for (int index = first_option; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--help" || argument == "-h") {
            usage(argv[0]);
            return 0;
        }
        if (argument == "--interval" && index + 1 < argc) {
            try {
                interval = parse_seconds(argv[++index], "interval", 3600);
            } catch (const std::exception&) {
                std::cerr << "Invalid interval; choose 1 to 3600 seconds.\n";
                return 2;
            }
            continue;
        }
        if (argument == "--report-dir" && index + 1 < argc) {
            report_directory = argv[++index];
            continue;
        }
        if (argument == "--baseline" && index + 1 < argc) {
            baseline_path = argv[++index];
            continue;
        }
        if (argument == "--reviewed" && index + 1 < argc) {
            reviewed_path = argv[++index];
            continue;
        }
        if (argument == "--idle-seconds" && index + 1 < argc) {
            try {
                idle_seconds = parse_seconds(argv[++index], "idle duration", 86400);
            } catch (const std::exception&) {
                std::cerr << "Invalid idle duration; choose 1 to 86400 seconds.\n";
                return 2;
            }
            continue;
        }
        if (argument == "--media-seconds" && index + 1 < argc) {
            try {
                media_seconds = parse_seconds(argv[++index], "media duration", 3600);
            } catch (const std::exception&) {
                std::cerr << "Invalid media duration; choose 1 to 3600 seconds.\n";
                return 2;
            }
            continue;
        }
        std::cerr << "Unknown or incomplete argument: " << argument << '\n';
        usage(argv[0]);
        return 2;
    }

    struct sigaction action {};
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(SIGINT, &action, nullptr) != 0 ||
        sigaction(SIGTERM, &action, nullptr) != 0 ||
        sigaction(SIGHUP, &action, nullptr) != 0) {
        std::cerr << "Unable to install shutdown signal handlers.\n";
        return 1;
    }

    try {
        validate_privileged_binary();
        if (command == "preflight") {
            return run_preflight(
                {baseline_path, reviewed_path, report_directory});
        }
        Monitor monitor(interval, report_directory, baseline_path, reviewed_path);
        if (command == "calibrate") {
            return monitor.calibrate(idle_seconds, media_seconds, stop_requested);
        }
        return monitor.run(stop_requested);
    } catch (const std::exception& error) {
        std::cerr << "nightwatch: " << error.what() << '\n';
        return 1;
    }
}
