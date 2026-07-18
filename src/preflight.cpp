#include "preflight.hpp"

#include "fingerprint.hpp"
#include "helper_runner.hpp"
#include "reviewed.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {
constexpr std::size_t maximum_baseline_size = 16U * 1024U * 1024U;

struct BaselineSummary {
    unsigned int version{0};
    std::string host;
    std::string kernel_release;
    std::map<std::string, ExecutableFingerprint> executables;
    std::size_t persistence_records{0};
};

const char* status_label(PreflightStatus status) {
    switch (status) {
    case PreflightStatus::pass:
        return "PASS";
    case PreflightStatus::warning:
        return "WARN";
    case PreflightStatus::failure:
        return "FAIL";
    }
    return "FAIL";
}

void add(std::vector<PreflightCheck>& checks, PreflightStatus status,
         std::string name, std::string detail) {
    checks.push_back({status, std::move(name), std::move(detail)});
}

std::string current_host() {
    char buffer[256] {};
    if (gethostname(buffer, sizeof(buffer) - 1) != 0) {
        return {};
    }
    return buffer;
}

std::string current_kernel() {
    struct utsname details {};
    if (uname(&details) != 0) {
        return {};
    }
    return details.release;
}

std::string self_path() {
    std::string result(4096, '\0');
    const ssize_t length = readlink("/proc/self/exe", result.data(),
                                    result.size() - 1);
    if (length <= 0) {
        return {};
    }
    result.resize(static_cast<std::size_t>(length));
    return result;
}

std::string read_protected_file(const std::string& path, std::size_t maximum,
                                bool require_root_owner) {
    const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        throw std::runtime_error(std::string("cannot open: ") +
                                 std::strerror(errno));
    }
    struct stat details {};
    if (fstat(descriptor, &details) != 0) {
        const std::string reason = std::strerror(errno);
        close(descriptor);
        throw std::runtime_error("cannot inspect: " + reason);
    }
    if (!S_ISREG(details.st_mode)) {
        close(descriptor);
        throw std::runtime_error("not a regular file");
    }
    if ((details.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(descriptor);
        throw std::runtime_error("writable by group or others");
    }
    if (require_root_owner && details.st_uid != 0) {
        close(descriptor);
        throw std::runtime_error("not owned by root");
    }
    if (details.st_size < 0 ||
        static_cast<std::uint64_t>(details.st_size) > maximum) {
        close(descriptor);
        throw std::runtime_error("unreasonably large");
    }
    std::string contents(static_cast<std::size_t>(details.st_size), '\0');
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const ssize_t count = read(descriptor, contents.data() + offset,
                                   contents.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            const std::string reason =
                count == 0 ? "unexpected end of file" : std::strerror(errno);
            close(descriptor);
            throw std::runtime_error("cannot read: " + reason);
        }
        offset += static_cast<std::size_t>(count);
    }
    close(descriptor);
    return contents;
}

BaselineSummary parse_baseline_summary(const std::string& contents) {
    std::istringstream input(contents);
    std::string header;
    if (!std::getline(input, header) ||
        (header != "NIGHTWATCH_BASELINE 5" &&
         header != "NIGHTWATCH_BASELINE 6")) {
        throw std::runtime_error("baseline format is not version 5 or 6");
    }
    BaselineSummary summary;
    summary.version = header == "NIGHTWATCH_BASELINE 6" ? 6U : 5U;
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string type;
        fields >> type;
        if (type == "host") {
            fields >> std::quoted(summary.host);
        } else if (type == "kernel") {
            std::uint64_t taint = 0;
            int enforcement = 0;
            int bpf = 0;
            std::string lockdown;
            fields >> std::quoted(summary.kernel_release) >> taint >>
                enforcement >> std::quoted(lockdown) >> bpf;
        } else if (type == "executable") {
            std::string path;
            int valid = 0;
            ExecutableFingerprint fingerprint;
            fields >> std::quoted(path) >> valid >> fingerprint.device >>
                fingerprint.inode >> fingerprint.size >>
                fingerprint.modified_nanoseconds >> fingerprint.mode >>
                fingerprint.uid >> fingerprint.gid >>
                std::quoted(fingerprint.sha256);
            fingerprint.valid = valid == 1;
            if (!fields || path.empty() || (valid != 0 && valid != 1) ||
                (valid == 1 && fingerprint.sha256.size() != 64)) {
                throw std::runtime_error(
                    "invalid executable record in baseline");
            }
            summary.executables.emplace(std::move(path),
                                        std::move(fingerprint));
        } else if (type == "persistence") {
            ++summary.persistence_records;
        }
    }
    if (summary.host.empty() || summary.kernel_release.empty()) {
        throw std::runtime_error("baseline lacks host or kernel metadata");
    }
    return summary;
}

std::optional<std::string> secure_executable(const std::string& preferred,
                                             const std::string& fallback = {}) {
    if (validate_helper_executable(preferred).valid) {
        return preferred;
    }
    if (!fallback.empty() && validate_helper_executable(fallback).valid) {
        return fallback;
    }
    return std::nullopt;
}

void inspect_report_directory(const std::string& path,
                              std::vector<PreflightCheck>& checks) {
    std::error_code error;
    const fs::path directory(path);
    if (!fs::exists(directory, error)) {
        fs::path parent = directory.parent_path();
        if (parent.empty()) {
            parent = ".";
        }
        if (!fs::is_directory(parent, error)) {
            add(checks, PreflightStatus::failure, "report directory",
                "does not exist and its parent is unavailable");
            return;
        }
        add(checks, PreflightStatus::warning, "report directory",
            "does not exist yet; Nightwatch will attempt to create it securely");
        return;
    }
    struct stat details {};
    if (stat(directory.c_str(), &details) != 0 || !S_ISDIR(details.st_mode)) {
        add(checks, PreflightStatus::failure, "report directory",
            "is not an accessible directory");
    } else if (geteuid() == 0 &&
               (details.st_uid != 0 ||
                (details.st_mode & (S_IWGRP | S_IWOTH)) != 0)) {
        add(checks, PreflightStatus::failure, "report directory",
            "must be root-owned and not writable by group or others");
    } else if (access(directory.c_str(), W_OK | X_OK) != 0) {
        add(checks, PreflightStatus::failure, "report directory",
            "is not writable and searchable by the current user");
    } else {
        add(checks, PreflightStatus::pass, "report directory",
            "exists with acceptable ownership, permissions, and access");
    }
}
}  // namespace

int preflight_exit_code(const std::vector<PreflightCheck>& checks) {
    bool warning = false;
    for (const PreflightCheck& check : checks) {
        if (check.status == PreflightStatus::failure) {
            return 1;
        }
        warning = warning || check.status == PreflightStatus::warning;
    }
    return warning ? 3 : 0;
}

int run_preflight(const PreflightOptions& options) {
    std::vector<PreflightCheck> checks;
    const bool root = geteuid() == 0;
    add(checks, root ? PreflightStatus::pass : PreflightStatus::warning,
        "privileges",
        root ? "running as root with full intended visibility"
             : "not running as root; process, kernel, BPF, and protected-file "
               "visibility may be incomplete");

    const std::string running_path = self_path();
    const ExecutableFingerprint running =
        fingerprint_file("/proc/self/exe", true);
    if (running_path.empty() || !running.valid) {
        add(checks, PreflightStatus::failure, "running binary",
            "could not resolve and fingerprint /proc/self/exe");
    } else if (root && (running.uid != 0 ||
                        (running.mode & (S_IWGRP | S_IWOTH)) != 0)) {
        add(checks, PreflightStatus::failure, "running binary",
            running_path + " is not root-owned or is writable by group/others");
    } else {
        add(checks, PreflightStatus::pass, "running binary",
            running_path + " has an acceptable ownership and mode");
    }

    try {
        const std::string contents = read_protected_file(
            options.baseline_path, maximum_baseline_size, root);
        const BaselineSummary baseline = parse_baseline_summary(contents);
        const std::string host = current_host();
        if (baseline.host != host) {
            add(checks, PreflightStatus::failure, "baseline host",
                "belongs to " + baseline.host + ", not " + host);
        } else {
            add(checks, PreflightStatus::pass, "baseline host",
                "version " + std::to_string(baseline.version) +
                    " baseline belongs to this host");
        }
        const auto expected = baseline.executables.find(running_path);
        if (expected == baseline.executables.end()) {
            add(checks, PreflightStatus::failure, "baseline binary",
                "does not contain the running path " + running_path);
        } else if (!same_security_fingerprint(expected->second, running)) {
            add(checks, PreflightStatus::failure, "baseline binary",
                "running Nightwatch does not match its calibrated fingerprint");
        } else {
            add(checks, PreflightStatus::pass, "baseline binary",
                "running Nightwatch exactly matches its calibrated fingerprint");
        }
        const std::string kernel = current_kernel();
        if (kernel.empty()) {
            add(checks, PreflightStatus::warning, "kernel release",
                "could not read the running kernel release");
        } else if (kernel != baseline.kernel_release) {
            add(checks, PreflightStatus::failure, "kernel release",
                "baseline has " + baseline.kernel_release +
                    " but the running kernel is " + kernel);
        } else {
            add(checks, PreflightStatus::pass, "kernel release",
                "running kernel matches the baseline");
        }
        if (baseline.version < 6U) {
            add(checks, PreflightStatus::warning, "persistence baseline",
                "baseline predates persistence inventory; recalibrate with "
                "the current build");
        } else {
            add(checks, PreflightStatus::pass, "persistence baseline",
                "version 6 contains " +
                    std::to_string(baseline.persistence_records) +
                    " persistence record(s)");
        }
    } catch (const std::exception& error) {
        add(checks, PreflightStatus::failure, "baseline",
            options.baseline_path + ": " + error.what());
    }

    try {
        const ReviewedExecutableFile reviewed =
            load_reviewed_executables(options.reviewed_path);
        if (!reviewed.loaded) {
            add(checks, PreflightStatus::warning, "reviewed fingerprints",
                "file is absent; reviewed executable/script recognition is disabled");
        } else {
            add(checks, PreflightStatus::pass, "reviewed fingerprints",
                "loaded " + std::to_string(reviewed.entries.size()) +
                    " executable and " + std::to_string(reviewed.scripts.size()) +
                    " script records");
        }
    } catch (const std::exception& error) {
        add(checks, PreflightStatus::failure, "reviewed fingerprints",
            options.reviewed_path + ": " + error.what());
    }

    inspect_report_directory(options.report_directory, checks);

    const auto modinfo = secure_executable("/usr/sbin/modinfo", "/sbin/modinfo");
    add(checks, modinfo ? PreflightStatus::pass : PreflightStatus::failure,
        "helper: modinfo",
        modinfo ? *modinfo + " is root-owned and not group/world-writable"
                : "missing or failed executable ownership/mode validation");
    const auto bpftool = secure_executable("/usr/sbin/bpftool", "/sbin/bpftool");
    add(checks, bpftool ? PreflightStatus::pass : PreflightStatus::failure,
        "helper: bpftool",
        bpftool ? *bpftool + " is root-owned and not group/world-writable"
                : "missing or failed executable ownership/mode validation");
    const auto pwcli = secure_executable("/usr/bin/pw-cli");
    add(checks, pwcli ? PreflightStatus::pass : PreflightStatus::warning,
        "helper: pw-cli",
        pwcli ? *pwcli + " is root-owned and not group/world-writable"
              : "missing or failed validation; PipeWire client attribution "
                "will be unavailable");
    const auto journalctl = secure_executable("/usr/bin/journalctl");
    add(checks, journalctl ? PreflightStatus::pass : PreflightStatus::failure,
        "helper: journalctl",
        journalctl ? *journalctl +
                         " is root-owned and not group/world-writable"
                   : "missing or failed executable ownership/mode validation");
    const auto loginctl = secure_executable("/usr/bin/loginctl");
    add(checks, loginctl ? PreflightStatus::pass : PreflightStatus::failure,
        "helper: loginctl",
        loginctl ? *loginctl + " is root-owned and not group/world-writable"
                 : "missing or failed executable ownership/mode validation");

    if (journalctl) {
        HelperRequest request;
        request.executable = *journalctl;
        request.arguments = {"--lines=0", "--show-cursor", "--no-pager"};
        request.timeout = std::chrono::seconds(3);
        request.maximum_output_bytes = 64U * 1024U;
        const HelperResult probe = run_helper(request);
        const bool cursor = probe.succeeded() &&
            probe.standard_output.find("-- cursor: ") != std::string::npos;
        add(checks, cursor ? PreflightStatus::pass : PreflightStatus::warning,
            "authentication journal access",
            cursor ? "journalctl returned a readable current cursor"
                   : "journal authentication evidence will be degraded: " +
                         (probe.succeeded()
                              ? std::string("no current cursor was returned")
                              : helper_result_summary(probe)));
    } else {
        add(checks, PreflightStatus::warning, "authentication journal access",
            "journal authentication evidence is unavailable without validated "
            "journalctl");
    }

    if (loginctl) {
        HelperRequest request;
        request.executable = *loginctl;
        request.arguments = {"list-sessions", "--no-legend", "--no-pager"};
        request.timeout = std::chrono::seconds(3);
        request.maximum_output_bytes = 256U * 1024U;
        const HelperResult probe = run_helper(request);
        add(checks, probe.succeeded() ? PreflightStatus::pass
                                      : PreflightStatus::warning,
            "login-session state access",
            probe.succeeded()
                ? "loginctl returned current session state"
                : "session start/end and lock-state evidence will be degraded: " +
                      helper_result_summary(probe));
    } else {
        add(checks, PreflightStatus::warning, "login-session state access",
            "session state is unavailable without validated loginctl");
    }

    if (root && bpftool) {
        HelperRequest request;
        request.executable = *bpftool;
        request.arguments = {"prog", "show"};
        request.timeout = std::chrono::seconds(3);
        request.maximum_output_bytes = 16U * 1024U * 1024U;
        const HelperResult probe = run_helper(request);
        std::ifstream bpf("/proc/sys/kernel/unprivileged_bpf_disabled");
        std::string setting;
        std::getline(bpf, setting);
        if (probe.succeeded()) {
            add(checks, PreflightStatus::pass, "BPF inventory access",
                "bpftool prog show completed successfully" +
                    (setting.empty() ? std::string{} :
                     "; unprivileged_bpf_disabled=" + setting));
        } else {
            add(checks, PreflightStatus::warning, "BPF inventory access",
                "bpftool prog show failed; BPF visibility is degraded: " +
                    helper_result_summary(probe));
        }
    } else {
        add(checks, PreflightStatus::warning, "BPF inventory access",
            "BPF inventory cannot be assured without root and validated bpftool");
    }

    std::size_t passed = 0;
    std::size_t warned = 0;
    std::size_t failed = 0;
    std::cout << "Nightwatch preflight\n"
              << "====================\n";
    for (const PreflightCheck& check : checks) {
        std::cout << '[' << status_label(check.status) << "] " << check.name
                  << "\n  " << check.detail << '\n';
        passed += check.status == PreflightStatus::pass ? 1U : 0U;
        warned += check.status == PreflightStatus::warning ? 1U : 0U;
        failed += check.status == PreflightStatus::failure ? 1U : 0U;
    }
    std::cout << "\nSummary: " << passed << " passed, " << warned
              << " warned, " << failed << " failed.\n";
    const int result = preflight_exit_code(checks);
    if (result == 0) {
        std::cout << "Result: READY for an unattended watch.\n";
    } else if (result == 3) {
        std::cout << "Result: DEGRADED; review warnings before an unattended watch.\n";
    } else {
        std::cout << "Result: NOT READY; correct failures before monitoring.\n";
    }
    return result;
}
