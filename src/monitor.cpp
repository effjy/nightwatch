#include "monitor.hpp"
#include "assurance_json.hpp"
#include "helper_runner.hpp"
#include "script.hpp"
#include "sha256.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <dirent.h>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <grp.h>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits.h>
#include <limits>
#include <pwd.h>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {
std::string read_file(const fs::path& path, bool replace_nul = false) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }
    std::ostringstream output;
    output << input.rdbuf();
    std::string result = output.str();
    if (replace_nul) {
        std::replace(result.begin(), result.end(), '\0', ' ');
        while (!result.empty() && result.back() == ' ') {
            result.pop_back();
        }
    }
    return result;
}

std::string read_link(const fs::path& path) {
    std::error_code error;
    const fs::path result = fs::read_symlink(path, error);
    return error ? std::string{} : result.string();
}

bool numeric_name(const char* value) {
    if (*value == '\0') {
        return false;
    }
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
    }
    return true;
}

std::uint64_t process_start_ticks(const fs::path& stat_path) {
    const std::string contents = read_file(stat_path);
    const std::size_t end_name = contents.rfind(')');
    if (end_name == std::string::npos || end_name + 2 >= contents.size()) {
        return 0;
    }
    std::istringstream fields(contents.substr(end_name + 2));
    std::string value;
    for (int field = 3; field <= 22; ++field) {
        if (!(fields >> value)) {
            return 0;
        }
        if (field == 22) {
            try {
                return std::stoull(value);
            } catch (const std::exception&) {
                return 0;
            }
        }
    }
    return 0;
}

std::string user_name(unsigned int uid) {
    const passwd* entry = getpwuid(static_cast<uid_t>(uid));
    return entry == nullptr ? std::to_string(uid) : entry->pw_name;
}

std::string host_name() {
    char buffer[HOST_NAME_MAX + 1]{};
    return gethostname(buffer, sizeof(buffer)) == 0 ? buffer : "unknown";
}

std::string kernel_name() {
    utsname details{};
    if (uname(&details) != 0) {
        return "unknown";
    }
    return std::string(details.sysname) + " " + details.release + " " + details.machine;
}

std::string process_label(const ProcessInfo& process) {
    std::ostringstream output;
    output << "PID " << process.pid << " (user " << user_name(process.uid)
           << ", executable "
           << (process.executable.empty() ? "[unavailable]" : process.executable) << ')';
    return output.str();
}

std::string script_label(const ProcessInfo& process) {
    return process_label(process) + " invoked script " +
           (process.script_entrypoint.empty() ? "[unavailable]" :
                                                process.script_entrypoint);
}

std::string network_label(const NetworkEvent& event) {
    std::ostringstream output;
    output << event.socket.protocol << ' ' << event.socket.role << " socket "
           << format_network_endpoint(event.socket.local_address,
                                      event.socket.local_port);
    if (event.socket.role == "connected") {
        output << " -> " << format_network_endpoint(event.socket.remote_address,
                                                     event.socket.remote_port);
    } else if (event.socket.role == "packet") {
        output << " on interface index " << event.socket.interface_index;
    }
    output << " (state " << event.socket.state << ") held by PID " << event.pid
           << " (user " << user_name(event.uid) << ", executable "
           << (event.executable.empty() ? "[unavailable]" : event.executable) << ')';
    return output.str();
}

bool unusual_location(const std::string& executable) {
    static const std::vector<std::string> prefixes = {
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"
    };
    return std::any_of(prefixes.begin(), prefixes.end(), [&](const std::string& prefix) {
        return executable.rfind(prefix, 0) == 0;
    });
}

std::string media_identity(const std::string& executable, const std::string& device) {
    return executable + "\n" + device;
}

std::string pipewire_identity(const PipeWireCapture& capture) {
    return std::to_string(capture.uid) + "\n" + capture.executable + "\n" +
           capture.application + "\n" + capture.media_class + "\n" + capture.node_name;
}

bool capture_device(const std::string& device) {
    if (device.rfind("/dev/video", 0) == 0) {
        return true;
    }
    const std::size_t pcm = device.find("/dev/snd/pcm");
    return pcm == 0 && !device.empty() && device.back() == 'c';
}

std::string trim(std::string value) {
    const std::size_t first = value.find_first_not_of(" \t\r\n*");
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string quoted_property(const std::string& line, const std::string& key) {
    const std::string marker = key + " = \"";
    const std::size_t start = line.find(marker);
    if (start == std::string::npos) {
        return {};
    }
    const std::size_t value_start = start + marker.size();
    const std::size_t end = line.find('"', value_start);
    return end == std::string::npos ? std::string{} :
                                     line.substr(value_start, end - value_start);
}

unsigned int pipewire_user() {
    if (const char* sudo_uid = std::getenv("SUDO_UID")) {
        try {
            return static_cast<unsigned int>(std::stoul(sudo_uid));
        } catch (const std::exception&) {
        }
    }
    if (geteuid() != 0) {
        return static_cast<unsigned int>(geteuid());
    }
    std::error_code error;
    for (fs::directory_iterator it("/run/user", error), end; !error && it != end;
         it.increment(error)) {
        const std::string name = it->path().filename().string();
        if (!name.empty() && std::all_of(name.begin(), name.end(), [](unsigned char value) {
                return std::isdigit(value) != 0;
            }) &&
            fs::exists(it->path() / "pipewire-0")) {
            try {
                return static_cast<unsigned int>(std::stoul(name));
            } catch (const std::exception&) {
            }
        }
    }
    return std::numeric_limits<unsigned int>::max();
}

HelperResult run_pipewire_info(unsigned int uid) {
    HelperResult unavailable;
    unavailable.status = HelperStatus::validation_failed;
    if (uid == std::numeric_limits<unsigned int>::max() ||
        !fs::exists("/usr/bin/pw-cli")) {
        unavailable.error = "PipeWire user or /usr/bin/pw-cli is unavailable";
        return unavailable;
    }
    const passwd* account = getpwuid(static_cast<uid_t>(uid));
    if (account == nullptr) {
        unavailable.error = "PipeWire user account is unavailable";
        return unavailable;
    }
    const std::string user = account->pw_name;
    const std::string home = account->pw_dir;
    const gid_t gid = account->pw_gid;
    const std::string runtime = "/run/user/" + std::to_string(uid);
    if (!fs::exists(fs::path(runtime) / "pipewire-0")) {
        unavailable.error = "PipeWire runtime socket is unavailable";
        return unavailable;
    }
    HelperRequest request;
    request.executable = "/usr/bin/pw-cli";
    request.arguments = {"info", "all"};
    request.timeout = std::chrono::seconds(2);
    request.maximum_output_bytes = 4U * 1024U * 1024U;
    request.environment = {
        {"HOME", home}, {"LOGNAME", user}, {"USER", user},
        {"XDG_RUNTIME_DIR", runtime},
    };
    request.identity = HelperIdentity{static_cast<uid_t>(uid), gid, user};
    return run_helper(request);
}

void write_all(int descriptor, const std::string& contents, const std::string& label) {
    std::size_t written = 0;
    while (written < contents.size()) {
        const ssize_t result = write(descriptor, contents.data() + written,
                                     contents.size() - written);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            throw std::runtime_error("cannot write " + label + ": " +
                                     std::strerror(errno));
        }
        written += static_cast<std::size_t>(result);
    }
}

void require_secure_directory(const fs::path& directory, const std::string& label) {
    struct stat details {};
    if (stat(directory.c_str(), &details) != 0 || !S_ISDIR(details.st_mode)) {
        throw std::runtime_error(label + " is not a usable directory");
    }
    if (geteuid() == 0 &&
        (details.st_uid != 0 || (details.st_mode & (S_IWGRP | S_IWOTH)) != 0)) {
        throw std::runtime_error(label +
            " must be owned by root and not writable by group or others");
    }
}

void synchronize_directory(const fs::path& directory, const std::string& label) {
    const int descriptor = open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (descriptor < 0) {
        throw std::runtime_error("cannot open " + label + " for synchronization: " +
                                 std::strerror(errno));
    }
    const bool failed = fsync(descriptor) != 0;
    const int reason = errno;
    close(descriptor);
    if (failed) {
        throw std::runtime_error("cannot synchronize " + label + ": " +
                                 std::strerror(reason));
    }
}

void wait_until_or_stopped(
    std::chrono::steady_clock::time_point deadline,
    const volatile std::sig_atomic_t& stop_requested) {
    constexpr auto maximum_slice = std::chrono::milliseconds(100);
    while (stop_requested == 0) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            break;
        }
        const auto remaining = deadline - now;
        std::this_thread::sleep_for(std::min(
            remaining,
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                maximum_slice)));
    }
}
}  // namespace

std::string timestamp(std::chrono::system_clock::time_point time, const char* format) {
    const std::time_t raw = std::chrono::system_clock::to_time_t(time);
    std::tm local{};
    localtime_r(&raw, &local);
    std::ostringstream output;
    output << std::put_time(&local, format);
    return output.str();
}

Monitor::Monitor(unsigned int interval_seconds, std::string report_directory,
                 std::string baseline_path, std::string reviewed_path)
    : interval_seconds_(interval_seconds),
      report_directory_(std::move(report_directory)),
      baseline_path_(std::move(baseline_path)),
      reviewed_path_(std::move(reviewed_path)) {}

Monitor::~Monitor() {
    if (report_descriptor_ >= 0) {
        fsync(report_descriptor_);
        close(report_descriptor_);
    }
    if (json_report_descriptor_ >= 0) {
        fsync(json_report_descriptor_);
        close(json_report_descriptor_);
    }
    if (journal_descriptor_ >= 0) {
        fsync(journal_descriptor_);
        close(journal_descriptor_);
    }
}

KernelSnapshot Monitor::scan_kernel(bool module_details, bool bpf_details) const {
    KernelSnapshot result;
    utsname details{};
    if (uname(&details) == 0) result.posture.release = details.release;
    try {
        const std::string taint = trim(read_file("/proc/sys/kernel/tainted"));
        if (!taint.empty()) result.posture.taint = std::stoull(taint);
    } catch (const std::exception&) {
        result.posture.taint = std::numeric_limits<std::uint64_t>::max();
    }
    const std::string enforcement = trim(
        read_file("/sys/module/module/parameters/sig_enforce"));
    result.posture.signature_enforcement = enforcement == "Y" || enforcement == "1";
    result.posture.lockdown = parse_lockdown_mode(
        read_file("/sys/kernel/security/lockdown"));

    const std::set<std::string> names = parse_loaded_modules(read_file("/proc/modules"));
    const std::string modinfo = fs::exists("/usr/sbin/modinfo")
        ? "/usr/sbin/modinfo" : "/sbin/modinfo";
    std::map<std::string, KernelModule> module_information;
    if (module_details && !names.empty()) {
        HelperRequest request;
        request.executable = modinfo;
        request.arguments.assign(names.begin(), names.end());
        request.timeout = std::chrono::seconds(10);
        request.maximum_output_bytes = 4U * 1024U * 1024U;
        const HelperResult helper = run_helper(request);
        module_information = parse_modinfo_batch(helper.standard_output);
        if (!helper.succeeded()) {
            result.module_error = helper_result_summary(helper);
        }
    }
    for (const std::string& name : names) {
        KernelModule module;
        module.name = name;
        if (module_details) {
            const auto information = module_information.find(name);
            if (information != module_information.end()) {
                module = information->second;
            }
            if (module.resolved) {
                const ExecutableFingerprint fingerprint =
                    fingerprint_file(module.path, true);
                module.sha256 = fingerprint.sha256;
                module.file_secure = fingerprint.valid && fingerprint.uid == 0 &&
                    (fingerprint.mode & 0022U) == 0;
            }
        }
        result.modules.emplace(name, std::move(module));
    }
    if (bpf_details) {
        const std::string bpftool = fs::exists("/usr/sbin/bpftool")
            ? "/usr/sbin/bpftool" : "/sbin/bpftool";
        HelperRequest request;
        request.executable = bpftool;
        request.arguments = {"prog", "show"};
        request.timeout = std::chrono::seconds(5);
        request.maximum_output_bytes = 16U * 1024U * 1024U;
        const HelperResult helper = run_helper(request);
        result.bpf_available = helper.succeeded();
        result.bpf_error = helper.succeeded() ? std::string{}
                                              : helper_result_summary(helper);
        if (helper.succeeded()) {
            result.bpf_programs = parse_bpftool_programs(helper.standard_output);
        }
    }
    return result;
}

void Monitor::inspect_kernel() {
    KernelSnapshot current = scan_kernel(false, false);
    std::set<std::string> current_names;
    std::set<std::string> previous_names;
    for (const auto& [name, module] : current.modules) {
        (void)module; current_names.insert(name);
    }
    for (const auto& [name, module] : last_kernel_snapshot_.modules) {
        (void)module; previous_names.insert(name);
    }
    const auto now = std::chrono::steady_clock::now();
    const bool lifecycle_changed = current_names != previous_names;
    const bool integrity_due = now >= next_kernel_integrity_check_;
    const bool bpf_due = now >= next_bpf_check_;
    if (lifecycle_changed || integrity_due || last_kernel_snapshot_.modules.empty()) {
        KernelSnapshot detailed = scan_kernel(true, bpf_due);
        current.modules = std::move(detailed.modules);
        current.module_error = std::move(detailed.module_error);
        if (bpf_due) {
            current.bpf_available = detailed.bpf_available;
            current.bpf_error = std::move(detailed.bpf_error);
            current.bpf_programs = std::move(detailed.bpf_programs);
        }
        next_kernel_integrity_check_ = now + std::chrono::hours(6);
    } else {
        current.modules = last_kernel_snapshot_.modules;
        current.module_error = last_kernel_snapshot_.module_error;
    }
    if (bpf_due && !current.bpf_available) {
        KernelSnapshot bpf = scan_kernel(false, true);
        current.bpf_available = bpf.bpf_available;
        current.bpf_error = std::move(bpf.bpf_error);
        current.bpf_programs = std::move(bpf.bpf_programs);
    } else if (!bpf_due) {
        current.bpf_available = last_kernel_snapshot_.bpf_available;
        current.bpf_error = last_kernel_snapshot_.bpf_error;
        current.bpf_programs = last_kernel_snapshot_.bpf_programs;
    }
    if (bpf_due) next_bpf_check_ = now + std::chrono::seconds(30);
    if ((lifecycle_changed || integrity_due) && !current.module_error.empty()) {
        record_degradation(
            "kernel.module-inventory-unavailable",
            "modinfo could not provide the complete loaded-module inventory: " +
                current.module_error);
    }
    if (bpf_due && baseline_loaded_ && baseline_.kernel_calibrated &&
        baseline_.kernel.bpf_available && !current.bpf_available) {
        record_degradation(
            "kernel.bpf-inventory-unavailable",
            "bpftool could not provide the BPF program inventory during this check: " +
                (current.bpf_error.empty() ? std::string("unknown helper failure")
                                           : current.bpf_error));
    }

    if (baseline_loaded_ && baseline_.kernel_calibrated) {
        for (const KernelFinding& finding :
             compare_kernel_snapshots(baseline_.kernel, current)) {
            record_alert(finding.severity, finding.rule, finding.detail);
        }
    }
    last_kernel_snapshot_ = std::move(current);
}

void Monitor::inspect_persistence(bool force) {
    const auto steady_now = std::chrono::steady_clock::now();
    if (!force && steady_now < next_persistence_check_) return;
    next_persistence_check_ = steady_now + std::chrono::seconds(60);

    PersistenceSnapshot current = collect_persistence(default_persistence_roots());
    if (current.truncated) {
        record_degradation(
            "persistence.inventory-limit-reached",
            "Persistence inventory reached its 10000-record ceiling; changes "
            "were not evaluated from the incomplete snapshot");
    }
    if (!current.errors.empty()) {
        record_degradation(
            "persistence.inventory-unavailable",
            "Persistence inventory could not verify one or more locations: " +
                current.errors.front() +
                (current.errors.size() > 1
                     ? " (and " + std::to_string(current.errors.size() - 1) +
                           " additional error(s))"
                     : std::string{}));
    }
    if (!current.truncated && current.errors.empty() && baseline_loaded_ &&
        baseline_.persistence_calibrated) {
        const PersistenceDiff diff = compare_persistence(
            baseline_.persistence, current.records);
        for (const PersistenceRecord& record : diff.added) {
            record_alert("HIGH", "persistence.entry-added",
                         persistence_kind_name(record.kind) + " entry " +
                             record.path + " appeared after calibration");
        }
        for (const PersistenceRecord& record : diff.changed) {
            record_alert("HIGH", "persistence.entry-changed",
                         persistence_kind_name(record.kind) + " entry " +
                             record.path +
                             " no longer matches its calibrated content, target, "
                             "ownership, or permissions");
        }
        for (const PersistenceRecord& record : diff.removed) {
            record_alert("NOTICE", "persistence.entry-removed",
                         persistence_kind_name(record.kind) + " entry " +
                             record.path + " disappeared after calibration");
        }
    }
    last_persistence_snapshot_ = std::move(current);
}

bool Monitor::collect_login_sessions(
    std::map<std::string, LoginSession>& sessions, std::string& error) {
    HelperRequest list_request;
    list_request.executable = "/usr/bin/loginctl";
    list_request.arguments = {"list-sessions", "--no-legend", "--no-pager"};
    list_request.timeout = std::chrono::seconds(3);
    list_request.maximum_output_bytes = 256U * 1024U;
    const HelperResult listed = run_helper(list_request);
    if (!listed.succeeded()) {
        error = "loginctl list-sessions failed: " +
                helper_result_summary(listed);
        return false;
    }
    const LoginSessionListParse parsed =
        parse_login_session_list(listed.standard_output);
    if (parsed.malformed_lines != 0 || parsed.truncated) {
        error = parsed.truncated
            ? "loginctl session list exceeded its 1024-session ceiling"
            : "loginctl returned " + std::to_string(parsed.malformed_lines) +
                  " malformed session-list line(s)";
        return false;
    }

    std::map<std::string, LoginSession> collected;
    for (const std::string& id : parsed.session_ids) {
        HelperRequest show_request;
        show_request.executable = "/usr/bin/loginctl";
        show_request.arguments = {
            "show-session", id, "-p", "Id", "-p", "Name", "-p", "User",
            "-p", "Seat", "-p", "TTY", "-p", "Remote", "-p",
            "RemoteHost", "-p", "State", "-p", "LockedHint", "--no-pager"
        };
        show_request.timeout = std::chrono::seconds(2);
        show_request.maximum_output_bytes = 64U * 1024U;
        const HelperResult shown = run_helper(show_request);
        if (!shown.succeeded()) {
            const std::string summary = helper_result_summary(shown);
            if (shown.status == HelperStatus::exited_nonzero &&
                (shown.standard_error.find("No session") != std::string::npos ||
                 shown.standard_error.find("not known") != std::string::npos)) {
                continue;
            }
            error = "loginctl show-session " + id + " failed: " + summary;
            return false;
        }
        LoginSession session;
        std::string parse_error;
        if (!parse_login_session_properties(
                shown.standard_output, session, parse_error)) {
            error = "loginctl show-session " + id + ": " + parse_error;
            return false;
        }
        collected.emplace(session.id, std::move(session));
    }
    sessions = std::move(collected);
    error.clear();
    return true;
}

void Monitor::record_authentication_event(AuthenticationEvent event) {
    std::string key;
    if ((event.type == AuthenticationEventType::session_started ||
         event.type == AuthenticationEventType::session_ended) &&
        !event.session_id.empty()) {
        key = authentication_event_type_name(event.type) + "|" +
              event.session_id;
    } else if (!event.cursor.empty()) {
        key = event.cursor;
    } else {
        key = authentication_event_type_name(event.type) + "|" +
              event.timestamp + "|" + event.session_id + "|" + event.user;
    }
    if (!authentication_event_keys_.insert(key).second) return;
    if (!authentication_budget_.allow_new(authentication_events_.size())) {
        if (authentication_budget_.dropped() == 1) {
            record_degradation(
                "authentication.event-limit-reached",
                "Authentication/session evidence reached its 4096-event "
                "ceiling; additional events are counted but not retained");
        }
        return;
    }
    if (event.timestamp.empty()) event.timestamp = timestamp(Clock::now());
    const std::string summary = authentication_event_summary(event);
    authentication_events_.push_back(event);
    append_journal("[" + event.timestamp + "] AUTHENTICATION " + summary +
                   "\n");
    if (event.type == AuthenticationEventType::session_started) {
        record_alert("NOTICE", "authentication.session-started", summary);
    } else if (event.type == AuthenticationEventType::authentication_failed) {
        record_alert("NOTICE", "authentication.failed", summary);
    } else if (event.type == AuthenticationEventType::session_unlocked) {
        record_alert("NOTICE", "authentication.session-unlocked", summary);
    }
}

void Monitor::initialize_authentication() {
    authentication_initialized_ = true;
    authentication_status_ = {};

    HelperRequest cursor_request;
    cursor_request.executable = "/usr/bin/journalctl";
    cursor_request.arguments = {"--lines=0", "--show-cursor", "--no-pager"};
    cursor_request.timeout = std::chrono::seconds(3);
    cursor_request.maximum_output_bytes = 64U * 1024U;
    const HelperResult cursor = run_helper(cursor_request);
    if (cursor.succeeded()) {
        authentication_journal_cursor_ =
            parse_journal_cursor(cursor.standard_output);
    }
    authentication_journal_live_ = cursor.succeeded() &&
                                   !authentication_journal_cursor_.empty();
    authentication_status_.journal_available = authentication_journal_live_;
    if (!authentication_journal_live_) {
        record_degradation(
            "authentication.journal-unavailable",
            "The system journal cursor could not be established: " +
                (cursor.succeeded() ? std::string("journalctl returned no cursor")
                                    : helper_result_summary(cursor)));
    }

    std::map<std::string, LoginSession> sessions;
    std::string session_error;
    authentication_sessions_live_ = collect_login_sessions(sessions, session_error);
    authentication_status_.session_state_available =
        authentication_sessions_live_;
    if (authentication_sessions_live_) {
        authentication_sessions_ = std::move(sessions);
        for (const auto& [id, session] : authentication_sessions_) {
            if (!session.locked_known) {
                authentication_status_.session_state_available = false;
                record_degradation(
                    "authentication.lock-state-unavailable",
                    "systemd-logind did not expose LockedHint for session " + id);
            }
        }
    } else {
        record_degradation("authentication.session-state-unavailable",
                           session_error);
    }
    next_authentication_check_ = SteadyClock::now() + std::chrono::seconds(10);
}

void Monitor::inspect_authentication(bool force) {
    const auto now = SteadyClock::now();
    if (!authentication_initialized_) {
        initialize_authentication();
        return;
    }
    if (!force && now < next_authentication_check_) return;
    next_authentication_check_ = now + std::chrono::seconds(10);

    const std::map<std::string, LoginSession> previous_sessions =
        authentication_sessions_;
    std::map<std::string, LoginSession> current_sessions;
    std::string session_error;
    const bool sessions_ok = collect_login_sessions(current_sessions, session_error);
    if (!sessions_ok) {
        authentication_sessions_live_ = false;
        authentication_status_.session_state_available = false;
        record_degradation("authentication.session-state-unavailable",
                           session_error);
    } else {
        if (!authentication_sessions_live_ &&
            !authentication_status_.session_state_available) {
            // Coverage already had a gap; retain the unknown final status even
            // after collection recovers.
        }
        authentication_sessions_live_ = true;
        for (const auto& [id, session] : current_sessions) {
            if (!session.locked_known) {
                authentication_status_.session_state_available = false;
                record_degradation(
                    "authentication.lock-state-unavailable",
                    "systemd-logind did not expose LockedHint for session " + id);
            }
        }
        for (const auto& [id, session] : current_sessions) {
            const auto previous = previous_sessions.find(id);
            if (previous != previous_sessions.end() &&
                previous->second.locked_known && session.locked_known &&
                previous->second.locked != session.locked) {
                AuthenticationEvent event;
                event.timestamp = timestamp(Clock::now());
                event.type = session.locked
                    ? AuthenticationEventType::session_locked
                    : AuthenticationEventType::session_unlocked;
                event.session_id = session.id;
                event.uid = session.uid;
                event.user = session.user;
                event.seat = session.seat;
                event.tty = session.tty;
                event.source = session.source;
                event.provider = "systemd-logind LockedHint";
                event.detail = "loginctl observed LockedHint=" +
                               std::string(session.locked ? "yes" : "no");
                record_authentication_event(std::move(event));
            }
        }
        if (!authentication_journal_live_) {
            for (const auto& [id, session] : current_sessions) {
                if (previous_sessions.find(id) == previous_sessions.end()) {
                    AuthenticationEvent event;
                    event.timestamp = timestamp(Clock::now());
                    event.type = AuthenticationEventType::session_started;
                    event.session_id = session.id;
                    event.uid = session.uid;
                    event.user = session.user;
                    event.seat = session.seat;
                    event.tty = session.tty;
                    event.source = session.source;
                    event.provider = "systemd-logind sampled state";
                    event.detail = "new active loginctl session";
                    record_authentication_event(std::move(event));
                }
            }
            for (const auto& [id, session] : previous_sessions) {
                if (current_sessions.find(id) == current_sessions.end()) {
                    AuthenticationEvent event;
                    event.timestamp = timestamp(Clock::now());
                    event.type = AuthenticationEventType::session_ended;
                    event.session_id = session.id;
                    event.uid = session.uid;
                    event.user = session.user;
                    event.seat = session.seat;
                    event.tty = session.tty;
                    event.source = session.source;
                    event.provider = "systemd-logind sampled state";
                    event.detail = "active loginctl session disappeared";
                    record_authentication_event(std::move(event));
                }
            }
        }
        authentication_sessions_ = current_sessions;
    }

    if (!authentication_journal_live_) {
        HelperRequest cursor_request;
        cursor_request.executable = "/usr/bin/journalctl";
        cursor_request.arguments = {"--lines=0", "--show-cursor", "--no-pager"};
        cursor_request.timeout = std::chrono::seconds(3);
        cursor_request.maximum_output_bytes = 64U * 1024U;
        const HelperResult cursor = run_helper(cursor_request);
        if (cursor.succeeded()) {
            authentication_journal_cursor_ =
                parse_journal_cursor(cursor.standard_output);
            authentication_journal_live_ =
                !authentication_journal_cursor_.empty();
        }
        return;
    }

    HelperRequest journal_request;
    journal_request.executable = "/usr/bin/journalctl";
    journal_request.arguments = {
        "--after-cursor=" + authentication_journal_cursor_, "--show-cursor",
        "--no-pager", "--all", "--output=json",
        "--output-fields=__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_SYSTEMD_UNIT,"
        "SYSLOG_IDENTIFIER,_COMM,_UID,MESSAGE"
    };
    journal_request.timeout = std::chrono::seconds(5);
    journal_request.maximum_output_bytes = 4U * 1024U * 1024U;
    const HelperResult journal = run_helper(journal_request);
    if (!journal.succeeded()) {
        authentication_journal_live_ = false;
        authentication_status_.journal_available = false;
        if (journal.status == HelperStatus::output_limit_reached) {
            authentication_status_.journal_truncated = true;
            record_degradation(
                "authentication.journal-truncated",
                "journalctl exceeded its 4 MiB bounded output while collecting "
                "authentication evidence");
        } else {
            record_degradation(
                "authentication.journal-unavailable",
                "journalctl could not continue authentication evidence: " +
                    helper_result_summary(journal));
        }
    }

    const AuthenticationJournalParse parsed =
        parse_authentication_journal(journal.standard_output);
    if (!parsed.cursor.empty()) authentication_journal_cursor_ = parsed.cursor;
    if (parsed.malformed_lines != 0) {
        authentication_status_.malformed_journal_records +=
            parsed.malformed_lines;
        authentication_status_.journal_available = false;
        record_degradation(
            "authentication.journal-malformed",
            "journalctl returned " + std::to_string(parsed.malformed_lines) +
                " malformed record(s); those records were not treated as clean evidence");
    }
    if (parsed.truncated) {
        authentication_status_.journal_truncated = true;
        authentication_status_.journal_available = false;
        record_degradation(
            "authentication.journal-truncated",
            "More than 4096 authentication events were present in one journal "
            "batch; excess events were not retained");
    }
    for (AuthenticationEvent event : parsed.events) {
        const LoginSession* session = nullptr;
        const auto current = authentication_sessions_.find(event.session_id);
        const auto previous = previous_sessions.find(event.session_id);
        if (current != authentication_sessions_.end()) {
            session = &current->second;
        } else if (previous != previous_sessions.end()) {
            session = &previous->second;
        }
        if (session != nullptr) {
            if (event.user.empty()) event.user = session->user;
            if (event.uid.empty()) event.uid = session->uid;
            if (event.seat.empty()) event.seat = session->seat;
            if (event.tty.empty()) event.tty = session->tty;
            if (event.source.empty()) event.source = session->source;
        }
        record_authentication_event(std::move(event));
    }
}

std::map<int, ProcessInfo> Monitor::scan_processes() const {
    std::map<int, ProcessInfo> result;
    DIR* directory = opendir("/proc");
    if (directory == nullptr) {
        throw std::runtime_error(std::string("cannot open /proc: ") + std::strerror(errno));
    }

    while (const dirent* entry = readdir(directory)) {
        if (!numeric_name(entry->d_name)) {
            continue;
        }
        const int pid = std::atoi(entry->d_name);
        const fs::path root = fs::path("/proc") / entry->d_name;
        const std::uint64_t start_before = process_start_ticks(root / "stat");
        if (start_before == 0) {
            continue;
        }
        ProcessInfo process;
        process.pid = pid;
        process.start_time_ticks = start_before;
        process.executable = read_link(root / "exe");
        const std::string raw_command_line = read_file(root / "cmdline");
        process.arguments = split_process_arguments(raw_command_line);
        process.command_line = raw_command_line;
        std::replace(process.command_line.begin(), process.command_line.end(), '\0', ' ');
        while (!process.command_line.empty() && process.command_line.back() == ' ') {
            process.command_line.pop_back();
        }
        const std::string working_directory = read_link(root / "cwd");
        if (const auto script = find_script_entrypoint(
                process.executable, process.arguments, working_directory)) {
            process.script_entrypoint = *script;
        }

        std::istringstream status(read_file(root / "status"));
        std::string line;
        while (std::getline(status, line)) {
            std::istringstream fields(line);
            std::string key;
            fields >> key;
            if (key == "Name:") {
                fields >> process.name;
            } else if (key == "PPid:") {
                fields >> process.ppid;
            } else if (key == "Uid:") {
                fields >> process.uid;
            }
        }

        std::error_code error;
        const fs::path fd_root = root / "fd";
        for (fs::directory_iterator it(fd_root, error), end; !error && it != end;
             it.increment(error)) {
            const std::string target = read_link(it->path());
            if (target.rfind("/dev/video", 0) == 0 || target.rfind("/dev/snd/", 0) == 0) {
                process.media_handles.insert(target);
            } else if (target.rfind("socket:[", 0) == 0 && target.back() == ']') {
                try {
                    const std::string value = target.substr(8, target.size() - 9);
                    std::size_t consumed = 0;
                    const std::uint64_t inode = std::stoull(value, &consumed);
                    if (consumed == value.size()) {
                        process.socket_inodes.insert(inode);
                    }
                } catch (const std::exception&) {
                }
            }
        }
        const std::uint64_t start_after = process_start_ticks(root / "stat");
        if (start_after == 0 || start_after != start_before) {
            continue;
        }
        result.emplace(pid, std::move(process));
    }
    closedir(directory);
    return result;
}

std::vector<NetworkEvent> Monitor::scan_network_sockets(
    const std::map<int, ProcessInfo>& processes) const {
    std::vector<NetworkSocket> sockets;
    auto append = [&](std::vector<NetworkSocket> parsed) {
        sockets.insert(sockets.end(), std::make_move_iterator(parsed.begin()),
                       std::make_move_iterator(parsed.end()));
    };
    const std::string tcp4 = read_file("/proc/net/tcp");
    const std::string udp4 = read_file("/proc/net/udp");
    if (tcp4.empty() || udp4.empty()) {
        throw std::runtime_error(
            "cannot read mandatory /proc TCP/UDP socket tables");
    }
    append(parse_inet_socket_table(tcp4, "TCP", false));
    append(parse_inet_socket_table(read_file("/proc/net/tcp6"), "TCP", true));
    append(parse_inet_socket_table(udp4, "UDP", false));
    append(parse_inet_socket_table(read_file("/proc/net/udp6"), "UDP", true));
    append(parse_inet_socket_table(read_file("/proc/net/raw"), "RAW", false));
    append(parse_inet_socket_table(read_file("/proc/net/raw6"), "RAW", true));
    append(parse_packet_socket_table(read_file("/proc/net/packet")));

    std::map<std::uint64_t, std::vector<const ProcessInfo*>> owners;
    for (const auto& [pid, process] : processes) {
        (void)pid;
        for (const std::uint64_t inode : process.socket_inodes) {
            owners[inode].push_back(&process);
        }
    }

    std::vector<NetworkEvent> result;
    for (NetworkSocket& socket : sockets) {
        const auto found = owners.find(socket.inode);
        if (found == owners.end()) {
            continue;
        }
        for (const ProcessInfo* process : found->second) {
            NetworkEvent event;
            event.pid = process->pid;
            event.process_start_ticks = process->start_time_ticks;
            event.uid = process->uid;
            event.executable = process->executable;
            event.socket = socket;
            result.push_back(std::move(event));
        }
    }
    return result;
}

ExecutableFingerprint Monitor::fingerprint_executable(const ProcessInfo& process,
                                                       bool include_hash) const {
    const fs::path process_root = fs::path("/proc") / std::to_string(process.pid);
    if (process_start_ticks(process_root / "stat") != process.start_time_ticks) {
        return {};
    }
    const ExecutableFingerprint result = fingerprint_file(
        (process_root / "exe").string(), include_hash);
    if (process_start_ticks(process_root / "stat") != process.start_time_ticks) {
        return {};
    }
    return result;
}

ExecutableFingerprint Monitor::fingerprint_script(const ProcessInfo& process,
                                                   bool include_hash) const {
    if (process.script_entrypoint.empty()) {
        return {};
    }
    const fs::path process_root = fs::path("/proc") / std::to_string(process.pid);
    if (process_start_ticks(process_root / "stat") != process.start_time_ticks) {
        return {};
    }
    const fs::path script(process.script_entrypoint);
    if (!script.is_absolute()) {
        return {};
    }
    const fs::path process_view = process_root / "root" / script.relative_path();
    const ExecutableFingerprint result = fingerprint_file(
        process_view.string(), include_hash);
    if (process_start_ticks(process_root / "stat") != process.start_time_ticks) {
        return {};
    }
    return result;
}

void Monitor::verify_executable(const ProcessInfo& process,
                                std::set<std::string>& verified_this_snapshot,
                                unsigned int& background_hash_budget) {
    if (process.executable.empty() ||
        !verified_this_snapshot.insert(process.executable).second) {
        return;
    }
    const auto expected = baseline_.executables.find(process.executable);
    if (expected == baseline_.executables.end()) {
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    const ExecutableFingerprint metadata = fingerprint_executable(process, false);
    if (!metadata.valid) {
        return;
    }
    const auto cached = current_fingerprints_.find(process.executable);
    const auto checked = last_hash_checks_.find(process.executable);
    const bool periodic_recheck = checked == last_hash_checks_.end() ||
        now - checked->second >= std::chrono::hours(6);
    const bool metadata_changed_from_baseline = expected->second.valid &&
        !same_executable_metadata(expected->second, metadata);
    const bool metadata_changed_during_run = cached != current_fingerprints_.end() &&
        !same_executable_metadata(cached->second, metadata);
    const bool background_check = (cached == current_fingerprints_.end() ||
                                   periodic_recheck) && background_hash_budget > 0;
    const bool needs_hash = executable_rehash_required(
        expected->second, metadata,
        cached == current_fingerprints_.end() ? nullptr : &cached->second,
        periodic_recheck, background_check);
    if (!needs_hash) {
        return;
    }
    if (!metadata_changed_from_baseline && !metadata_changed_during_run &&
        background_hash_budget > 0) {
        --background_hash_budget;
    }

    const ExecutableFingerprint current = fingerprint_executable(process, true);
    if (!current.valid) {
        return;
    }
    current_fingerprints_[process.executable] = current;
    last_hash_checks_[process.executable] = now;
    if (!expected->second.valid && changed_executables_.insert(
            "unverified\n" + process.executable).second) {
        record_degradation(
            "executable.baseline-fingerprint-unavailable",
            process_label(process) + " had no usable calibration fingerprint");
    } else if (expected->second.valid &&
               !same_security_fingerprint(expected->second, current) &&
               changed_executables_.insert(process.executable).second) {
        record_alert("HIGH", "executable.fingerprint-changed",
                     process_label(process) + " no longer matches its calibrated SHA-256 "
                     "hash or file metadata");
    }
}

void Monitor::verify_script(const ProcessInfo& process,
                            std::set<std::string>& verified_this_snapshot,
                            unsigned int& background_hash_budget) {
    if (process.script_entrypoint.empty() ||
        !verified_this_snapshot.insert(process.script_entrypoint).second) {
        return;
    }
    const auto expected = baseline_.scripts.find(process.script_entrypoint);
    if (expected == baseline_.scripts.end()) {
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    const ExecutableFingerprint metadata = fingerprint_script(process, false);
    if (!metadata.valid) {
        if (changed_scripts_.insert("unverified\n" +
                                    process.script_entrypoint).second) {
            record_degradation(
                "script.fingerprint-unavailable",
                script_label(process) +
                " could not be checked against its calibration fingerprint");
        }
        return;
    }
    const auto cached = current_script_fingerprints_.find(process.script_entrypoint);
    const auto checked = last_script_hash_checks_.find(process.script_entrypoint);
    const bool periodic_recheck = checked == last_script_hash_checks_.end() ||
        now - checked->second >= std::chrono::hours(6);
    const bool metadata_changed_from_baseline = expected->second.valid &&
        !same_executable_metadata(expected->second, metadata);
    const bool metadata_changed_during_run =
        cached != current_script_fingerprints_.end() &&
        !same_executable_metadata(cached->second, metadata);
    const bool background_check =
        (cached == current_script_fingerprints_.end() || periodic_recheck) &&
        background_hash_budget > 0;
    const bool needs_hash = executable_rehash_required(
        expected->second, metadata,
        cached == current_script_fingerprints_.end() ? nullptr : &cached->second,
        periodic_recheck, background_check);
    if (!needs_hash) {
        return;
    }
    if (!metadata_changed_from_baseline && !metadata_changed_during_run &&
        background_hash_budget > 0) {
        --background_hash_budget;
    }

    const ExecutableFingerprint current = fingerprint_script(process, true);
    if (!current.valid) {
        return;
    }
    current_script_fingerprints_[process.script_entrypoint] = current;
    last_script_hash_checks_[process.script_entrypoint] = now;
    if (!expected->second.valid && changed_scripts_.insert(
            "unverified-baseline\n" + process.script_entrypoint).second) {
        record_degradation(
            "script.baseline-fingerprint-unavailable",
            script_label(process) + " had no usable calibration fingerprint");
    } else if (expected->second.valid &&
               !same_security_fingerprint(expected->second, current) &&
               changed_scripts_.insert(process.script_entrypoint).second) {
        record_alert("HIGH", "script.fingerprint-changed",
                     script_label(process) +
                     " no longer matches its calibrated SHA-256 hash or file metadata");
    }
}

ReviewedStatus Monitor::verify_reviewed_executable(
    const ProcessInfo& process,
    std::set<std::string>& verified_this_snapshot) {
    const auto expected = reviewed_executables_.find(process.executable);
    if (expected == reviewed_executables_.end()) {
        return ReviewedStatus::not_reviewed;
    }
    if (!verified_this_snapshot.insert(process.executable).second) {
        const auto cached = current_reviewed_fingerprints_.find(process.executable);
        return cached == current_reviewed_fingerprints_.end()
            ? ReviewedStatus::changed
            : reviewed_status(reviewed_executables_, process.executable,
                              cached->second);
    }

    const auto cached = current_reviewed_fingerprints_.find(process.executable);
    const ExecutableFingerprint metadata = fingerprint_executable(process, false);
    if (!metadata.valid) {
        if (cached != current_reviewed_fingerprints_.end() &&
            reviewed_status(reviewed_executables_, process.executable,
                            cached->second) == ReviewedStatus::matched) {
            return ReviewedStatus::matched;
        }
        if (reviewed_executables_unverified_.insert(process.executable).second) {
            record_degradation(
                "reviewed-executable.unverified",
                process_label(process) +
                " could not be checked against its reviewed fingerprint");
        }
        return ReviewedStatus::changed;
    }

    const auto now = std::chrono::steady_clock::now();
    const auto checked = last_reviewed_hash_checks_.find(process.executable);
    const bool metadata_changed = cached == current_reviewed_fingerprints_.end() ||
        !same_executable_metadata(cached->second, metadata);
    const bool periodic_recheck = checked == last_reviewed_hash_checks_.end() ||
        now - checked->second >= std::chrono::hours(6);
    if (!metadata_changed && !periodic_recheck) {
        return reviewed_status(reviewed_executables_, process.executable,
                               cached->second);
    }

    const ExecutableFingerprint current = fingerprint_executable(process, true);
    if (!current.valid) {
        if (cached != current_reviewed_fingerprints_.end() &&
            reviewed_status(reviewed_executables_, process.executable,
                            cached->second) == ReviewedStatus::matched) {
            return ReviewedStatus::matched;
        }
        if (reviewed_executables_unverified_.insert(process.executable).second) {
            record_degradation(
                "reviewed-executable.unverified",
                process_label(process) +
                " could not be checked against its reviewed fingerprint");
        }
        return ReviewedStatus::changed;
    }
    current_reviewed_fingerprints_[process.executable] = current;
    last_reviewed_hash_checks_[process.executable] = now;
    const ReviewedStatus status = reviewed_status(
        reviewed_executables_, process.executable, current);
    const ReviewedStateUpdate update = note_reviewed_verification(
        process.executable, status, reviewed_executables_observed_,
        reviewed_executables_changed_, reviewed_executables_unverified_);
    if (update.first_match) {
        append_journal("[" + timestamp(Clock::now()) + "] REVIEWED " +
                       process.executable + " matched its approved fingerprint (" +
                       expected->second.reason + ")\n");
    } else if (update.first_change) {
        changed_executables_.insert("reviewed\n" + process.executable);
        record_alert("HIGH", "reviewed-executable.fingerprint-changed",
                     process_label(process) +
                     " does not match its reviewed SHA-256 hash or file metadata; " +
                     "review reason: " + expected->second.reason);
    }
    return status;
}

ReviewedStatus Monitor::verify_reviewed_script(
    const ProcessInfo& process,
    std::set<std::string>& verified_this_snapshot) {
    const auto expected = reviewed_scripts_.find(process.script_entrypoint);
    if (expected == reviewed_scripts_.end()) {
        return ReviewedStatus::not_reviewed;
    }
    if (!verified_this_snapshot.insert(process.script_entrypoint).second) {
        const auto cached =
            current_reviewed_script_fingerprints_.find(process.script_entrypoint);
        return cached == current_reviewed_script_fingerprints_.end()
            ? ReviewedStatus::changed
            : reviewed_status(reviewed_scripts_, process.script_entrypoint,
                              cached->second);
    }

    const auto cached =
        current_reviewed_script_fingerprints_.find(process.script_entrypoint);
    const ExecutableFingerprint metadata = fingerprint_script(process, false);
    if (!metadata.valid) {
        if (cached != current_reviewed_script_fingerprints_.end() &&
            reviewed_status(reviewed_scripts_, process.script_entrypoint,
                            cached->second) == ReviewedStatus::matched) {
            return ReviewedStatus::matched;
        }
        if (reviewed_scripts_unverified_.insert(
                process.script_entrypoint).second) {
            record_degradation(
                "reviewed-script.unverified",
                script_label(process) +
                " could not be checked against its reviewed fingerprint");
        }
        return ReviewedStatus::changed;
    }

    const auto now = std::chrono::steady_clock::now();
    const auto checked =
        last_reviewed_script_hash_checks_.find(process.script_entrypoint);
    const bool metadata_changed =
        cached == current_reviewed_script_fingerprints_.end() ||
        !same_executable_metadata(cached->second, metadata);
    const bool periodic_recheck =
        checked == last_reviewed_script_hash_checks_.end() ||
        now - checked->second >= std::chrono::hours(6);
    if (!metadata_changed && !periodic_recheck) {
        return reviewed_status(reviewed_scripts_, process.script_entrypoint,
                               cached->second);
    }

    const ExecutableFingerprint current = fingerprint_script(process, true);
    if (!current.valid) {
        if (cached != current_reviewed_script_fingerprints_.end() &&
            reviewed_status(reviewed_scripts_, process.script_entrypoint,
                            cached->second) == ReviewedStatus::matched) {
            return ReviewedStatus::matched;
        }
        if (reviewed_scripts_unverified_.insert(
                process.script_entrypoint).second) {
            record_degradation(
                "reviewed-script.unverified",
                script_label(process) +
                " could not be checked against its reviewed fingerprint");
        }
        return ReviewedStatus::changed;
    }
    current_reviewed_script_fingerprints_[process.script_entrypoint] = current;
    last_reviewed_script_hash_checks_[process.script_entrypoint] = now;
    const ReviewedStatus status = reviewed_status(
        reviewed_scripts_, process.script_entrypoint, current);
    const ReviewedStateUpdate update = note_reviewed_verification(
        process.script_entrypoint, status, reviewed_scripts_observed_,
        reviewed_scripts_changed_, reviewed_scripts_unverified_);
    if (update.first_match) {
        append_journal("[" + timestamp(Clock::now()) + "] REVIEWED-SCRIPT " +
                       process.script_entrypoint +
                       " matched its approved fingerprint (" +
                       expected->second.reason + ")\n");
    } else if (update.first_change) {
        changed_scripts_.insert("reviewed\n" + process.script_entrypoint);
        record_alert("HIGH", "reviewed-script.fingerprint-changed",
                     script_label(process) +
                     " does not match its reviewed SHA-256 hash or file metadata; "
                     "review reason: " + expected->second.reason);
    }
    return status;
}

std::vector<PipeWireCapture> Monitor::scan_pipewire_captures(
    const std::map<int, ProcessInfo>& processes) {
    const unsigned int session_uid = pipewire_user();
    const HelperResult helper = run_pipewire_info(session_uid);
    const std::string& listing = helper.standard_output;
    std::vector<PipeWireCapture> result;
    if (!helper.succeeded()) {
        record_degradation(
            "pipewire.inventory-unavailable",
            "pw-cli could not provide the PipeWire graph for capture attribution: " +
                helper_result_summary(helper));
        return result;
    }
    if (listing.empty()) {
        return result;
    }

    struct Block {
        std::string type;
        std::string state;
        std::string application;
        std::string binary;
        std::string process_id;
        std::string media_class;
        std::string node_name;
    } block;

    auto finish_block = [&]() {
        const bool capture_class = block.media_class == "Stream/Input/Audio" ||
                                   block.media_class == "Stream/Input/Video";
        if (block.type.find("PipeWire:Interface:Node") == std::string::npos ||
            block.state != "running" || !capture_class) {
            block = Block{};
            return;
        }
        PipeWireCapture capture;
        capture.uid = session_uid;
        capture.application = block.application;
        capture.executable = block.binary;
        capture.media_class = block.media_class;
        capture.node_name = block.node_name;
        try {
            capture.pid = std::stoi(block.process_id);
        } catch (const std::exception&) {
            capture.pid = 0;
        }
        const auto process = processes.find(capture.pid);
        if (process != processes.end()) {
            capture.uid = process->second.uid;
            capture.executable = process->second.executable;
        }
        if (capture.application.empty()) {
            capture.application = capture.executable.empty() ? "[unknown]" : capture.executable;
        }
        result.push_back(std::move(capture));
        block = Block{};
    };

    std::istringstream input(listing);
    std::string line;
    while (std::getline(input, line)) {
        const std::string cleaned = trim(line);
        if (cleaned.rfind("id:", 0) == 0) {
            finish_block();
        } else if (cleaned.rfind("type:", 0) == 0) {
            block.type = trim(cleaned.substr(5));
        } else if (cleaned.rfind("state: \"", 0) == 0) {
            const std::size_t begin = cleaned.find('"') + 1;
            const std::size_t end = cleaned.find('"', begin);
            block.state = cleaned.substr(begin, end - begin);
        } else if (const std::string value = quoted_property(cleaned, "application.name");
                   !value.empty()) {
            block.application = value;
        } else if (const std::string value = quoted_property(
                       cleaned, "application.process.binary"); !value.empty()) {
            block.binary = value;
        } else if (const std::string value = quoted_property(
                       cleaned, "application.process.id"); !value.empty()) {
            block.process_id = value;
        } else if (const std::string value = quoted_property(cleaned, "media.class");
                   !value.empty()) {
            block.media_class = value;
        } else if (const std::string value = quoted_property(cleaned, "node.name");
                   !value.empty()) {
            block.node_name = value;
        }
    }
    finish_block();
    return result;
}

void Monitor::inspect_pipewire(const std::vector<PipeWireCapture>& captures) {
    const std::string now = timestamp(Clock::now());
    std::set<std::string> current;
    std::set<std::string> current_dropped;
    for (PipeWireCapture capture : captures) {
        const std::string identity = pipewire_identity(capture);
        current.insert(identity);
        const bool continued = previous_pipewire_captures_.find(identity) !=
                               previous_pipewire_captures_.end();
        if (continued && previous_dropped_pipewire_captures_.find(identity) !=
                             previous_dropped_pipewire_captures_.end()) {
            current_dropped.insert(identity);
            continue;
        }
        const bool matched = baseline_loaded_ &&
            baseline_.authorized_pipewire_captures.find(identity) !=
                baseline_.authorized_pipewire_captures.end();
        const std::string detail = "PipeWire application " + capture.application +
            " (PID " + std::to_string(capture.pid) + ", executable " +
            (capture.executable.empty() ? "[unavailable]" : capture.executable) +
            ") activated " + capture.media_class;
        if (!continued && !pipewire_budget_.allow_new(pipewire_events_.size())) {
            current_dropped.insert(identity);
            if (pipewire_budget_.dropped() == 1) {
                record_degradation(
                    "retention.pipewire-limit-reached",
                    "PipeWire session retention reached its " +
                        std::to_string(pipewire_budget_.limit()) +
                        "-record budget; additional sessions are counted but "
                        "not retained");
            }
            if (baseline_loaded_ && !matched) {
                record_alert("HIGH", "pipewire.capture-not-in-baseline", detail);
            } else if (!baseline_loaded_) {
                record_alert("NOTICE", "pipewire.capture-active", detail);
            }
            continue;
        }
        unsigned int& session = pipewire_session_counts_[identity];
        if (!continued) {
            ++session;
        }
        const std::string key = identity + "\n" + std::to_string(session);
        capture.first_seen = now;
        capture.last_seen = now;
        capture.matched_baseline = matched;
        auto [position, inserted] = pipewire_events_.try_emplace(key, capture);
        position->second.last_seen = now;
        if (inserted) {
            append_journal("[" + now + "] PIPEWIRE " +
                           (matched ? "CALIBRATED " : "NEW ") + detail + "\n");
            if (baseline_loaded_ && !matched) {
                record_alert("HIGH", "pipewire.capture-not-in-baseline", detail);
            } else if (!baseline_loaded_) {
                record_alert("NOTICE", "pipewire.capture-active", detail);
            }
        }
    }
    previous_pipewire_captures_ = std::move(current);
    previous_dropped_pipewire_captures_ = std::move(current_dropped);
}

void Monitor::inspect_network(const std::vector<NetworkEvent>& sockets) {
    const std::string now = timestamp(Clock::now());
    const auto steady_now = std::chrono::steady_clock::now();
    std::set<std::string> active_pending_binds;
    std::set<std::string> current_dropped_events;
    for (NetworkEvent event : sockets) {
        const NetworkPattern pattern = network_pattern(event.executable, event.socket);
        event.matched_baseline = baseline_loaded_ && baseline_.network_calibrated &&
            baseline_.authorized_network.find(pattern) !=
                baseline_.authorized_network.end();
        event.first_seen = now;
        event.last_seen = now;

        std::ostringstream key;
        key << event.pid << '\n' << event.process_start_ticks << '\n'
            << event.socket.inode << '\n' << event.socket.protocol << '\n'
            << event.socket.local_address << '\n' << event.socket.local_port << '\n'
            << event.socket.remote_address << '\n' << event.socket.remote_port;
        const std::string event_key = key.str();
        const auto existing = network_events_.find(event_key);
        if (existing != network_events_.end()) {
            existing->second.last_seen = now;
            const auto pending = pending_network_binds_.find(event_key);
            if (pending != pending_network_binds_.end()) {
                active_pending_binds.insert(event_key);
                if (external_bind_persistence_reached(
                        steady_now - pending->second.first_seen)) {
                    if (persistent_network_patterns_alerted_.insert(
                            pending->second.pattern).second) {
                        record_alert("HIGH", "network.new-external-bind",
                                     pending->second.detail +
                                     "; this ephemeral wildcard UDP bind persisted "
                                     "for at least five seconds");
                    }
                    pending_network_binds_.erase(pending);
                }
            }
            continue;
        }
        if (network_events_.size() >= network_budget_.limit()) {
            current_dropped_events.insert(event_key);
            if (previous_dropped_network_events_.find(event_key) !=
                    previous_dropped_network_events_.end()) {
                continue;
            }
            (void)network_budget_.allow_new(network_events_.size());
            if (network_budget_.dropped() == 1) {
                record_degradation(
                    "retention.network-limit-reached",
                    "Network session retention reached its " +
                        std::to_string(network_budget_.limit()) +
                        "-record budget; additional sessions are counted but "
                        "not retained");
            }
            continue;
        }
        network_events_.emplace(event_key, event);

        const std::string detail = network_label(event);
        const std::string status = !baseline_loaded_ || !baseline_.network_calibrated
            ? "UNCALIBRATED "
            : (event.matched_baseline ? "CALIBRATED " : "NEW ");
        append_journal("[" + now + "] NETWORK " + status + detail + "\n");
        if (!baseline_loaded_ || !baseline_.network_calibrated ||
            event.matched_baseline) {
            continue;
        }
        const bool pattern_first_seen = new_network_patterns_.insert(pattern).second;

        const bool executable_calibrated = baseline_.executables.find(event.executable) !=
                                           baseline_.executables.end();
        const bool executable_reviewed = reviewed_executables_observed_.find(
                                             event.executable) !=
                                         reviewed_executables_observed_.end();
        const bool executable_trusted = executable_calibrated || executable_reviewed;
        if (externally_reachable(event.socket) &&
            defer_external_bind_alert(event.socket, executable_trusted) &&
            persistent_network_patterns_alerted_.find(pattern) ==
                persistent_network_patterns_alerted_.end()) {
            pending_network_binds_.emplace(
                event_key, PendingNetworkBind{steady_now, detail, pattern});
            active_pending_binds.insert(event_key);
            continue;
        }
        if (!pattern_first_seen) {
            continue;
        }
        if (!executable_calibrated && !executable_reviewed) {
            record_alert("HIGH", "network.unreviewed-executable",
                         detail + "; the executable was neither calibrated nor "
                         "fingerprint-reviewed");
        } else if (externally_reachable(event.socket)) {
            record_alert("HIGH", "network.new-external-bind",
                         detail +
                         "; this externally reachable bind was not calibrated");
        } else if (event.socket.role == "raw" || event.socket.role == "packet") {
            record_alert("HIGH", "network.new-low-level-socket",
                         detail + "; this raw/packet socket pattern was not calibrated");
        } else {
            record_alert("NOTICE", "network.not-in-baseline",
                         detail + "; this network behavior pattern was not calibrated");
        }
    }

    for (auto pending = pending_network_binds_.begin();
         pending != pending_network_binds_.end();) {
        if (active_pending_binds.find(pending->first) !=
            active_pending_binds.end()) {
            ++pending;
            continue;
        }
        if (persistent_network_patterns_alerted_.find(pending->second.pattern) ==
                persistent_network_patterns_alerted_.end() &&
            transient_network_patterns_noticed_.insert(
                pending->second.pattern).second) {
            record_alert("NOTICE", "network.transient-ephemeral-bind",
                         pending->second.detail +
                         "; this calibrated executable's ephemeral wildcard UDP bind "
                         "ended before the five-second persistence threshold");
        }
        pending = pending_network_binds_.erase(pending);
    }
    previous_dropped_network_events_ = std::move(current_dropped_events);
}

void Monitor::finalize_pending_network_binds() {
    for (const auto& [key, pending] : pending_network_binds_) {
        (void)key;
        if (persistent_network_patterns_alerted_.find(pending.pattern) ==
                persistent_network_patterns_alerted_.end() &&
            transient_network_patterns_noticed_.insert(pending.pattern).second) {
            record_alert("NOTICE", "network.transient-ephemeral-bind",
                         pending.detail +
                         "; monitoring ended before this calibrated executable's "
                         "ephemeral wildcard UDP bind reached the five-second "
                         "persistence threshold");
        }
    }
    pending_network_binds_.clear();
}

Baseline Monitor::collect_calibration(unsigned int idle_seconds,
                                      unsigned int media_seconds,
                                      const volatile std::sig_atomic_t& stop_requested) {
    Baseline result;
    result.created = timestamp(Clock::now());
    result.host = host_name();
    result.network_calibrated = true;
    result.scripts_calibrated = true;
    result.kernel_calibrated = true;
    std::cout << "Collecting the persistence baseline...\n";
    const PersistenceSnapshot persistence = collect_persistence(
        default_persistence_roots());
    if (persistence.truncated || !persistence.errors.empty()) {
        std::ostringstream detail;
        detail << "persistence inventory was incomplete";
        if (persistence.truncated) detail << " (record limit reached)";
        if (!persistence.errors.empty()) detail << ": " << persistence.errors.front();
        throw std::runtime_error(detail.str());
    }
    result.persistence_calibrated = true;
    result.persistence = persistence.records;
    std::cout << "Collecting the kernel-module and BPF baseline...\n";
    result.kernel = scan_kernel(true, true);

    auto collect_phase = [&](unsigned int seconds, bool media_phase) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(seconds);
        while (stop_requested == 0 && std::chrono::steady_clock::now() < deadline) {
            const auto snapshot = scan_processes();
            const auto pipewire_captures = scan_pipewire_captures(snapshot);
            const auto network_sockets = scan_network_sockets(snapshot);
            for (const auto& [pid, process] : snapshot) {
                (void)pid;
                if (!process.executable.empty()) {
                    auto position = result.executables.find(process.executable);
                    if (position == result.executables.end() || !position->second.valid) {
                        result.executables[process.executable] =
                            fingerprint_executable(process, true);
                    }
                }
                if (!process.script_entrypoint.empty()) {
                    auto position = result.scripts.find(process.script_entrypoint);
                    if (position == result.scripts.end() || !position->second.valid) {
                        result.scripts[process.script_entrypoint] =
                            fingerprint_script(process, true);
                    }
                }
                for (const std::string& device : process.media_handles) {
                    if (media_phase || !capture_device(device)) {
                        result.authorized_media.insert(
                            media_identity(process.executable, device));
                    } else {
                        calibration_idle_capture_.insert(
                            process_label(process) + " opened " + device);
                    }
                }
            }
            for (const PipeWireCapture& capture : pipewire_captures) {
                if (media_phase) {
                    result.authorized_pipewire_captures.insert(
                        pipewire_identity(capture));
                } else {
                    calibration_idle_capture_.insert(
                        "PipeWire application " + capture.application + " activated " +
                        capture.media_class);
                }
            }
            for (const NetworkEvent& event : network_sockets) {
                if (!event.executable.empty()) {
                    result.authorized_network.insert(
                        network_pattern(event.executable, event.socket));
                }
            }

            const auto wake = std::min(
                deadline, std::chrono::steady_clock::now() +
                              std::chrono::seconds(interval_seconds_));
            wait_until_or_stopped(wake, stop_requested);
        }
    };

    std::cout << "\nIDLE PHASE: leave the computer idle for " << idle_seconds
              << " seconds. Do not open the camera or microphone.\n";
    collect_phase(idle_seconds, false);
    if (stop_requested != 0) {
        return result;
    }

    std::cout << "\a\nMEDIA PHASE: for the next " << media_seconds
              << " seconds, open your trusted webcam and microphone applications now.\n"
              << "Keep them active until this phase ends.\n";
    collect_phase(media_seconds, true);
    return result;
}

void Monitor::save_baseline(const Baseline& baseline) const {
    const fs::path destination(baseline_path_);
    const fs::path directory = destination.has_parent_path()
        ? destination.parent_path() : fs::path(".");
    std::error_code error;
    const bool directory_created = fs::create_directories(directory, error);
    if (error) {
        throw std::runtime_error("cannot create baseline directory: " + error.message());
    }
    if (!fs::is_directory(directory)) {
        throw std::runtime_error("baseline parent is not a directory: " +
                                 directory.string());
    }
    if (directory_created) {
        fs::permissions(directory, fs::perms::owner_all,
                        fs::perm_options::replace, error);
        if (error) {
            throw std::runtime_error("cannot protect baseline directory: " +
                                     error.message());
        }
    }
    require_secure_directory(directory, "baseline directory");

    std::ostringstream serialized;
    serialized << "NIGHTWATCH_BASELINE 6\n"
               << "created " << std::quoted(baseline.created) << '\n'
               << "host " << std::quoted(baseline.host) << '\n'
               << "network_calibrated " << (baseline.network_calibrated ? 1 : 0)
               << '\n'
               << "kernel " << std::quoted(baseline.kernel.posture.release) << ' '
               << baseline.kernel.posture.taint << ' '
               << (baseline.kernel.posture.signature_enforcement ? 1 : 0) << ' '
               << std::quoted(baseline.kernel.posture.lockdown) << ' '
               << (baseline.kernel.bpf_available ? 1 : 0) << '\n';
    for (const auto& [executable, fingerprint] : baseline.executables) {
        serialized << "executable " << std::quoted(executable) << ' '
                   << (fingerprint.valid ? 1 : 0) << ' ' << fingerprint.device << ' '
                   << fingerprint.inode << ' ' << fingerprint.size << ' '
                   << fingerprint.modified_nanoseconds << ' ' << fingerprint.mode << ' '
                   << fingerprint.uid << ' ' << fingerprint.gid << ' '
                   << std::quoted(fingerprint.sha256) << '\n';
    }
    for (const auto& [script, fingerprint] : baseline.scripts) {
        serialized << "script " << std::quoted(script) << ' '
                   << (fingerprint.valid ? 1 : 0) << ' ' << fingerprint.device << ' '
                   << fingerprint.inode << ' ' << fingerprint.size << ' '
                   << fingerprint.modified_nanoseconds << ' ' << fingerprint.mode << ' '
                   << fingerprint.uid << ' ' << fingerprint.gid << ' '
                   << std::quoted(fingerprint.sha256) << '\n';
    }
    for (const std::string& identity : baseline.authorized_media) {
        const std::size_t separator = identity.find('\n');
        if (separator != std::string::npos) {
            serialized << "media " << std::quoted(identity.substr(0, separator)) << ' '
                       << std::quoted(identity.substr(separator + 1)) << '\n';
        }
    }
    for (const std::string& identity : baseline.authorized_pipewire_captures) {
        std::istringstream parts(identity);
        std::string uid;
        std::string executable;
        std::string application;
        std::string media_class;
        std::string node_name;
        std::getline(parts, uid);
        std::getline(parts, executable);
        std::getline(parts, application);
        std::getline(parts, media_class);
        std::getline(parts, node_name);
        serialized << "pipewire " << uid << ' ' << std::quoted(executable) << ' '
                   << std::quoted(application) << ' ' << std::quoted(media_class) << ' '
                   << std::quoted(node_name) << '\n';
    }
    for (const NetworkPattern& pattern : baseline.authorized_network) {
        serialized << "network " << std::quoted(pattern.executable) << ' '
                   << std::quoted(pattern.protocol) << ' '
                   << std::quoted(pattern.role) << ' '
                   << std::quoted(pattern.bind_scope) << ' '
                   << pattern.local_port << ' ' << pattern.remote_port << '\n';
    }
    for (const auto& [name, module] : baseline.kernel.modules) {
        serialized << "module " << std::quoted(name) << ' '
                   << std::quoted(module.path) << ' ' << std::quoted(module.sha256) << ' '
                   << std::quoted(module.signer) << ' '
                   << std::quoted(module.version_magic) << ' '
                   << (module.in_tree ? 1 : 0) << ' '
                   << (module.resolved ? 1 : 0) << ' '
                   << (module.file_secure ? 1 : 0) << '\n';
    }
    for (const BpfProgram& program : baseline.kernel.bpf_programs) {
        serialized << "bpf " << std::quoted(program.type) << ' '
                   << std::quoted(program.name) << ' ' << std::quoted(program.tag) << ' '
                   << std::quoted(program.owner) << '\n';
    }
    for (const auto& [path, record] : baseline.persistence) {
        const ExecutableFingerprint& fingerprint = record.fingerprint;
        serialized << "persistence " << std::quoted(path) << ' '
                   << std::quoted(persistence_kind_name(record.kind)) << ' '
                   << (record.symlink ? 1 : 0) << ' '
                   << std::quoted(record.symlink_target) << ' '
                   << (fingerprint.valid ? 1 : 0) << ' '
                   << fingerprint.device << ' ' << fingerprint.inode << ' '
                   << fingerprint.size << ' ' << fingerprint.modified_nanoseconds
                   << ' ' << fingerprint.mode << ' ' << fingerprint.uid << ' '
                   << fingerprint.gid << ' ' << std::quoted(fingerprint.sha256)
                   << '\n';
    }

    fs::path temporary;
    int descriptor = -1;
    for (unsigned int suffix = 0; descriptor < 0; ++suffix) {
        temporary = destination.string() + ".tmp-" + std::to_string(getpid()) +
                    "-" + std::to_string(suffix);
        descriptor = open(temporary.c_str(),
                          O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (descriptor < 0 && errno != EEXIST) {
            throw std::runtime_error("cannot create temporary baseline: " +
                                     std::string(std::strerror(errno)));
        }
    }
    try {
        write_all(descriptor, serialized.str(), "baseline");
        if (fsync(descriptor) != 0) {
            throw std::runtime_error("cannot synchronize baseline: " +
                                     std::string(std::strerror(errno)));
        }
        if (close(descriptor) != 0) {
            descriptor = -1;
            throw std::runtime_error("cannot finalize baseline: " +
                                     std::string(std::strerror(errno)));
        }
        descriptor = -1;
    } catch (...) {
        if (descriptor >= 0) {
            close(descriptor);
        }
        fs::remove(temporary, error);
        throw;
    }
    fs::rename(temporary, destination, error);
    if (error) {
        fs::remove(temporary);
        throw std::runtime_error("cannot install baseline: " + error.message());
    }
    synchronize_directory(directory, "baseline directory");
}

bool Monitor::load_baseline() {
    const int descriptor = open(baseline_path_.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        if (errno == ENOENT) {
            return false;
        }
        throw std::runtime_error("cannot open baseline securely: " +
                                 std::string(std::strerror(errno)));
    }
    struct stat details {};
    if (fstat(descriptor, &details) != 0) {
        const std::string reason = std::strerror(errno);
        close(descriptor);
        throw std::runtime_error("cannot inspect baseline: " + reason);
    }
    if (!S_ISREG(details.st_mode)) {
        close(descriptor);
        throw std::runtime_error("baseline is not a regular file: " + baseline_path_);
    }
    if ((details.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(descriptor);
        throw std::runtime_error("baseline must not be writable by group or others");
    }
    if (geteuid() == 0 && details.st_uid != 0) {
        close(descriptor);
        throw std::runtime_error("root will not trust a baseline not owned by root");
    }
    constexpr off_t maximum_baseline_size = 16 * 1024 * 1024;
    if (details.st_size < 0 || details.st_size > maximum_baseline_size) {
        close(descriptor);
        throw std::runtime_error("baseline file is unreasonably large");
    }
    std::string contents;
    contents.resize(static_cast<std::size_t>(details.st_size));
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const ssize_t count = read(descriptor, contents.data() + offset,
                                   contents.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            const std::string reason = count == 0 ? "unexpected end of file" :
                                                   std::strerror(errno);
            close(descriptor);
            throw std::runtime_error("cannot read baseline: " + reason);
        }
        offset += static_cast<std::size_t>(count);
    }
    close(descriptor);
    std::istringstream input(contents);
    std::string header;
    std::getline(input, header);
    const bool baseline_v2 = header == "NIGHTWATCH_BASELINE 2";
    const bool baseline_v3 = header == "NIGHTWATCH_BASELINE 3";
    const bool baseline_v4 = header == "NIGHTWATCH_BASELINE 4";
    const bool baseline_v5 = header == "NIGHTWATCH_BASELINE 5";
    const bool baseline_v6 = header == "NIGHTWATCH_BASELINE 6";
    if (!input || (!baseline_v2 && !baseline_v3 && !baseline_v4 &&
                   !baseline_v5 && !baseline_v6)) {
        throw std::runtime_error(
            "unsupported baseline format; run "
            "'sudo /usr/local/sbin/nightwatch calibrate' after upgrading");
    }

    Baseline loaded;
    loaded.scripts_calibrated = baseline_v4 || baseline_v5 || baseline_v6;
    loaded.kernel_calibrated = baseline_v5 || baseline_v6;
    loaded.persistence_calibrated = baseline_v6;
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string type;
        fields >> type;
        if (type == "created") {
            fields >> std::quoted(loaded.created);
        } else if (type == "host") {
            fields >> std::quoted(loaded.host);
        } else if (type == "network_calibrated") {
            int calibrated = 0;
            fields >> calibrated;
            if (calibrated != 0 && calibrated != 1) {
                throw std::runtime_error("invalid network calibration marker in baseline");
            }
            loaded.network_calibrated = calibrated == 1;
        } else if (type == "executable") {
            std::string executable;
            int valid = 0;
            ExecutableFingerprint fingerprint;
            fields >> std::quoted(executable) >> valid >> fingerprint.device >>
                fingerprint.inode >> fingerprint.size >> fingerprint.modified_nanoseconds >>
                fingerprint.mode >> fingerprint.uid >> fingerprint.gid >>
                std::quoted(fingerprint.sha256);
            fingerprint.valid = valid == 1;
            if (valid != 0 && valid != 1) {
                throw std::runtime_error("damaged executable fingerprint in baseline");
            }
            if (executable.empty() || (fingerprint.valid && fingerprint.sha256.size() != 64)) {
                throw std::runtime_error("invalid executable fingerprint in baseline");
            }
            loaded.executables.emplace(std::move(executable), std::move(fingerprint));
        } else if (type == "script") {
            if (!baseline_v4 && !baseline_v5 && !baseline_v6) {
                throw std::runtime_error("script entry in an older baseline format");
            }
            std::string script;
            int valid = 0;
            ExecutableFingerprint fingerprint;
            fields >> std::quoted(script) >> valid >> fingerprint.device >>
                fingerprint.inode >> fingerprint.size >> fingerprint.modified_nanoseconds >>
                fingerprint.mode >> fingerprint.uid >> fingerprint.gid >>
                std::quoted(fingerprint.sha256);
            fingerprint.valid = valid == 1;
            if (valid != 0 && valid != 1) {
                throw std::runtime_error("damaged script fingerprint in baseline");
            }
            if (script.empty() || script[0] != '/' ||
                (fingerprint.valid && fingerprint.sha256.size() != 64)) {
                throw std::runtime_error("invalid script fingerprint in baseline");
            }
            loaded.scripts.emplace(std::move(script), std::move(fingerprint));
        } else if (type == "media") {
            std::string executable;
            std::string device;
            fields >> std::quoted(executable) >> std::quoted(device);
            loaded.authorized_media.insert(media_identity(executable, device));
        } else if (type == "pipewire") {
            unsigned int uid = 0;
            PipeWireCapture capture;
            fields >> uid >> std::quoted(capture.executable) >>
                std::quoted(capture.application) >> std::quoted(capture.media_class) >>
                std::quoted(capture.node_name);
            capture.uid = uid;
            loaded.authorized_pipewire_captures.insert(pipewire_identity(capture));
        } else if (type == "network") {
            NetworkPattern pattern;
            fields >> std::quoted(pattern.executable) >>
                std::quoted(pattern.protocol) >> std::quoted(pattern.role) >>
                std::quoted(pattern.bind_scope) >> pattern.local_port >>
                pattern.remote_port;
            if (pattern.executable.empty() || pattern.protocol.empty() ||
                pattern.role.empty() || pattern.local_port > 65535 ||
                pattern.remote_port > 65535) {
                throw std::runtime_error("invalid network pattern in baseline");
            }
            loaded.authorized_network.insert(
                normalize_network_pattern(std::move(pattern)));
        } else if (type == "kernel") {
            if (!baseline_v5 && !baseline_v6) throw std::runtime_error("kernel entry in older baseline");
            int enforcement = 0;
            int bpf_available = 0;
            fields >> std::quoted(loaded.kernel.posture.release) >>
                loaded.kernel.posture.taint >> enforcement >>
                std::quoted(loaded.kernel.posture.lockdown) >> bpf_available;
            if ((enforcement != 0 && enforcement != 1) ||
                (bpf_available != 0 && bpf_available != 1) ||
                loaded.kernel.posture.release.empty()) {
                throw std::runtime_error("invalid kernel posture in baseline");
            }
            loaded.kernel.posture.signature_enforcement = enforcement == 1;
            loaded.kernel.bpf_available = bpf_available == 1;
        } else if (type == "module") {
            if (!baseline_v5 && !baseline_v6) throw std::runtime_error("module entry in older baseline");
            KernelModule module;
            int in_tree = 0, resolved = 0, secure = 0;
            fields >> std::quoted(module.name) >> std::quoted(module.path) >>
                std::quoted(module.sha256) >> std::quoted(module.signer) >>
                std::quoted(module.version_magic) >> in_tree >> resolved >> secure;
            if (module.name.empty() || (in_tree != 0 && in_tree != 1) ||
                (resolved != 0 && resolved != 1) || (secure != 0 && secure != 1) ||
                (resolved == 1 && module.sha256.size() != 64)) {
                throw std::runtime_error("invalid kernel module in baseline");
            }
            module.in_tree = in_tree == 1;
            module.resolved = resolved == 1;
            module.file_secure = secure == 1;
            loaded.kernel.modules.emplace(module.name, std::move(module));
        } else if (type == "bpf") {
            if (!baseline_v5 && !baseline_v6) throw std::runtime_error("BPF entry in older baseline");
            BpfProgram program;
            fields >> std::quoted(program.type) >> std::quoted(program.name) >>
                std::quoted(program.tag) >> std::quoted(program.owner);
            if (program.type.empty() || program.tag.empty()) {
                throw std::runtime_error("invalid BPF program in baseline");
            }
            loaded.kernel.bpf_programs.insert(std::move(program));
        } else if (type == "persistence") {
            if (!baseline_v6) {
                throw std::runtime_error("persistence entry in older baseline");
            }
            PersistenceRecord record;
            std::string kind;
            int symlink = 0;
            int valid = 0;
            fields >> std::quoted(record.path) >> std::quoted(kind) >> symlink >>
                std::quoted(record.symlink_target) >> valid >>
                record.fingerprint.device >> record.fingerprint.inode >>
                record.fingerprint.size >>
                record.fingerprint.modified_nanoseconds >> record.fingerprint.mode >>
                record.fingerprint.uid >> record.fingerprint.gid >>
                std::quoted(record.fingerprint.sha256);
            record.symlink = symlink == 1;
            record.fingerprint.valid = valid == 1;
            if (record.path.empty() || record.path[0] != '/' ||
                (symlink != 0 && symlink != 1) || (valid != 0 && valid != 1) ||
                !parse_persistence_kind(kind, record.kind) ||
                (!record.symlink && record.fingerprint.valid &&
                 record.fingerprint.sha256.size() != 64) ||
                (record.symlink && record.symlink_target.empty())) {
                throw std::runtime_error("invalid persistence record in baseline");
            }
            loaded.persistence.emplace(record.path, std::move(record));
        } else if (!type.empty()) {
            throw std::runtime_error("unknown entry in baseline file: " + type);
        }
        if (!fields && !type.empty()) {
            throw std::runtime_error("damaged entry in baseline file");
        }
    }
    if (loaded.host != host_name()) {
        throw std::runtime_error("baseline belongs to host " + loaded.host +
                                 ", not " + host_name());
    }
    baseline_ = std::move(loaded);
    baseline_loaded_ = true;
    return true;
}

bool Monitor::load_reviewed() {
    ReviewedExecutableFile loaded = load_reviewed_executables(reviewed_path_);
    if (!loaded.loaded) {
        return false;
    }
    reviewed_executables_ = std::move(loaded.entries);
    reviewed_scripts_ = std::move(loaded.scripts);
    reviewed_loaded_ = true;
    return true;
}

int Monitor::calibrate(unsigned int idle_seconds, unsigned int media_seconds,
                       const volatile std::sig_atomic_t& stop_requested) {
    if (geteuid() != 0) {
        std::cout << "Warning: calibration is not running as root; process visibility may be limited.\n";
    }
    std::cout << "Nightwatch calibration will create: " << baseline_path_ << "\n"
              << "Press Ctrl-C at any time to cancel without replacing the baseline.\n";
    const Baseline baseline = collect_calibration(idle_seconds, media_seconds,
                                                  stop_requested);
    if (stop_requested != 0) {
        std::cout << "\nCalibration cancelled; the existing baseline was not changed.\n";
        return 130;
    }
    if (!calibration_idle_capture_.empty()) {
        std::cerr << "\nCalibration refused: capture activity was detected during the idle phase:\n";
        for (const std::string& detail : calibration_idle_capture_) {
            std::cerr << "  - " << detail << '\n';
        }
        std::cerr << "Close all recording/camera applications and calibrate again. "
                     "The existing baseline was not changed.\n";
        return 3;
    }
    save_baseline(baseline);
    std::cout << "\a\nCalibration complete.\n"
              << "Known executable paths: " << baseline.executables.size() << '\n'
              << "Known script entrypoints: " << baseline.scripts.size() << '\n'
              << "Authorized direct media patterns: " << baseline.authorized_media.size() << '\n'
              << "Authorized PipeWire capture patterns: "
              << baseline.authorized_pipewire_captures.size() << '\n'
              << "Authorized network behavior patterns: "
              << baseline.authorized_network.size() << '\n'
              << "Loaded kernel modules fingerprinted: "
              << baseline.kernel.modules.size() << '\n'
              << "BPF program identities calibrated: "
              << baseline.kernel.bpf_programs.size() << '\n'
              << "Persistence records fingerprinted: "
              << baseline.persistence.size() << '\n'
              << "Baseline saved to: " << fs::absolute(baseline_path_).string() << '\n';
    return 0;
}

void Monitor::record_alert(const std::string& severity, const std::string& rule,
                           const std::string& detail) {
    const std::string key = rule + "\n" + detail;
    if (alert_keys_.find(key) != alert_keys_.end()) {
        return;
    }
    if (!finding_budget_.allow_new(findings_.size())) {
        if (finding_budget_.dropped() == 1) {
            record_degradation(
                "retention.finding-limit-reached",
                "Finding retention reached its " +
                    std::to_string(finding_budget_.limit()) +
                    "-record budget; additional distinct findings are counted "
                    "but not retained");
        }
        return;
    }
    alert_keys_.insert(key);
    const std::string now = timestamp(Clock::now());
    const FindingPriority priority = finding_priority(severity);
    const RuleMetadata metadata = rule_metadata(rule, priority);
    findings_.push_back({
        now,
        domain_for_rule(rule),
        priority,
        metadata.classification,
        rule,
        metadata.title,
        detail,
        metadata.rationale,
        metadata.recommended_action
    });
    append_journal("[" + now + "] ALERT " + severity + " " + rule + "\n  " +
                   detail + "\n");
}

void Monitor::record_degradation(const std::string& rule,
                                 const std::string& detail,
                                 bool session_critical,
                                 bool write_journal) {
    const std::string key = rule + "\n" + detail;
    const auto existing = degradation_indexes_.find(key);
    if (existing != degradation_indexes_.end()) {
        std::uint64_t& count = degradations_[existing->second].count;
        if (count != std::numeric_limits<std::uint64_t>::max()) {
            ++count;
        }
        return;
    }
    if (!degradation_budget_.allow_new(degradations_.size())) {
        const std::string limit_rule = "retention.degradation-limit-reached";
        const std::string limit_detail =
            "Degradation retention reached its 1024-record budget; additional "
            "unique degradation records are counted but not retained";
        const std::string limit_key = limit_rule + "\n" + limit_detail;
        const auto limit_existing = degradation_indexes_.find(limit_key);
        if (limit_existing != degradation_indexes_.end()) {
            degradations_[limit_existing->second].count =
                degradation_budget_.dropped();
            return;
        }
        const std::string now = timestamp(Clock::now());
        degradation_indexes_[limit_key] = degradations_.size();
        degradations_.push_back({
            now, MonitoringDomain::retention, limit_rule, limit_detail,
            degradation_budget_.dropped(), false});
        if (write_journal) {
            append_journal("[" + now + "] DEGRADATION " +
                           domain_name(MonitoringDomain::retention) + " " +
                           limit_rule + "\n  " + limit_detail + "\n");
        }
        return;
    }
    const std::string now = timestamp(Clock::now());
    degradation_indexes_[key] = degradations_.size();
    degradations_.push_back({now, domain_for_rule(rule), rule, detail, 1,
                             session_critical});
    if (write_journal) {
        append_journal("[" + now + "] DEGRADATION " +
                       domain_name(domain_for_rule(rule)) + " " + rule +
                       "\n  " + detail + "\n");
    }
}

void Monitor::record_phase_timing(const std::string& phase,
                                  SteadyClock::duration elapsed) {
    const auto value = std::chrono::duration_cast<std::chrono::microseconds>(
        elapsed).count();
    if (value < 0) {
        return;
    }
    const auto microseconds = static_cast<std::uint64_t>(value);
    TimingSummary& timing = phase_timings_[phase];
    ++timing.invocations;
    if (std::numeric_limits<std::uint64_t>::max() - timing.total_microseconds <
        microseconds) {
        timing.total_microseconds = std::numeric_limits<std::uint64_t>::max();
    } else {
        timing.total_microseconds += microseconds;
    }
    timing.maximum_microseconds = std::max(
        timing.maximum_microseconds, microseconds);
}

void Monitor::inspect_snapshot(const std::map<int, ProcessInfo>& current) {
    const std::string now = timestamp(Clock::now());
    std::set<std::string> verified_this_snapshot;
    std::set<std::string> scripts_verified_this_snapshot;
    std::set<std::string> current_dropped_media_events;
    const bool background_hash_due = std::chrono::steady_clock::now() >=
                                     next_background_hash_;
    unsigned int background_hash_budget = background_hash_due ? 1U : 0U;
    for (const auto& [pid, process] : current) {
        const auto previous = previous_.find(pid);
        const bool newly_seen = previous == previous_.end() ||
                                previous->second.start_time_ticks != process.start_time_ticks;
        if (!process.executable.empty()) {
            observed_executables_.insert(process.executable);
        }

        const bool absent_from_baseline = baseline_loaded_ &&
            !process.executable.empty() &&
            baseline_.executables.find(process.executable) ==
                baseline_.executables.end();
        ReviewedStatus review = ReviewedStatus::not_reviewed;
        if (absent_from_baseline && reviewed_loaded_) {
            review = verify_reviewed_executable(process, verified_this_snapshot);
        }
        if (absent_from_baseline && review == ReviewedStatus::not_reviewed &&
            new_executables_.insert(process.executable).second) {
            record_alert("NOTICE", "process.not-in-baseline",
                         process_label(process) +
                         " was not observed during calibration or reviewed separately");
        }
        if (baseline_loaded_) {
            verify_executable(process, verified_this_snapshot, background_hash_budget);
        }

        if (!process.script_entrypoint.empty()) {
            observed_scripts_.insert(process.script_entrypoint);
            if (baseline_loaded_ && baseline_.scripts_calibrated) {
                const bool script_absent =
                    baseline_.scripts.find(process.script_entrypoint) ==
                    baseline_.scripts.end();
                ReviewedStatus script_review = ReviewedStatus::not_reviewed;
                if (script_absent && reviewed_loaded_) {
                    script_review = verify_reviewed_script(
                        process, scripts_verified_this_snapshot);
                }
                if (script_absent &&
                    script_review == ReviewedStatus::not_reviewed &&
                    new_scripts_.insert(process.script_entrypoint).second) {
                    record_alert("NOTICE", "script.not-in-baseline",
                                 script_label(process) +
                                 " was not observed during calibration or "
                                 "reviewed separately");
                }
                verify_script(process, scripts_verified_this_snapshot,
                              background_hash_budget);
            }
            if (newly_seen && unusual_location(process.script_entrypoint)) {
                record_alert("HIGH", "script.unusual-location",
                             script_label(process) +
                             " resides in a writable runtime directory");
            }
        }

        if (newly_seen && unusual_location(process.executable)) {
            record_alert("HIGH", "process.unusual-location",
                         process_label(process) + " started from a writable runtime directory");
        }
        if (process.executable.find(" (deleted)") != std::string::npos) {
            record_alert("HIGH", "process.deleted-executable",
                         process_label(process) + " is running from a deleted executable");
        }

        for (const std::string& device : process.media_handles) {
            const std::string base = std::to_string(pid) + "\n" +
                std::to_string(process.start_time_ticks) + "\n" + process.executable +
                "\n" + device;
            const bool continued = previous != previous_.end() &&
                previous->second.start_time_ticks == process.start_time_ticks &&
                previous->second.media_handles.find(device) !=
                    previous->second.media_handles.end();
            if (continued && previous_dropped_media_events_.find(base) !=
                                 previous_dropped_media_events_.end()) {
                current_dropped_media_events.insert(base);
                continue;
            }
            const bool matched_baseline = baseline_loaded_ &&
                baseline_.authorized_media.find(
                    media_identity(process.executable, device)) !=
                baseline_.authorized_media.end();
            const std::string detail = process_label(process) + " opened " + device;
            if (!continued && !media_budget_.allow_new(media_events_.size())) {
                current_dropped_media_events.insert(base);
                if (media_budget_.dropped() == 1) {
                    record_degradation(
                        "retention.media-limit-reached",
                        "Direct media-session retention reached its " +
                            std::to_string(media_budget_.limit()) +
                            "-record budget; additional sessions are counted but "
                            "not retained");
                }
                if (baseline_loaded_ && !matched_baseline) {
                    record_alert("HIGH", "media.not-in-baseline",
                                 detail + "; this process/device combination was "
                                 "not calibrated");
                } else if (!baseline_loaded_) {
                    record_alert("NOTICE", "media.direct-device-access", detail);
                }
                continue;
            }
            unsigned int& session = media_session_counts_[base];
            if (!continued) {
                ++session;
            }
            const std::string key = base + "\n" + std::to_string(session);
            auto [position, inserted] = media_events_.try_emplace(
                key, MediaEvent{now, now, pid, process.uid, process.executable,
                                device, matched_baseline});
            position->second.last_seen = now;
            if (inserted) {
                append_journal("[" + now + "] MEDIA " +
                               (matched_baseline ? "CALIBRATED " : "NEW ") +
                               detail + "\n");
                if (baseline_loaded_ && !matched_baseline) {
                    record_alert("HIGH", "media.not-in-baseline",
                                 detail + "; this process/device combination was "
                                 "not calibrated");
                } else if (!baseline_loaded_) {
                    record_alert("NOTICE", "media.direct-device-access", detail);
                }
            }
        }
    }
    if (background_hash_due && background_hash_budget == 0) {
        next_background_hash_ = std::chrono::steady_clock::now() +
                                std::chrono::seconds(10);
    }
    previous_dropped_media_events_ = std::move(current_dropped_media_events);
    previous_ = current;
    ++scans_;
}

int Monitor::run(const volatile std::sig_atomic_t& stop_requested) {
    const bool loaded = load_baseline();
    const bool reviewed_loaded = load_reviewed();
    started_ = Clock::now();
    steady_started_ = SteadyClock::now();
    start_report();
    next_checkpoint_ = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    next_background_hash_ = std::chrono::steady_clock::now() +
                            std::chrono::seconds(10);
    next_kernel_integrity_check_ = std::chrono::steady_clock::now();
    next_bpf_check_ = std::chrono::steady_clock::now();
    next_persistence_check_ = std::chrono::steady_clock::now();
    next_authentication_check_ = std::chrono::steady_clock::now();
    std::cout << "Nightwatch started at " << timestamp(started_) << ".\n"
              << "Read-only monitoring is active; press Ctrl-C to stop and create the report.\n"
              << "Sampling every " << interval_seconds_ << " second(s).\n";
    if (loaded) {
        std::cout << "Using baseline from " << baseline_path_ << " (created "
                  << baseline_.created << ").\n";
    } else {
        std::cout << "Warning: no baseline found at " << baseline_path_
                  << "; observations will be uncalibrated.\n";
    }
    if (reviewed_loaded) {
        std::cout << "Using " << reviewed_executables_.size()
                  << " reviewed executable and " << reviewed_scripts_.size()
                  << " reviewed script fingerprint(s) from "
                  << reviewed_path_ << ".\n";
    } else {
        std::cout << "No reviewed-fingerprint file found at " << reviewed_path_
                  << ".\n";
    }
    if (loaded && baseline_.network_calibrated) {
        std::cout << "Network baseline contains "
                  << baseline_.authorized_network.size()
                  << " behavior pattern(s).\n";
    } else {
        std::cout << "Network monitoring is uncalibrated; recalibrate before "
                     "interpreting new network behavior.\n";
        record_degradation(
            "network.baseline-unavailable",
            "Network socket observation is active, but this baseline contains no "
            "calibrated network behavior patterns");
    }
    if (loaded && baseline_.scripts_calibrated) {
        std::cout << "Script baseline contains " << baseline_.scripts.size()
                  << " entrypoint fingerprint(s).\n";
    } else {
        std::cout << "Script-entrypoint monitoring is uncalibrated; recalibrate "
                     "with baseline version 4.\n";
        record_degradation(
            "script.baseline-unavailable",
            "Script entrypoints are observed, but this baseline contains no "
            "calibrated script fingerprints");
    }
    if (loaded && baseline_.kernel_calibrated) {
        std::cout << "Kernel baseline contains " << baseline_.kernel.modules.size()
                  << " module fingerprint(s) and "
                  << baseline_.kernel.bpf_programs.size() << " BPF identity record(s).\n";
    } else {
        std::cout << "Kernel/BPF monitoring is uncalibrated; recalibrate with "
                     "the current baseline format.\n";
        record_degradation(
            "kernel.baseline-unavailable",
            "Kernel and BPF state are observed, but this baseline contains no "
            "calibrated kernel inventory");
    }
    if (loaded && baseline_.persistence_calibrated) {
        std::cout << "Persistence baseline contains "
                  << baseline_.persistence.size() << " startup record(s).\n";
    } else {
        std::cout << "Persistence monitoring is uncalibrated; recalibrate with "
                     "baseline version 6.\n";
        record_degradation(
            "persistence.baseline-unavailable",
            "Persistence locations are observed, but this baseline contains no "
            "calibrated persistence inventory");
    }
    initialize_authentication();
    std::cout << "Authentication evidence: journal "
              << (authentication_status_.journal_available ? "available" : "unavailable")
              << ", session state "
              << (authentication_status_.session_state_available ? "available"
                                                                  : "unavailable")
              << ".\n";

    const auto sampling_interval = std::chrono::seconds(interval_seconds_);
    auto next_sampling_deadline = SteadyClock::now() + sampling_interval;
    while (stop_requested == 0) {
        const auto loop_started = SteadyClock::now();
        const auto deadline = next_sampling_deadline;
        std::map<int, ProcessInfo> snapshot;
        std::vector<PipeWireCapture> pipewire_captures;
        std::vector<NetworkEvent> network_sockets;
        try {
            auto phase_started = SteadyClock::now();
            snapshot = scan_processes();
            record_phase_timing("process collection", SteadyClock::now() - phase_started);
            phase_started = SteadyClock::now();
            pipewire_captures = scan_pipewire_captures(snapshot);
            record_phase_timing("PipeWire collection", SteadyClock::now() - phase_started);
            phase_started = SteadyClock::now();
            network_sockets = scan_network_sockets(snapshot);
            record_phase_timing("network collection", SteadyClock::now() - phase_started);
        } catch (const std::exception& error) {
            ++failed_snapshots_;
            record_degradation(
                "monitor.snapshot-failed",
                std::string("A snapshot was skipped after a transient read ") +
                "failure: " + error.what());
            wait_until_or_stopped(deadline, stop_requested);
            next_sampling_deadline += sampling_interval;
            continue;
        }
        auto phase_started = SteadyClock::now();
        inspect_snapshot(snapshot);
        record_phase_timing("process and integrity policy",
                            SteadyClock::now() - phase_started);
        phase_started = SteadyClock::now();
        inspect_pipewire(pipewire_captures);
        record_phase_timing("PipeWire policy", SteadyClock::now() - phase_started);
        phase_started = SteadyClock::now();
        inspect_network(network_sockets);
        record_phase_timing("network policy", SteadyClock::now() - phase_started);
        phase_started = SteadyClock::now();
        inspect_kernel();
        record_phase_timing("kernel and BPF policy", SteadyClock::now() - phase_started);
        phase_started = SteadyClock::now();
        inspect_persistence();
        record_phase_timing("persistence policy", SteadyClock::now() - phase_started);
        phase_started = SteadyClock::now();
        inspect_authentication();
        record_phase_timing("authentication/session policy",
                            SteadyClock::now() - phase_started);
        if (std::chrono::steady_clock::now() >= next_checkpoint_) {
            write_checkpoint();
            next_checkpoint_ = std::chrono::steady_clock::now() +
                               std::chrono::seconds(60);
        }
        const auto scan_finished = SteadyClock::now();
        const auto scan_microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            scan_finished - loop_started).count();
        if (scan_microseconds > 0) {
            maximum_scan_microseconds_ = std::max(
                maximum_scan_microseconds_,
                static_cast<std::uint64_t>(scan_microseconds));
        }
        if (scan_finished > deadline) {
            const auto overrun = std::chrono::duration_cast<std::chrono::microseconds>(
                scan_finished - deadline).count();
            const auto overrun_us = static_cast<std::uint64_t>(overrun);
            ++deadline_overruns_;
            if (std::numeric_limits<std::uint64_t>::max() -
                    cumulative_overrun_microseconds_ < overrun_us) {
                cumulative_overrun_microseconds_ =
                    std::numeric_limits<std::uint64_t>::max();
            } else {
                cumulative_overrun_microseconds_ += overrun_us;
            }
            maximum_overrun_microseconds_ = std::max(
                maximum_overrun_microseconds_, overrun_us);
        }
        wait_until_or_stopped(deadline, stop_requested);
        next_sampling_deadline += sampling_interval;
    }

    stopped_ = Clock::now();
    steady_stopped_ = SteadyClock::now();
    if (cadence_visibility_degraded(session_metadata())) {
        std::ostringstream detail;
        detail << deadline_overruns_ << " sampling cycle(s) exceeded the "
               << interval_seconds_ << "-second deadline; cumulative lateness was "
               << cumulative_overrun_microseconds_ / 1000U
               << " ms, maximum lateness was "
               << maximum_overrun_microseconds_ / 1000U
               << " ms, and the slowest scan took "
               << maximum_scan_microseconds_ / 1000U << " ms";
        record_degradation("monitor.cadence-overrun", detail.str());
    }
    std::map<int, ProcessInfo> final_snapshot = previous_;
    try {
        auto candidate = scan_processes();
        const auto final_pipewire_captures = scan_pipewire_captures(candidate);
        const auto final_network_sockets = scan_network_sockets(candidate);
        inspect_snapshot(candidate);
        inspect_pipewire(final_pipewire_captures);
        inspect_network(final_network_sockets);
        inspect_kernel();
        inspect_persistence(true);
        inspect_authentication(true);
        final_snapshot = std::move(candidate);
    } catch (const std::exception& error) {
        ++failed_snapshots_;
        record_degradation(
            "monitor.final-snapshot-failed",
            std::string("The final snapshot failed; the report uses the last ") +
            "successful snapshot: " + error.what());
    }
    finalize_pending_network_binds();
    std::string json_path;
    try {
        json_path = save_json_report(build_json_report());
    } catch (const std::exception& error) {
        record_degradation(
            "report.json-write-failed",
            std::string("The versioned JSON report could not be finalized: ") +
                error.what());
    }
    const std::string report = build_report(final_snapshot);
    const std::string path = save_report(report);
    std::cout << "\n" << report << "\nReport saved to: " << path << '\n';
    if (!json_path.empty()) {
        std::cout << "JSON report saved to: " << json_path << '\n';
    }
    return 0;
}

std::string Monitor::build_json_report() const {
    const SessionMetadata metadata = session_metadata();
    return render_json_report(
        metadata, findings_, degradations_,
        summarize_domains(findings_, degradations_), authentication_status_,
        authentication_events_, authentication_sessions_);
}

SessionMetadata Monitor::session_metadata() const {
    const auto monotonic_duration = std::chrono::duration_cast<std::chrono::seconds>(
        steady_stopped_ - steady_started_).count();
    const auto wall_duration = std::chrono::duration_cast<std::chrono::seconds>(
        stopped_ - started_).count();
    SessionMetadata metadata{
        host_name(),
        kernel_name(),
        timestamp(started_),
        timestamp(stopped_),
        baseline_loaded_ ? baseline_path_ : std::string{},
        baseline_loaded_ ? baseline_.created : std::string{},
        monotonic_duration < 0 ? 0U
                               : static_cast<std::uint64_t>(monotonic_duration),
        scans_,
        failed_snapshots_,
        interval_seconds_,
        wall_duration < 0 ? 0U : static_cast<std::uint64_t>(wall_duration),
        deadline_overruns_,
        cumulative_overrun_microseconds_,
        maximum_overrun_microseconds_,
        maximum_scan_microseconds_,
        {},
        {}
    };
    for (const auto& [phase, timing] : phase_timings_) {
        metadata.phase_timings.push_back({
            phase, timing.invocations, timing.total_microseconds,
            timing.maximum_microseconds});
    }
    metadata.retention = {
        {static_cast<std::uint64_t>(findings_.size()),
         static_cast<std::uint64_t>(finding_budget_.limit()),
         finding_budget_.dropped()},
        {static_cast<std::uint64_t>(degradations_.size()),
         static_cast<std::uint64_t>(degradation_budget_.limit() + 1U),
         degradation_budget_.dropped()},
        {static_cast<std::uint64_t>(media_events_.size()),
         static_cast<std::uint64_t>(media_budget_.limit()),
         media_budget_.dropped()},
        {static_cast<std::uint64_t>(pipewire_events_.size()),
         static_cast<std::uint64_t>(pipewire_budget_.limit()),
         pipewire_budget_.dropped()},
        {static_cast<std::uint64_t>(network_events_.size()),
         static_cast<std::uint64_t>(network_budget_.limit()),
         network_budget_.dropped()},
        {static_cast<std::uint64_t>(authentication_events_.size()),
         static_cast<std::uint64_t>(authentication_budget_.limit()),
         authentication_budget_.dropped()},
        journal_budget_.written_bytes(),
        journal_budget_.maximum_bytes(),
        journal_budget_.dropped_entries()
    };
    return metadata;
}

std::string Monitor::build_report(const std::map<int, ProcessInfo>& final_snapshot) const {
    const SessionMetadata metadata = session_metadata();
    std::ostringstream output;
    output << "Nightwatch monitoring report\n"
           << "============================\n"
           << "Host: " << metadata.host << '\n'
           << "Kernel: " << metadata.kernel << '\n'
           << "Started: " << metadata.started << '\n'
           << "Stopped: " << metadata.stopped << '\n'
           << "Duration (monotonic): " << metadata.duration_seconds << " seconds\n"
           << "Wall-clock duration: " << metadata.wall_clock_duration_seconds
           << " seconds\n"
           << "Snapshots: " << metadata.snapshots << '\n'
           << "Skipped snapshots: " << metadata.skipped_snapshots << '\n'
           << "Cadence overruns: " << metadata.deadline_overruns << '\n'
           << "Cumulative cadence overrun: "
           << metadata.cumulative_overrun_microseconds / 1000U << " ms\n"
           << "Maximum cadence overrun: "
           << metadata.maximum_overrun_microseconds / 1000U << " ms\n"
           << "Slowest complete scan: "
           << metadata.maximum_scan_microseconds / 1000U << " ms\n"
           << "Processes at shutdown: " << final_snapshot.size() << '\n'
           << "Distinct executable paths observed: " << observed_executables_.size() << '\n'
           << "Distinct script entrypoints observed: " << observed_scripts_.size() << '\n';
    output << "\nCollector/policy timing\n"
           << "-----------------------\n";
    for (const auto& [phase, timing] : phase_timings_) {
        const std::uint64_t average_us = timing.invocations == 0
            ? 0U : timing.total_microseconds / timing.invocations;
        output << phase << ": calls=" << timing.invocations
               << ", average=" << average_us / 1000U
               << " ms, maximum=" << timing.maximum_microseconds / 1000U
               << " ms\n";
    }
    if (baseline_loaded_) {
        output << "Baseline: " << metadata.baseline_path << '\n'
               << "Baseline created: " << metadata.baseline_created << '\n'
               << "Unreviewed executable paths absent from baseline: "
               << new_executables_.size()
               << '\n' << "Executable integrity findings: " << changed_executables_.size()
               << '\n' << "Script calibration: "
               << (baseline_.scripts_calibrated ? "loaded" : "not available")
               << '\n' << "Script entrypoints absent from baseline: "
               << new_scripts_.size()
               << '\n' << "Script integrity findings: " << changed_scripts_.size()
               << "\n\n";
    } else {
        output << "Baseline: not loaded\n\n";
    }

    const std::vector<DomainStatus> domain_statuses =
        summarize_domains(findings_, degradations_);
    output << render_assurance_sections(
        metadata, findings_, degradations_, domain_statuses);

    const auto render_record_budget = [&output](
        const char* label, const RecordRetention& retention) {
        output << label << ": retained=" << retention.retained
               << ", limit=" << retention.limit
               << ", dropped=" << retention.dropped << '\n';
    };
    output << "Observation retention budgets\n"
           << "-----------------------------\n";
    render_record_budget("Findings", metadata.retention.findings);
    render_record_budget("Degradations", metadata.retention.degradations);
    render_record_budget("Direct media sessions",
                         metadata.retention.media_sessions);
    render_record_budget("PipeWire sessions",
                         metadata.retention.pipewire_sessions);
    render_record_budget("Network sessions",
                         metadata.retention.network_sessions);
    render_record_budget("Authentication/session events",
                         metadata.retention.authentication_events);
    output << "Recovery journal: bytes_written="
           << metadata.retention.journal_bytes_written
           << ", byte_limit=" << metadata.retention.journal_byte_limit
           << ", entries_dropped="
           << metadata.retention.journal_entries_dropped << "\n\n";

    std::size_t kernel_findings = 0;
    for (const Finding& finding : findings_) {
        if (finding.domain == MonitoringDomain::kernel ||
            finding.domain == MonitoringDomain::bpf) {
            ++kernel_findings;
        }
    }
    output << "Kernel and BPF integrity\n"
           << "------------------------\n"
           << "Kernel calibration: "
           << (baseline_loaded_ && baseline_.kernel_calibrated
                   ? "loaded" : "not available") << '\n'
           << "Kernel release: " << last_kernel_snapshot_.posture.release << '\n'
           << "Kernel taint: " << last_kernel_snapshot_.posture.taint << '\n'
           << "Module signature enforcement: "
           << (last_kernel_snapshot_.posture.signature_enforcement ? "enabled" : "disabled")
           << '\n'
           << "Lockdown mode: " << last_kernel_snapshot_.posture.lockdown << '\n'
           << "Loaded modules observed: " << last_kernel_snapshot_.modules.size() << '\n'
           << "BPF inventory: "
           << (last_kernel_snapshot_.bpf_available ? "available" : "unavailable") << '\n'
           << "BPF program identities observed: "
           << last_kernel_snapshot_.bpf_programs.size() << '\n'
           << "Kernel/BPF findings: " << kernel_findings << "\n\n";

    std::size_t persistence_findings = 0;
    for (const Finding& finding : findings_) {
        if (finding.domain == MonitoringDomain::persistence) {
            ++persistence_findings;
        }
    }
    output << "Persistence integrity\n"
           << "---------------------\n"
           << "Persistence calibration: "
           << (baseline_loaded_ && baseline_.persistence_calibrated
                   ? "loaded" : "not available") << '\n'
           << "Calibrated records: " << baseline_.persistence.size() << '\n'
           << "Records observed in final inventory: "
           << last_persistence_snapshot_.records.size() << '\n'
           << "Inventory errors: " << last_persistence_snapshot_.errors.size()
           << '\n'
           << "Inventory truncated: "
           << (last_persistence_snapshot_.truncated ? "yes" : "no") << '\n'
           << "Persistence findings: " << persistence_findings << "\n\n";

    output << "Authentication and login-session evidence\n"
           << "-----------------------------------------\n"
           << "Journal evidence: "
           << (authentication_status_.journal_available ? "available" : "unavailable")
           << '\n'
           << "Session-state evidence: "
           << (authentication_status_.session_state_available ? "available"
                                                               : "unavailable")
           << '\n'
           << "Malformed journal records: "
           << authentication_status_.malformed_journal_records << '\n'
           << "Journal input truncated: "
           << (authentication_status_.journal_truncated ? "yes" : "no") << '\n'
           << "Active sessions at shutdown: "
           << authentication_sessions_.size() << '\n'
           << "Events retained: " << authentication_events_.size() << '\n';
    if (metadata.retention.authentication_events.dropped != 0) {
        output << "Events omitted after retention limit: "
               << metadata.retention.authentication_events.dropped << '\n';
    }
    if (authentication_sessions_.empty()) {
        output << "No active login sessions were visible at shutdown.\n";
    } else {
        for (const auto& [id, session] : authentication_sessions_) {
            (void)id;
            output << "[ACTIVE] session " << session.id << ", user "
                   << session.user;
            if (!session.seat.empty()) output << ", seat " << session.seat;
            if (!session.tty.empty()) output << ", TTY " << session.tty;
            if (session.remote) {
                output << ", remote";
                if (!session.source.empty()) output << " from " << session.source;
            }
            if (session.locked_known) {
                output << ", " << (session.locked ? "locked" : "unlocked");
            } else {
                output << ", lock state unavailable";
            }
            if (!session.state.empty()) output << ", state " << session.state;
            output << '\n';
        }
    }
    if (authentication_events_.empty()) {
        output << "No login start/end, failed authentication, or reliable "
                  "lock-state transition was observed after startup.\n\n";
    } else {
        for (const AuthenticationEvent& event : authentication_events_) {
            output << '[' << event.timestamp << "] "
                   << authentication_event_summary(event) << '\n';
            if (!event.detail.empty()) output << "  " << event.detail << '\n';
        }
        output << '\n';
    }

    output << "Observed script entrypoints (" << observed_scripts_.size() << ")\n"
           << "---------------------------\n";
    if (observed_scripts_.empty()) {
        output << "No recognized interpreter script entrypoints were observed.\n";
    } else {
        for (const std::string& script : observed_scripts_) {
            if (!baseline_loaded_ || !baseline_.scripts_calibrated) {
                output << "[UNCALIBRATED] ";
            } else if (changed_scripts_.find(script) != changed_scripts_.end() ||
                       reviewed_scripts_changed_.find(script) !=
                           reviewed_scripts_changed_.end()) {
                output << "[CHANGED] ";
            } else if (baseline_.scripts.find(script) != baseline_.scripts.end()) {
                output << "[CALIBRATED] ";
            } else if (reviewed_scripts_observed_.find(script) !=
                       reviewed_scripts_observed_.end()) {
                output << "[REVIEWED] ";
            } else if (reviewed_scripts_unverified_.find(script) !=
                       reviewed_scripts_unverified_.end()) {
                output << "[UNVERIFIED] ";
            } else {
                output << "[NEW] ";
            }
            output << script << '\n';
        }
    }

    output << "\nReviewed executable fingerprints ("
           << reviewed_executables_observed_.size() << " matched, "
           << reviewed_executables_changed_.size() << " changed, "
           << reviewed_executables_unverified_.size() << " unverified)\n"
           << "--------------------------------\n";
    if (!reviewed_loaded_) {
        output << "No reviewed-executable file was loaded.\n";
    } else if (reviewed_executables_observed_.empty() &&
               reviewed_executables_changed_.empty() &&
               reviewed_executables_unverified_.empty()) {
        output << "No reviewed executable was observed outside the baseline.\n";
    } else {
        for (const std::string& executable : reviewed_executables_observed_) {
            const auto entry = reviewed_executables_.find(executable);
            output << "[MATCHED] " << executable;
            if (entry != reviewed_executables_.end()) {
                output << " -- " << entry->second.reason;
            }
            output << '\n';
        }
        for (const std::string& executable : reviewed_executables_changed_) {
            output << "[CHANGED] " << executable << '\n';
        }
        for (const std::string& executable : reviewed_executables_unverified_) {
            output << "[UNVERIFIED] " << executable << '\n';
        }
    }

    output << "\nReviewed script fingerprints ("
           << reviewed_scripts_observed_.size() << " matched, "
           << reviewed_scripts_changed_.size() << " changed, "
           << reviewed_scripts_unverified_.size() << " unverified)\n"
           << "----------------------------\n";
    if (!reviewed_loaded_) {
        output << "No reviewed-fingerprint file was loaded.\n";
    } else if (reviewed_scripts_observed_.empty() &&
               reviewed_scripts_changed_.empty() &&
               reviewed_scripts_unverified_.empty()) {
        output << "No reviewed script was observed outside the baseline.\n";
    } else {
        for (const std::string& script : reviewed_scripts_observed_) {
            const auto entry = reviewed_scripts_.find(script);
            output << "[MATCHED] " << script;
            if (entry != reviewed_scripts_.end()) {
                output << " -- " << entry->second.reason;
            }
            output << '\n';
        }
        for (const std::string& script : reviewed_scripts_changed_) {
            output << "[CHANGED] " << script << '\n';
        }
        for (const std::string& script : reviewed_scripts_unverified_) {
            output << "[UNVERIFIED] " << script << '\n';
        }
    }

    output << "\nAttributed network socket sessions (" << network_events_.size()
           << ")\n"
           << "----------------------------------\n"
           << "Network calibration: "
           << (baseline_loaded_ && baseline_.network_calibrated
                   ? "loaded" : "not available")
           << '\n'
           << "Distinct new network behavior patterns: "
           << new_network_patterns_.size() << '\n';
    if (metadata.retention.network_sessions.dropped != 0) {
        output << "Sessions omitted after retention limit: "
               << metadata.retention.network_sessions.dropped << '\n';
    }
    if (network_events_.empty()) {
        output << "No process-attributed TCP, UDP, raw, or packet sockets were observed.\n";
    } else {
        for (const auto& [key, event] : network_events_) {
            (void)key;
            output << event.first_seen << " through " << event.last_seen << ": ";
            if (baseline_loaded_ && baseline_.network_calibrated) {
                output << (event.matched_baseline ? "[CALIBRATED] " : "[NEW] ");
            } else {
                output << "[UNCALIBRATED] ";
            }
            output << network_label(event) << '\n';
        }
    }

    output << "\nPipeWire capture sessions (" << pipewire_events_.size() << ")\n"
           << "-----------------------------\n";
    if (metadata.retention.pipewire_sessions.dropped != 0) {
        output << "Sessions omitted after retention limit: "
               << metadata.retention.pipewire_sessions.dropped << '\n';
    }
    if (pipewire_events_.empty()) {
        output << "No active PipeWire microphone or camera client sessions were observed.\n";
    } else {
        for (const auto& [key, event] : pipewire_events_) {
            (void)key;
            output << event.first_seen << " through " << event.last_seen << ": "
                   << (baseline_loaded_
                       ? (event.matched_baseline ? "[CALIBRATED] " : "[NEW] ")
                       : "")
                   << event.application << " (PID " << event.pid << ", user "
                   << user_name(event.uid) << ", executable "
                   << (event.executable.empty() ? "[unavailable]" : event.executable)
                   << ") used " << event.media_class;
            if (!event.node_name.empty()) {
                output << " via node " << event.node_name;
            }
            output << '\n';
        }
    }

    output << "\nMonitoring degradations (" << degradations_.size() << ")\n"
           << "------------------------\n";
    if (degradations_.empty()) {
        output << "No known monitoring visibility losses were recorded.\n";
    } else {
        for (const Degradation& degradation : degradations_) {
            output << '[' << degradation.timestamp << "] "
                   << domain_name(degradation.domain) << ' ' << degradation.rule;
            if (degradation.count > 1) {
                output << " (occurred " << degradation.count << " times)";
            }
            output << "\n  " << degradation.detail << '\n';
        }
    }

    output << "\nAlerts (" << findings_.size() << ")\n"
           << "----------------\n";
    if (metadata.retention.findings.dropped != 0) {
        output << "Distinct findings omitted after retention limit: "
               << metadata.retention.findings.dropped << '\n';
    }
    if (findings_.empty()) {
        output << "No heuristic alerts were recorded.\n";
    } else {
        for (const Finding& finding : findings_) {
            output << '[' << finding.timestamp << "] "
                   << finding_priority_name(finding.priority) << ' '
                   << finding.rule << "\n  " << finding.detail << '\n';
        }
    }

    output << "\nDirect media-device observations (" << media_events_.size() << ")\n"
           << "-------------------------------------\n";
    if (metadata.retention.media_sessions.dropped != 0) {
        output << "Sessions omitted after retention limit: "
               << metadata.retention.media_sessions.dropped << '\n';
    }
    if (media_events_.empty()) {
        output << "No direct /dev/video* or /dev/snd/* handles were observed.\n";
    } else {
        for (const auto& [key, event] : media_events_) {
            (void)key;
            output << event.first_seen << " through " << event.last_seen << ": "
                   << (baseline_loaded_
                       ? (event.matched_baseline ? "[CALIBRATED] " : "[NEW] ")
                       : "")
                   << "PID "
                   << event.pid << " (user " << user_name(event.uid) << ", executable "
                   << (event.executable.empty() ? "[unavailable]" : event.executable)
                   << ") held " << event.device << '\n';
        }
    }

    output << "\nImportant limitations\n"
           << "---------------------\n"
           << "This draft observes user-space state and cannot prove that a system is clean.\n"
           << "A kernel-level rootkit may hide activity from /proc and this program.\n"
           << "PipeWire client attribution is best-effort and depends on graph properties.\n"
           << "Socket attribution uses /proc and may miss short sessions, other network\n"
           << "namespaces, and destinations used through unconnected UDP sockets.\n"
           << "Authentication evidence depends on journal retention/access and sampled\n"
           << "systemd-logind state; lock transitions can be missed when not exposed.\n"
           << "Polling can miss activity shorter than the sampling interval. An alert is\n"
           << "evidence to investigate, not proof of compromise.\n";
    return output.str();
}

void Monitor::start_report() {
    std::error_code error;
    const bool directory_created = fs::create_directories(report_directory_, error);
    if (error) {
        throw std::runtime_error("cannot create report directory: " + error.message());
    }
    if (!fs::is_directory(report_directory_)) {
        throw std::runtime_error("report destination is not a directory: " +
                                 report_directory_);
    }
    if (directory_created) {
        fs::permissions(report_directory_, fs::perms::owner_all,
                        fs::perm_options::replace, error);
        if (error) {
            throw std::runtime_error("cannot protect report directory: " + error.message());
        }
    }
    require_secure_directory(report_directory_, "report directory");

    const std::string base_name = "nightwatch-" + timestamp(started_, "%Y%m%d-%H%M%S");
    fs::path path;
    fs::path journal_path;
    fs::path json_path;
    for (unsigned int suffix = 0; report_descriptor_ < 0; ++suffix) {
        const std::string name = suffix == 0
            ? base_name + ".txt"
            : base_name + "-" + std::to_string(suffix) + ".txt";
        path = fs::path(report_directory_) / name;
        report_descriptor_ = open(path.c_str(),
                                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (report_descriptor_ < 0 && errno != EEXIST) {
            throw std::runtime_error("cannot create report file " + path.string() +
                                     ": " + std::strerror(errno));
        }
        if (report_descriptor_ >= 0) {
            journal_path = path;
            journal_path.replace_extension(".journal");
            json_path = path;
            json_path.replace_extension(".json");
            journal_descriptor_ = open(journal_path.c_str(),
                                       O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
            if (journal_descriptor_ < 0) {
                const int reason = errno;
                close(report_descriptor_);
                report_descriptor_ = -1;
                fs::remove(path, error);
                if (reason != EEXIST) {
                    throw std::runtime_error("cannot create recovery journal: " +
                                             std::string(std::strerror(reason)));
                }
            } else {
                json_report_descriptor_ = open(
                    json_path.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
                if (json_report_descriptor_ < 0) {
                    const int reason = errno;
                    close(journal_descriptor_);
                    journal_descriptor_ = -1;
                    close(report_descriptor_);
                    report_descriptor_ = -1;
                    fs::remove(journal_path, error);
                    fs::remove(path, error);
                    if (reason != EEXIST) {
                        throw std::runtime_error("cannot create JSON report: " +
                                                 std::string(std::strerror(reason)));
                    }
                }
            }
        }
    }
    report_path_ = fs::absolute(path).string();
    json_report_path_ = fs::absolute(json_path).string();
    journal_path_ = fs::absolute(journal_path).string();
    const std::string stub = "Nightwatch monitoring is in progress. Recovery journal: " +
                             journal_path_ + "\n";
    write_all(report_descriptor_, stub, "report stub");
    if (fsync(report_descriptor_) != 0) {
        throw std::runtime_error("cannot synchronize report stub: " +
                                 std::string(std::strerror(errno)));
    }
    std::ostringstream json_stub_output;
    json_stub_output << "{\n  \"schema\": \"nightwatch.report\",\n"
                     << "  \"schema_version\": "
                     << NIGHTWATCH_JSON_SCHEMA_VERSION << ",\n"
                     << "  \"status\": \"monitoring\"\n}\n";
    const std::string json_stub = json_stub_output.str();
    write_all(json_report_descriptor_, json_stub, "JSON report stub");
    if (fsync(json_report_descriptor_) != 0) {
        throw std::runtime_error("cannot synchronize JSON report stub: " +
                                 std::string(std::strerror(errno)));
    }
    std::ostringstream header;
    header << "Nightwatch recovery journal\n"
           << "===========================\n"
           << "Started: " << timestamp(started_) << '\n'
           << "Host: " << host_name() << '\n'
           << "Baseline: " << (baseline_loaded_ ? baseline_path_ : "not loaded") << '\n'
           << "Reviewed executables: "
           << (reviewed_loaded_ ? reviewed_path_ : "not loaded") << '\n'
           << "Status: monitoring; this file becomes the final report after a clean stop.\n\n";
    append_journal(header.str());
    synchronize_directory(report_directory_, "report directory");
}

void Monitor::append_journal(const std::string& entry, bool synchronize) {
    if (journal_descriptor_ < 0) {
        return;
    }
    if (!journal_budget_.allow_entry(entry.size())) {
        if (journal_budget_.dropped_entries() == 1) {
            const std::string detail =
                "Recovery-journal retention entered the reserved final marker "
                "region of its " +
                std::to_string(journal_budget_.maximum_bytes()) +
                "-byte budget; additional journal entries are counted but not "
                "written";
            record_degradation("retention.journal-limit-reached", detail,
                               false, false);
            const std::string marker =
                "[" + timestamp(Clock::now()) + "] DEGRADATION " +
                domain_name(MonitoringDomain::retention) +
                " retention.journal-limit-reached\n  " + detail + "\n";
            if (journal_budget_.marker_fits(marker.size())) {
                write_all(journal_descriptor_, marker,
                          "recovery journal exhaustion marker");
                journal_budget_.account_written(marker.size());
                if (fdatasync(journal_descriptor_) != 0) {
                    throw std::runtime_error(
                        "cannot synchronize recovery journal exhaustion marker: " +
                        std::string(std::strerror(errno)));
                }
            }
        }
        return;
    }
    write_all(journal_descriptor_, entry, "recovery journal");
    journal_budget_.account_written(entry.size());
    if (synchronize && fdatasync(journal_descriptor_) != 0) {
        throw std::runtime_error("cannot synchronize recovery journal: " +
                                 std::string(std::strerror(errno)));
    }
}

void Monitor::write_checkpoint() {
    std::ostringstream entry;
    entry << '[' << timestamp(Clock::now()) << "] CHECKPOINT snapshots=" << scans_
          << " skipped_snapshots=" << failed_snapshots_
          << " cadence_overruns=" << deadline_overruns_
          << " cumulative_overrun_us=" << cumulative_overrun_microseconds_
          << " maximum_scan_us=" << maximum_scan_microseconds_
          << " findings=" << findings_.size()
          << " degradations=" << degradations_.size()
          << " media_events=" << media_events_.size()
          << " pipewire_captures=" << pipewire_events_.size()
          << " network_sessions=" << network_events_.size()
          << " findings_dropped=" << finding_budget_.dropped()
          << " degradations_dropped=" << degradation_budget_.dropped()
          << " media_events_dropped=" << media_budget_.dropped()
          << " pipewire_captures_dropped=" << pipewire_budget_.dropped()
          << " network_sessions_dropped=" << network_budget_.dropped()
          << " journal_entries_dropped=" << journal_budget_.dropped_entries()
          << " executables=" << observed_executables_.size()
          << " scripts=" << observed_scripts_.size() << '\n';
    append_journal(entry.str());
}

std::string Monitor::save_report(const std::string& report) {
    if (report_descriptor_ < 0) {
        throw std::runtime_error("report journal was not initialized");
    }
    if (ftruncate(report_descriptor_, 0) != 0 || lseek(report_descriptor_, 0, SEEK_SET) < 0) {
        throw std::runtime_error("cannot prepare final report: " +
                                 std::string(std::strerror(errno)));
    }

    write_all(report_descriptor_, report, "final report");
    if (fsync(report_descriptor_) != 0) {
        throw std::runtime_error("cannot synchronize final report: " +
                                 std::string(std::strerror(errno)));
    }
    if (close(report_descriptor_) != 0) {
        report_descriptor_ = -1;
        throw std::runtime_error("cannot finalize report file: " +
                                 std::string(std::strerror(errno)));
    }
    report_descriptor_ = -1;
    if (journal_descriptor_ >= 0) {
        const bool sync_failed = fsync(journal_descriptor_) != 0;
        const int sync_error = errno;
        const bool close_failed = close(journal_descriptor_) != 0;
        const int close_error = errno;
        if (sync_failed || close_failed) {
            journal_descriptor_ = -1;
            throw std::runtime_error("cannot finalize recovery journal: " +
                                     std::string(std::strerror(
                                         sync_failed ? sync_error : close_error)));
        }
        journal_descriptor_ = -1;
        std::error_code error;
        fs::remove(journal_path_, error);
        if (error) {
            throw std::runtime_error("final report saved but recovery journal could not be removed: " +
                                     error.message());
        }
        synchronize_directory(report_directory_, "report directory");
    }
    return report_path_;
}

std::string Monitor::save_json_report(const std::string& report) {
    if (json_report_descriptor_ < 0) {
        throw std::runtime_error("JSON report was not initialized");
    }
    if (ftruncate(json_report_descriptor_, 0) != 0 ||
        lseek(json_report_descriptor_, 0, SEEK_SET) < 0) {
        throw std::runtime_error("cannot prepare final JSON report: " +
                                 std::string(std::strerror(errno)));
    }
    write_all(json_report_descriptor_, report, "final JSON report");
    if (fsync(json_report_descriptor_) != 0) {
        throw std::runtime_error("cannot synchronize final JSON report: " +
                                 std::string(std::strerror(errno)));
    }
    if (close(json_report_descriptor_) != 0) {
        json_report_descriptor_ = -1;
        throw std::runtime_error("cannot finalize JSON report file: " +
                                 std::string(std::strerror(errno)));
    }
    json_report_descriptor_ = -1;
    return json_report_path_;
}
