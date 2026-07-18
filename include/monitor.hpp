#pragma once

#include "assurance.hpp"
#include "authentication.hpp"
#include "fingerprint.hpp"
#include "kernel.hpp"
#include "network.hpp"
#include "persistence.hpp"
#include "retention.hpp"
#include "reviewed.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

struct ProcessInfo {
    int pid{};
    int ppid{};
    unsigned int uid{};
    std::string name;
    std::string executable;
    std::string command_line;
    std::vector<std::string> arguments;
    std::string script_entrypoint;
    std::set<std::string> media_handles;
    std::set<std::uint64_t> socket_inodes;
    std::uint64_t start_time_ticks{};
};

struct MediaEvent {
    std::string first_seen;
    std::string last_seen;
    int pid{};
    unsigned int uid{};
    std::string executable;
    std::string device;
    bool matched_baseline{false};
};

struct PipeWireCapture {
    std::string first_seen;
    std::string last_seen;
    int pid{};
    unsigned int uid{};
    std::string executable;
    std::string application;
    std::string media_class;
    std::string node_name;
    bool matched_baseline{false};
};

struct NetworkEvent {
    std::string first_seen;
    std::string last_seen;
    int pid{};
    std::uint64_t process_start_ticks{};
    unsigned int uid{};
    std::string executable;
    NetworkSocket socket;
    bool matched_baseline{false};
};

struct PendingNetworkBind {
    std::chrono::steady_clock::time_point first_seen;
    std::string detail;
    NetworkPattern pattern;
};

struct Baseline {
    std::string created;
    std::string host;
    std::map<std::string, ExecutableFingerprint> executables;
    bool scripts_calibrated{false};
    std::map<std::string, ExecutableFingerprint> scripts;
    std::set<std::string> authorized_media;
    std::set<std::string> authorized_pipewire_captures;
    bool network_calibrated{false};
    std::set<NetworkPattern> authorized_network;
    bool kernel_calibrated{false};
    KernelSnapshot kernel;
    bool persistence_calibrated{false};
    std::map<std::string, PersistenceRecord> persistence;
};

class Monitor {
public:
    Monitor(unsigned int interval_seconds, std::string report_directory,
            std::string baseline_path, std::string reviewed_path);
    ~Monitor();
    int run(const volatile std::sig_atomic_t& stop_requested);
    int calibrate(unsigned int idle_seconds, unsigned int media_seconds,
                  const volatile std::sig_atomic_t& stop_requested);

private:
    using Clock = std::chrono::system_clock;
    using SteadyClock = std::chrono::steady_clock;

    struct TimingSummary {
        std::uint64_t invocations{0};
        std::uint64_t total_microseconds{0};
        std::uint64_t maximum_microseconds{0};
    };

    std::map<int, ProcessInfo> scan_processes() const;
    ExecutableFingerprint fingerprint_executable(const ProcessInfo& process,
                                                 bool include_hash) const;
    ExecutableFingerprint fingerprint_script(const ProcessInfo& process,
                                             bool include_hash) const;
    void verify_executable(const ProcessInfo& process,
                           std::set<std::string>& verified_this_snapshot,
                           unsigned int& background_hash_budget);
    void verify_script(const ProcessInfo& process,
                       std::set<std::string>& verified_this_snapshot,
                       unsigned int& background_hash_budget);
    ReviewedStatus verify_reviewed_executable(
        const ProcessInfo& process,
        std::set<std::string>& verified_this_snapshot);
    ReviewedStatus verify_reviewed_script(
        const ProcessInfo& process,
        std::set<std::string>& verified_this_snapshot);
    std::vector<PipeWireCapture> scan_pipewire_captures(
        const std::map<int, ProcessInfo>& processes);
    std::vector<NetworkEvent> scan_network_sockets(
        const std::map<int, ProcessInfo>& processes) const;
    void inspect_network(const std::vector<NetworkEvent>& sockets);
    void finalize_pending_network_binds();
    void inspect_pipewire(const std::vector<PipeWireCapture>& captures);
    void inspect_snapshot(const std::map<int, ProcessInfo>& current);
    KernelSnapshot scan_kernel(bool module_details, bool bpf_details) const;
    void inspect_kernel();
    void inspect_persistence(bool force = false);
    void initialize_authentication();
    void inspect_authentication(bool force = false);
    bool collect_login_sessions(std::map<std::string, LoginSession>& sessions,
                                std::string& error);
    void record_authentication_event(AuthenticationEvent event);
    void record_alert(const std::string& severity, const std::string& rule,
                      const std::string& detail);
    void record_degradation(const std::string& rule, const std::string& detail,
                            bool session_critical = false,
                            bool write_journal = true);
    void record_phase_timing(const std::string& phase,
                             SteadyClock::duration elapsed);
    SessionMetadata session_metadata() const;
    Baseline collect_calibration(unsigned int idle_seconds,
                                 unsigned int media_seconds,
                                 const volatile std::sig_atomic_t& stop_requested);
    bool load_baseline();
    bool load_reviewed();
    void save_baseline(const Baseline& baseline) const;
    std::string build_report(const std::map<int, ProcessInfo>& final_snapshot) const;
    std::string build_json_report() const;
    void start_report();
    void append_journal(const std::string& entry, bool synchronize = true);
    void write_checkpoint();
    std::string save_report(const std::string& report);
    std::string save_json_report(const std::string& report);

    unsigned int interval_seconds_;
    std::string report_directory_;
    std::string baseline_path_;
    std::string reviewed_path_;
    Clock::time_point started_;
    Clock::time_point stopped_;
    SteadyClock::time_point steady_started_;
    SteadyClock::time_point steady_stopped_;
    std::uint64_t scans_{0};
    std::uint64_t failed_snapshots_{0};
    std::uint64_t deadline_overruns_{0};
    std::uint64_t cumulative_overrun_microseconds_{0};
    std::uint64_t maximum_overrun_microseconds_{0};
    std::uint64_t maximum_scan_microseconds_{0};
    std::map<std::string, TimingSummary> phase_timings_;
    std::map<int, ProcessInfo> previous_;
    std::map<std::string, MediaEvent> media_events_;
    std::map<std::string, unsigned int> media_session_counts_;
    std::set<std::string> previous_dropped_media_events_;
    std::map<std::string, PipeWireCapture> pipewire_events_;
    std::map<std::string, unsigned int> pipewire_session_counts_;
    std::set<std::string> previous_pipewire_captures_;
    std::set<std::string> previous_dropped_pipewire_captures_;
    std::map<std::string, NetworkEvent> network_events_;
    std::set<std::string> previous_dropped_network_events_;
    std::map<std::string, PendingNetworkBind> pending_network_binds_;
    std::set<NetworkPattern> new_network_patterns_;
    std::set<NetworkPattern> transient_network_patterns_noticed_;
    std::set<NetworkPattern> persistent_network_patterns_alerted_;
    std::vector<Finding> findings_;
    std::set<std::string> alert_keys_;
    std::vector<Degradation> degradations_;
    std::map<std::string, std::size_t> degradation_indexes_;
    std::set<std::string> observed_executables_;
    std::set<std::string> new_executables_;
    std::set<std::string> changed_executables_;
    std::set<std::string> observed_scripts_;
    std::set<std::string> new_scripts_;
    std::set<std::string> changed_scripts_;
    std::map<std::string, ExecutableFingerprint> current_fingerprints_;
    std::map<std::string, std::chrono::steady_clock::time_point> last_hash_checks_;
    std::map<std::string, ExecutableFingerprint> current_script_fingerprints_;
    std::map<std::string, std::chrono::steady_clock::time_point>
        last_script_hash_checks_;
    std::map<std::string, ExecutableFingerprint> current_reviewed_fingerprints_;
    std::map<std::string, std::chrono::steady_clock::time_point>
        last_reviewed_hash_checks_;
    std::map<std::string, ReviewedExecutable> reviewed_executables_;
    std::set<std::string> reviewed_executables_observed_;
    std::set<std::string> reviewed_executables_changed_;
    std::set<std::string> reviewed_executables_unverified_;
    std::map<std::string, ExecutableFingerprint>
        current_reviewed_script_fingerprints_;
    std::map<std::string, std::chrono::steady_clock::time_point>
        last_reviewed_script_hash_checks_;
    std::map<std::string, ReviewedExecutable> reviewed_scripts_;
    std::set<std::string> reviewed_scripts_observed_;
    std::set<std::string> reviewed_scripts_changed_;
    std::set<std::string> reviewed_scripts_unverified_;
    Baseline baseline_;
    bool baseline_loaded_{false};
    bool reviewed_loaded_{false};
    int report_descriptor_{-1};
    int json_report_descriptor_{-1};
    int journal_descriptor_{-1};
    std::string report_path_;
    std::string json_report_path_;
    std::string journal_path_;
    std::chrono::steady_clock::time_point next_checkpoint_;
    std::chrono::steady_clock::time_point next_background_hash_;
    std::set<std::string> calibration_idle_capture_;
    KernelSnapshot last_kernel_snapshot_;
    PersistenceSnapshot last_persistence_snapshot_;
    std::vector<AuthenticationEvent> authentication_events_;
    std::set<std::string> authentication_event_keys_;
    std::map<std::string, LoginSession> authentication_sessions_;
    AuthenticationStatus authentication_status_;
    std::string authentication_journal_cursor_;
    bool authentication_initialized_{false};
    bool authentication_journal_live_{false};
    bool authentication_sessions_live_{false};
    std::chrono::steady_clock::time_point next_kernel_integrity_check_;
    std::chrono::steady_clock::time_point next_bpf_check_;
    std::chrono::steady_clock::time_point next_persistence_check_;
    std::chrono::steady_clock::time_point next_authentication_check_;
    RecordBudget finding_budget_{10000};
    RecordBudget degradation_budget_{1023};
    RecordBudget media_budget_{50000};
    RecordBudget pipewire_budget_{10000};
    RecordBudget network_budget_{100000};
    RecordBudget authentication_budget_{4096};
    JournalBudget journal_budget_{64U * 1024U * 1024U, 4096U};
};

std::string timestamp(std::chrono::system_clock::time_point time,
                      const char* format = "%Y-%m-%d %H:%M:%S %Z");
