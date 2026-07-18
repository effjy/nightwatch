#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum class MonitoringDomain {
    executable,
    script,
    media,
    pipewire,
    network,
    kernel,
    bpf,
    authentication,
    persistence,
    sampling,
    retention,
    evidence
};

enum class VerificationState {
    verified,
    finding_detected,
    unknown
};

enum class FindingPriority {
    notice,
    high
};

enum class FindingClassification {
    probably_normal,
    needs_review,
    high_concern
};

enum class SessionConclusion {
    fully_verified,
    verified_with_findings,
    partially_verified,
    inconclusive
};

struct Finding {
    std::string timestamp;
    MonitoringDomain domain{MonitoringDomain::evidence};
    FindingPriority priority{FindingPriority::notice};
    FindingClassification classification{FindingClassification::needs_review};
    std::string rule;
    std::string title;
    std::string detail;
    std::string rationale;
    std::string recommended_action;
};

struct RuleMetadata {
    FindingClassification classification{FindingClassification::needs_review};
    std::string title;
    std::string rationale;
    std::string recommended_action;
};

struct FindingGroup {
    FindingClassification classification{FindingClassification::needs_review};
    std::string title;
    std::string first_seen;
    std::string last_seen;
    std::string rationale;
    std::string observation_summary;
    std::string recommended_action;
    std::vector<std::size_t> finding_indexes;
};

struct Degradation {
    std::string timestamp;
    MonitoringDomain domain{MonitoringDomain::evidence};
    std::string rule;
    std::string detail;
    std::uint64_t count{1};
    bool session_critical{false};
};

struct DomainStatus {
    MonitoringDomain domain{MonitoringDomain::evidence};
    VerificationState state{VerificationState::verified};
    std::size_t finding_count{0};
    std::size_t degradation_count{0};
};

struct PhaseTiming {
    std::string phase;
    std::uint64_t invocations{0};
    std::uint64_t total_microseconds{0};
    std::uint64_t maximum_microseconds{0};
};

struct RecordRetention {
    std::uint64_t retained{0};
    std::uint64_t limit{0};
    std::uint64_t dropped{0};
};

struct RetentionMetadata {
    RecordRetention findings;
    RecordRetention degradations;
    RecordRetention media_sessions;
    RecordRetention pipewire_sessions;
    RecordRetention network_sessions;
    RecordRetention authentication_events;
    std::uint64_t journal_bytes_written{0};
    std::uint64_t journal_byte_limit{0};
    std::uint64_t journal_entries_dropped{0};
};

struct SessionMetadata {
    std::string host;
    std::string kernel;
    std::string started;
    std::string stopped;
    std::string baseline_path;
    std::string baseline_created;
    std::uint64_t duration_seconds{0};
    std::uint64_t snapshots{0};
    std::uint64_t skipped_snapshots{0};
    std::uint64_t sampling_interval_seconds{0};
    std::uint64_t wall_clock_duration_seconds{0};
    std::uint64_t deadline_overruns{0};
    std::uint64_t cumulative_overrun_microseconds{0};
    std::uint64_t maximum_overrun_microseconds{0};
    std::uint64_t maximum_scan_microseconds{0};
    std::vector<PhaseTiming> phase_timings;
    RetentionMetadata retention;
};

MonitoringDomain domain_for_rule(const std::string& rule);
FindingPriority finding_priority(const std::string& severity);
RuleMetadata rule_metadata(const std::string& rule, FindingPriority priority);
std::string domain_name(MonitoringDomain domain);
std::string verification_state_name(VerificationState state);
std::string finding_priority_name(FindingPriority priority);
std::string finding_classification_name(FindingClassification classification);
std::string degradation_recommended_action(const Degradation& degradation);
bool cadence_visibility_degraded(const SessionMetadata& metadata);
std::string session_conclusion_name(SessionConclusion conclusion);
std::vector<MonitoringDomain> monitored_domains();
std::vector<DomainStatus> summarize_domains(
    const std::vector<Finding>& findings,
    const std::vector<Degradation>& degradations);
SessionConclusion summarize_session(
    const std::vector<DomainStatus>& domains,
    const std::vector<Degradation>& degradations);
std::vector<FindingGroup> correlate_finding_groups(
    const std::vector<Finding>& findings);
std::string outcome_narrative(
    const std::vector<Finding>& findings,
    const std::vector<Degradation>& degradations,
    const std::vector<DomainStatus>& domains);
std::string render_assurance_sections(
    const SessionMetadata& metadata,
    const std::vector<Finding>& findings,
    const std::vector<Degradation>& degradations,
    const std::vector<DomainStatus>& domains);
