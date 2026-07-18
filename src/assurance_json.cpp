#include "assurance_json.hpp"

#include <iomanip>
#include <sstream>

namespace {
std::string json_escape(const std::string& value) {
    std::ostringstream output;
    for (const unsigned char character : value) {
        switch (character) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (character < 0x20U) {
                output << "\\u" << std::hex << std::setw(4)
                       << std::setfill('0')
                       << static_cast<unsigned int>(character)
                       << std::dec << std::setfill(' ');
            } else {
                output << static_cast<char>(character);
            }
        }
    }
    return output.str();
}

void string_field(std::ostringstream& output, const char* name,
                  const std::string& value, bool comma = true,
                  std::size_t indentation = 6) {
    output << std::string(indentation, ' ') << '"' << name << "\": \""
           << json_escape(value) << '"';
    if (comma) output << ',';
    output << '\n';
}

const char* domain_id(MonitoringDomain domain) {
    switch (domain) {
    case MonitoringDomain::executable: return "executable";
    case MonitoringDomain::script: return "script";
    case MonitoringDomain::media: return "media";
    case MonitoringDomain::pipewire: return "pipewire";
    case MonitoringDomain::network: return "network";
    case MonitoringDomain::kernel: return "kernel";
    case MonitoringDomain::bpf: return "bpf";
    case MonitoringDomain::authentication: return "authentication";
    case MonitoringDomain::persistence: return "persistence";
    case MonitoringDomain::sampling: return "sampling";
    case MonitoringDomain::retention: return "retention";
    case MonitoringDomain::evidence: return "evidence";
    }
    return "evidence";
}

const char* state_id(VerificationState state) {
    switch (state) {
    case VerificationState::verified: return "verified";
    case VerificationState::finding_detected: return "finding_detected";
    case VerificationState::unknown: return "unknown";
    }
    return "unknown";
}

const char* conclusion_id(SessionConclusion conclusion) {
    switch (conclusion) {
    case SessionConclusion::fully_verified: return "fully_verified";
    case SessionConclusion::verified_with_findings:
        return "verified_with_findings";
    case SessionConclusion::partially_verified: return "partially_verified";
    case SessionConclusion::inconclusive: return "inconclusive";
    }
    return "inconclusive";
}

const char* priority_id(FindingPriority priority) {
    return priority == FindingPriority::high ? "high" : "notice";
}

const char* classification_id(FindingClassification classification) {
    switch (classification) {
    case FindingClassification::probably_normal: return "probably_normal";
    case FindingClassification::needs_review: return "needs_review";
    case FindingClassification::high_concern: return "high_concern";
    }
    return "needs_review";
}
}

std::string render_json_report(
    const SessionMetadata& metadata,
    const std::vector<Finding>& findings,
    const std::vector<Degradation>& degradations,
    const std::vector<DomainStatus>& domains,
    const AuthenticationStatus& authentication,
    const std::vector<AuthenticationEvent>& authentication_events,
    const std::map<std::string, LoginSession>& active_sessions) {
    const SessionConclusion conclusion = summarize_session(domains, degradations);
    const std::vector<FindingGroup> groups = correlate_finding_groups(findings);
    std::size_t high_count = 0;
    for (const Finding& finding : findings) {
        if (finding.priority == FindingPriority::high) ++high_count;
    }

    std::ostringstream output;
    output << "{\n"
           << "  \"schema\": \"nightwatch.report\",\n"
           << "  \"schema_version\": " << NIGHTWATCH_JSON_SCHEMA_VERSION
           << ",\n"
           << "  \"session\": {\n";
    string_field(output, "host", metadata.host);
    string_field(output, "kernel", metadata.kernel);
    string_field(output, "started", metadata.started);
    string_field(output, "stopped", metadata.stopped);
    string_field(output, "baseline_path", metadata.baseline_path);
    string_field(output, "baseline_created", metadata.baseline_created);
    output << "      \"duration_seconds\": " << metadata.duration_seconds << ",\n"
           << "      \"wall_clock_duration_seconds\": "
           << metadata.wall_clock_duration_seconds << ",\n"
           << "      \"snapshots\": " << metadata.snapshots << ",\n"
           << "      \"skipped_snapshots\": " << metadata.skipped_snapshots
           << ",\n"
           << "      \"cadence\": {\n"
           << "        \"interval_seconds\": "
           << metadata.sampling_interval_seconds << ",\n"
           << "        \"deadline_overruns\": "
           << metadata.deadline_overruns << ",\n"
           << "        \"cumulative_overrun_microseconds\": "
           << metadata.cumulative_overrun_microseconds << ",\n"
           << "        \"maximum_overrun_microseconds\": "
           << metadata.maximum_overrun_microseconds << ",\n"
           << "        \"maximum_scan_microseconds\": "
           << metadata.maximum_scan_microseconds << "\n"
           << "      },\n"
           << "      \"phase_timings\": [\n";
    for (std::size_t index = 0; index < metadata.phase_timings.size(); ++index) {
        const PhaseTiming& timing = metadata.phase_timings[index];
        output << "        {\n";
        string_field(output, "phase", timing.phase, true, 10);
        output << "          \"invocations\": " << timing.invocations << ",\n"
               << "          \"total_microseconds\": "
               << timing.total_microseconds << ",\n"
               << "          \"maximum_microseconds\": "
               << timing.maximum_microseconds << "\n"
               << "        }"
               << (index + 1 == metadata.phase_timings.size() ? "\n" : ",\n");
    }
    const RetentionMetadata& retention = metadata.retention;
    output << "      ],\n"
           << "      \"retention\": {\n"
           << "        \"findings\": {\"retained\": "
           << retention.findings.retained << ", \"limit\": "
           << retention.findings.limit << ", \"dropped\": "
           << retention.findings.dropped << "},\n"
           << "        \"degradations\": {\"retained\": "
           << retention.degradations.retained << ", \"limit\": "
           << retention.degradations.limit << ", \"dropped\": "
           << retention.degradations.dropped << "},\n"
           << "        \"media_sessions\": {\"retained\": "
           << retention.media_sessions.retained << ", \"limit\": "
           << retention.media_sessions.limit << ", \"dropped\": "
           << retention.media_sessions.dropped << "},\n"
           << "        \"pipewire_sessions\": {\"retained\": "
           << retention.pipewire_sessions.retained << ", \"limit\": "
           << retention.pipewire_sessions.limit << ", \"dropped\": "
           << retention.pipewire_sessions.dropped << "},\n"
           << "        \"network_sessions\": {\"retained\": "
           << retention.network_sessions.retained << ", \"limit\": "
           << retention.network_sessions.limit << ", \"dropped\": "
           << retention.network_sessions.dropped << "},\n"
           << "        \"authentication_events\": {\"retained\": "
           << retention.authentication_events.retained << ", \"limit\": "
           << retention.authentication_events.limit << ", \"dropped\": "
           << retention.authentication_events.dropped << "},\n"
           << "        \"journal_bytes_written\": "
           << retention.journal_bytes_written << ",\n"
           << "        \"journal_byte_limit\": "
           << retention.journal_byte_limit << ",\n"
           << "        \"journal_entries_dropped\": "
           << retention.journal_entries_dropped << "\n"
           << "      }\n  },\n"
           << "  \"assurance\": {\n"
           << "      \"conclusion\": \"" << conclusion_id(conclusion) << "\",\n"
           << "      \"conclusion_label\": \""
           << json_escape(session_conclusion_name(conclusion)) << "\",\n"
           << "      \"finding_count\": " << findings.size() << ",\n"
           << "      \"high_finding_count\": " << high_count << ",\n"
           << "      \"degradation_count\": " << degradations.size() << "\n"
           << "  },\n"
           << "  \"domains\": [\n";
    for (std::size_t index = 0; index < domains.size(); ++index) {
        const DomainStatus& domain = domains[index];
        output << "    {\n"
               << "      \"id\": \"" << domain_id(domain.domain) << "\",\n"
               << "      \"label\": \"" << json_escape(domain_name(domain.domain))
               << "\",\n"
               << "      \"state\": \"" << state_id(domain.state) << "\",\n"
               << "      \"finding_count\": " << domain.finding_count << ",\n"
               << "      \"degradation_count\": " << domain.degradation_count
               << "\n    }" << (index + 1 == domains.size() ? "\n" : ",\n");
    }
    output << "  ],\n"
           << "  \"authentication\": {\n"
           << "    \"journal_available\": "
           << (authentication.journal_available ? "true" : "false") << ",\n"
           << "    \"session_state_available\": "
           << (authentication.session_state_available ? "true" : "false")
           << ",\n"
           << "    \"malformed_journal_records\": "
           << authentication.malformed_journal_records << ",\n"
           << "    \"journal_truncated\": "
           << (authentication.journal_truncated ? "true" : "false") << ",\n"
           << "    \"active_sessions\": [\n";
    std::size_t session_index = 0;
    for (const auto& [id, session] : active_sessions) {
        (void)id;
        output << "      {\n";
        string_field(output, "id", session.id, true, 8);
        string_field(output, "uid", session.uid, true, 8);
        string_field(output, "user", session.user, true, 8);
        string_field(output, "seat", session.seat, true, 8);
        string_field(output, "tty", session.tty, true, 8);
        string_field(output, "source", session.source, true, 8);
        string_field(output, "state", session.state, true, 8);
        output << "        \"remote\": " << (session.remote ? "true" : "false")
               << ",\n"
               << "        \"locked_known\": "
               << (session.locked_known ? "true" : "false") << ",\n"
               << "        \"locked\": " << (session.locked ? "true" : "false")
               << "\n      }"
               << (++session_index == active_sessions.size() ? "\n" : ",\n");
    }
    output << "    ],\n"
           << "    \"events\": [\n";
    for (std::size_t index = 0; index < authentication_events.size(); ++index) {
        const AuthenticationEvent& event = authentication_events[index];
        output << "      {\n";
        string_field(output, "timestamp", event.timestamp, true, 8);
        string_field(output, "type", authentication_event_type_name(event.type),
                     true, 8);
        string_field(output, "session_id", event.session_id, true, 8);
        string_field(output, "user", event.user, true, 8);
        string_field(output, "uid", event.uid, true, 8);
        string_field(output, "seat", event.seat, true, 8);
        string_field(output, "tty", event.tty, true, 8);
        string_field(output, "source", event.source, true, 8);
        string_field(output, "provider", event.provider, true, 8);
        string_field(output, "detail", event.detail, false, 8);
        output << "      }"
               << (index + 1 == authentication_events.size() ? "\n" : ",\n");
    }
    output << "    ]\n"
           << "  },\n"
           << "  \"finding_groups\": [\n";
    for (std::size_t index = 0; index < groups.size(); ++index) {
        const FindingGroup& group = groups[index];
        output << "    {\n"
               << "      \"classification\": \""
               << classification_id(group.classification) << "\",\n";
        string_field(output, "title", group.title);
        string_field(output, "first_seen", group.first_seen);
        string_field(output, "last_seen", group.last_seen);
        string_field(output, "rationale", group.rationale);
        string_field(output, "observation_summary", group.observation_summary);
        string_field(output, "recommended_action", group.recommended_action);
        output << "      \"finding_indexes\": [";
        for (std::size_t member = 0; member < group.finding_indexes.size(); ++member) {
            if (member != 0) output << ", ";
            output << group.finding_indexes[member];
        }
        output << "]\n    }" << (index + 1 == groups.size() ? "\n" : ",\n");
    }
    output << "  ],\n"
           << "  \"findings\": [\n";
    for (std::size_t index = 0; index < findings.size(); ++index) {
        const Finding& finding = findings[index];
        output << "    {\n";
        string_field(output, "timestamp", finding.timestamp);
        output << "      \"domain\": \"" << domain_id(finding.domain) << "\",\n"
               << "      \"priority\": \"" << priority_id(finding.priority)
               << "\",\n"
               << "      \"classification\": \""
               << classification_id(finding.classification) << "\",\n";
        string_field(output, "rule", finding.rule);
        string_field(output, "title", finding.title);
        string_field(output, "detail", finding.detail);
        string_field(output, "rationale", finding.rationale);
        string_field(output, "recommended_action", finding.recommended_action,
                     false);
        output << "    }" << (index + 1 == findings.size() ? "\n" : ",\n");
    }
    output << "  ],\n"
           << "  \"degradations\": [\n";
    for (std::size_t index = 0; index < degradations.size(); ++index) {
        const Degradation& degradation = degradations[index];
        output << "    {\n";
        string_field(output, "timestamp", degradation.timestamp);
        output << "      \"domain\": \"" << domain_id(degradation.domain)
               << "\",\n";
        string_field(output, "rule", degradation.rule);
        string_field(output, "detail", degradation.detail);
        output << "      \"count\": " << degradation.count << ",\n"
               << "      \"session_critical\": "
               << (degradation.session_critical ? "true" : "false") << ",\n";
        string_field(output, "recommended_action",
                     degradation_recommended_action(degradation), false);
        output << "    }"
               << (index + 1 == degradations.size() ? "\n" : ",\n");
    }
    output << "  ]\n}\n";
    return output.str();
}
