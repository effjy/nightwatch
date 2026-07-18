#include "assurance.hpp"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace {
bool starts_with(const std::string& value, const std::string& prefix) {
    return value.rfind(prefix, 0) == 0;
}

bool domain_clear(const std::vector<DomainStatus>& domains,
                  MonitoringDomain domain) {
    const auto found = std::find_if(
        domains.begin(), domains.end(), [domain](const DomainStatus& status) {
            return status.domain == domain;
        });
    return found != domains.end() &&
           found->state == VerificationState::verified;
}

std::string count_phrase(std::size_t count, const std::string& singular,
                         const std::string& plural) {
    return std::to_string(count) + " " + (count == 1 ? singular : plural);
}

bool contains(const std::string& value, const std::string& part) {
    return value.find(part) != std::string::npos;
}

std::time_t finding_time(const Finding& finding) {
    if (finding.timestamp.size() < 19) {
        return static_cast<std::time_t>(-1);
    }
    std::tm local{};
    std::istringstream input(finding.timestamp.substr(0, 19));
    input >> std::get_time(&local, "%Y-%m-%d %H:%M:%S");
    if (!input) {
        return static_cast<std::time_t>(-1);
    }
    local.tm_isdst = -1;
    return std::mktime(&local);
}

bool maintenance_candidate(const Finding& finding) {
    if (finding.priority != FindingPriority::notice) {
        return false;
    }
    if (finding.rule == "kernel.module-loaded" ||
        finding.rule == "kernel.module-unloaded" ||
        finding.rule == "kernel.bpf-program-lifecycle" ||
        finding.rule == "kernel.bpf-program-removed") {
        return true;
    }
    if (finding.rule == "network.not-in-baseline") {
        return contains(finding.detail, "/usr/lib/apt/methods/http");
    }
    if (finding.rule != "process.not-in-baseline" &&
        finding.rule != "script.not-in-baseline") {
        return false;
    }
    static const std::vector<std::string> markers{
        "/usr/sbin/aptd",
        "/usr/bin/cloud-id",
        "/usr/bin/hwe-support-status",
        "/usr/libexec/pk-debconf-helper",
        "/usr/bin/perl",
        "/usr/bin/debconf-communicate",
        "/usr/sbin/dpkg-preconfigure",
        "/usr/bin/dpkg",
        "/usr/bin/dpkg-deb",
        "/usr/share/debconf/frontend",
        "/var/lib/dpkg/info/",
        "/usr/sbin/apparmor_parser",
        "/usr/bin/mandb",
        "/usr/bin/run-parts",
        "/usr/sbin/update-initramfs",
        "/usr/sbin/mkinitramfs",
        "/usr/lib/dracut/dracut-install",
        "/usr/share/initramfs-tools/",
        "/usr/lib/linux/triggers/",
        "/etc/kernel/postinst.d/",
        "/usr/sbin/grub-mkconfig",
        "/etc/grub.d/",
        "/usr/bin/kmod"
    };
    return std::any_of(markers.begin(), markers.end(),
                       [&finding](const std::string& marker) {
                           return contains(finding.detail, marker);
                       });
}
}

MonitoringDomain domain_for_rule(const std::string& rule) {
    if (starts_with(rule, "retention.")) {
        return MonitoringDomain::retention;
    }
    if (starts_with(rule, "script.") ||
        starts_with(rule, "reviewed-script.")) {
        return MonitoringDomain::script;
    }
    if (starts_with(rule, "media.")) {
        return MonitoringDomain::media;
    }
    if (starts_with(rule, "pipewire.")) {
        return MonitoringDomain::pipewire;
    }
    if (starts_with(rule, "network.")) {
        if (rule == "network.event-limit-reached") {
            return MonitoringDomain::retention;
        }
        return MonitoringDomain::network;
    }
    if (starts_with(rule, "kernel.bpf") || starts_with(rule, "bpf.")) {
        return MonitoringDomain::bpf;
    }
    if (starts_with(rule, "kernel.")) {
        return MonitoringDomain::kernel;
    }
    if (starts_with(rule, "authentication.")) {
        return MonitoringDomain::authentication;
    }
    if (starts_with(rule, "persistence.")) {
        return MonitoringDomain::persistence;
    }
    if (starts_with(rule, "monitor.cadence") ||
        starts_with(rule, "monitor.snapshot") ||
        starts_with(rule, "monitor.final-snapshot")) {
        return MonitoringDomain::sampling;
    }
    if (starts_with(rule, "report.") || starts_with(rule, "journal.")) {
        return MonitoringDomain::evidence;
    }
    return MonitoringDomain::executable;
}

FindingPriority finding_priority(const std::string& severity) {
    return severity == "HIGH" ? FindingPriority::high
                              : FindingPriority::notice;
}

RuleMetadata rule_metadata(const std::string& rule, FindingPriority priority) {
    if (priority == FindingPriority::high) {
        return {
            FindingClassification::high_concern,
            "High-priority security finding",
            "Nightwatch detected behavior that violates a calibrated integrity "
            "or exposure expectation.",
            "Inspect the supporting evidence promptly and verify the responsible "
            "file, process, package, or system change before trusting it."
        };
    }
    if (rule == "network.not-in-baseline") {
        return {
            FindingClassification::probably_normal,
            "New low-risk network behavior",
            "A calibrated or fingerprint-reviewed executable used a socket "
            "pattern absent from calibration. The socket was not an externally "
            "reachable bind or a raw/packet socket.",
            "Confirm the named application was in use. Keep the observation as "
            "evidence; do not authorize it permanently unless the behavior is "
            "expected and repeatable."
        };
    }
    if (rule == "network.transient-ephemeral-bind") {
        return {
            FindingClassification::probably_normal,
            "Transient ephemeral UDP bind",
            "A calibrated executable briefly opened a wildcard UDP socket, but "
            "the bind ended before Nightwatch's persistence threshold.",
            "No action is normally required. Review only if the application was "
            "unexpected or similar binds later become persistent."
        };
    }
    if (rule == "pipewire.capture-active" ||
        rule == "media.direct-device-access") {
        return {
            FindingClassification::probably_normal,
            "Calibrated media activity",
            "A calibrated media-access pattern was active and attributed to a "
            "known application.",
            "Confirm that the named application was expected to use the "
            "microphone, camera, or audio device at that time."
        };
    }
    if (rule == "kernel.bpf-program-lifecycle" ||
        rule == "kernel.bpf-program-removed" ||
        rule == "kernel.module-loaded" ||
        rule == "kernel.module-unloaded") {
        return {
            FindingClassification::needs_review,
            "Kernel lifecycle change",
            "Kernel or BPF inventory changed without an immediate integrity "
            "violation, but the lifecycle change was absent from calibration.",
            "Compare the event time with updates, device activity, and service "
            "logs before accepting the change as routine."
        };
    }
    if (rule == "process.not-in-baseline" ||
        rule == "script.not-in-baseline") {
        return {
            FindingClassification::needs_review,
            "New executable or script",
            "A path absent from calibration was observed. Absence from the "
            "baseline is not proof of compromise, but its origin is not yet "
            "established.",
            "Identify the package or owner, verify its fingerprint and purpose, "
            "and review it only after establishing that provenance."
        };
    }
    if (rule == "persistence.entry-removed") {
        return {
            FindingClassification::needs_review,
            "Persistence entry removed",
            "A calibrated startup or scheduling entry disappeared. Removal may "
            "be legitimate maintenance, but it changes the host's startup state.",
            "Confirm the removal against an expected package, service, or user "
            "configuration change before recalibrating."
        };
    }
    if (rule == "authentication.session-started") {
        return {
            FindingClassification::needs_review,
            "Login or session started",
            "A login/session began after Nightwatch started. This can be normal "
            "during attended use, but it is important evidence during an "
            "unattended watch.",
            "Confirm the user, time, seat or TTY, and remote source when present. "
            "Correlate unexpected sessions with lock state and failed authentication."
        };
    }
    if (rule == "authentication.failed") {
        return {
            FindingClassification::needs_review,
            "Failed authentication",
            "An authentication provider rejected a credential. Owner mistakes "
            "are common, but an unexpected failure can indicate attempted access.",
            "Confirm whether the failure was yours. Review the named provider, "
            "user, TTY, and source, especially when failures repeat or are remote."
        };
    }
    if (rule == "authentication.session-unlocked") {
        return {
            FindingClassification::needs_review,
            "Session unlocked",
            "A reliably observed lock-state transition shows that an existing "
            "session became unlocked while Nightwatch was running.",
            "Confirm that you performed the unlock and correlate its time with "
            "session starts and failed authentication evidence."
        };
    }
    return {
        FindingClassification::needs_review,
        "Observation requiring review",
        "Nightwatch recorded a low-priority deviation from calibrated behavior.",
        "Review the supporting evidence and correlate it with expected activity "
        "before changing the baseline or reviewed-fingerprint database."
    };
}

std::string domain_name(MonitoringDomain domain) {
    switch (domain) {
    case MonitoringDomain::executable: return "Executable and process integrity";
    case MonitoringDomain::script: return "Script integrity";
    case MonitoringDomain::media: return "Direct media-device access";
    case MonitoringDomain::pipewire: return "PipeWire capture attribution";
    case MonitoringDomain::network: return "Network activity";
    case MonitoringDomain::kernel: return "Kernel posture and modules";
    case MonitoringDomain::bpf: return "BPF inventory";
    case MonitoringDomain::authentication:
        return "Authentication and login sessions";
    case MonitoringDomain::persistence: return "Persistence mechanisms";
    case MonitoringDomain::sampling: return "Snapshot sampling";
    case MonitoringDomain::retention: return "Observation retention";
    case MonitoringDomain::evidence: return "Report evidence";
    }
    return "Unknown domain";
}

std::string verification_state_name(VerificationState state) {
    switch (state) {
    case VerificationState::verified: return "VERIFIED";
    case VerificationState::finding_detected: return "FINDING DETECTED";
    case VerificationState::unknown: return "UNKNOWN / UNAVAILABLE";
    }
    return "UNKNOWN / UNAVAILABLE";
}

std::string finding_priority_name(FindingPriority priority) {
    return priority == FindingPriority::high ? "HIGH" : "NOTICE";
}

std::string finding_classification_name(
    FindingClassification classification) {
    switch (classification) {
    case FindingClassification::probably_normal: return "PROBABLY NORMAL";
    case FindingClassification::needs_review: return "NEEDS REVIEW";
    case FindingClassification::high_concern: return "HIGH CONCERN";
    }
    return "NEEDS REVIEW";
}

std::string degradation_recommended_action(
    const Degradation& degradation) {
    if (starts_with(degradation.rule, "retention.")) {
        return "Review the retained evidence and dropped-record count, identify "
               "whether the activity was expected, and raise or redesign the "
               "specific bounded budget before relying on a repeat session.";
    }
    if (degradation.rule == "reviewed-script.unverified" ||
        degradation.rule == "reviewed-executable.unverified") {
        return "The process may have ended before its process-visible file could "
               "be fingerprinted. Verify the current protected reviewed record "
               "and package provenance; repeated occurrences indicate that "
               "earlier capture or event-driven observation is needed.";
    }
    if (degradation.rule == "monitor.snapshot-failed" ||
        degradation.rule == "monitor.final-snapshot-failed") {
        return "Review the failure detail and recovery journal. Repeat an "
               "attended watch if skipped sampling could have hidden relevant "
               "activity.";
    }
    if (degradation.rule == "monitor.cadence-overrun") {
        return "Review the slowest collector timings and system load. Repeat an "
               "attended watch after correcting persistent overruns or choose "
               "an interval the host can sustain.";
    }
    if (degradation.rule == "network.event-limit-reached") {
        return "Review the dropped-session count and report size, then raise or "
               "redesign the bounded retention policy before relying on a "
               "similarly busy unattended session.";
    }
    if (degradation.rule == "pipewire.inventory-unavailable" ||
        degradation.rule == "kernel.bpf-inventory-unavailable") {
        return "Check the named helper, permissions, and service availability, "
               "then rerun preflight and an attended watch before relying on "
               "that domain.";
    }
    if (starts_with(degradation.rule, "authentication.")) {
        return "Check journal and systemd-logind access, then rerun preflight "
               "and an attended watch. Do not interpret missing authentication "
               "evidence as proof that no login or unlock occurred.";
    }
    return "Restore or validate the affected monitoring source before treating "
           "this domain as verified.";
}

bool cadence_visibility_degraded(const SessionMetadata& metadata) {
    if (metadata.deadline_overruns == 0 ||
        metadata.sampling_interval_seconds == 0) {
        return false;
    }
    const std::uint64_t interval_us =
        metadata.sampling_interval_seconds * 1000000U;
    return metadata.cumulative_overrun_microseconds >= interval_us ||
           metadata.maximum_scan_microseconds >= interval_us * 2U;
}

std::string session_conclusion_name(SessionConclusion conclusion) {
    switch (conclusion) {
    case SessionConclusion::fully_verified:
        return "FULLY VERIFIED - NO FINDINGS";
    case SessionConclusion::verified_with_findings:
        return "VERIFIED WITH FINDINGS";
    case SessionConclusion::partially_verified:
        return "PARTIALLY VERIFIED";
    case SessionConclusion::inconclusive:
        return "INCONCLUSIVE";
    }
    return "INCONCLUSIVE";
}

std::vector<MonitoringDomain> monitored_domains() {
    return {
        MonitoringDomain::executable,
        MonitoringDomain::script,
        MonitoringDomain::media,
        MonitoringDomain::pipewire,
        MonitoringDomain::network,
        MonitoringDomain::kernel,
        MonitoringDomain::bpf,
        MonitoringDomain::authentication,
        MonitoringDomain::persistence,
        MonitoringDomain::sampling,
        MonitoringDomain::retention,
        MonitoringDomain::evidence
    };
}

std::vector<DomainStatus> summarize_domains(
    const std::vector<Finding>& findings,
    const std::vector<Degradation>& degradations) {
    std::map<MonitoringDomain, DomainStatus> result;
    for (MonitoringDomain domain : monitored_domains()) {
        result.emplace(domain, DomainStatus{domain});
    }
    for (const Finding& finding : findings) {
        DomainStatus& status = result[finding.domain];
        status.domain = finding.domain;
        ++status.finding_count;
        if (status.state == VerificationState::verified) {
            status.state = VerificationState::finding_detected;
        }
    }
    for (const Degradation& degradation : degradations) {
        DomainStatus& status = result[degradation.domain];
        status.domain = degradation.domain;
        ++status.degradation_count;
        status.state = VerificationState::unknown;
    }

    std::vector<DomainStatus> statuses;
    statuses.reserve(result.size());
    for (MonitoringDomain domain : monitored_domains()) {
        statuses.push_back(result.at(domain));
    }
    return statuses;
}

SessionConclusion summarize_session(
    const std::vector<DomainStatus>& domains,
    const std::vector<Degradation>& degradations) {
    if (std::any_of(degradations.begin(), degradations.end(),
                    [](const Degradation& degradation) {
                        return degradation.session_critical;
                    })) {
        return SessionConclusion::inconclusive;
    }
    if (std::any_of(domains.begin(), domains.end(),
                    [](const DomainStatus& status) {
                        return status.state == VerificationState::unknown;
                    })) {
        return SessionConclusion::partially_verified;
    }
    if (std::any_of(domains.begin(), domains.end(),
                    [](const DomainStatus& status) {
                        return status.state ==
                               VerificationState::finding_detected;
                    })) {
        return SessionConclusion::verified_with_findings;
    }
    return SessionConclusion::fully_verified;
}

std::vector<FindingGroup> correlate_finding_groups(
    const std::vector<Finding>& findings) {
    std::vector<std::size_t> candidates;
    bool apt_acquisition = false;
    bool transaction_engine = false;
    bool package_configuration = false;
    bool kernel_package_configuration = false;
    std::time_t earliest = static_cast<std::time_t>(-1);
    std::time_t latest = static_cast<std::time_t>(-1);

    for (std::size_t index = 0; index < findings.size(); ++index) {
        const Finding& finding = findings[index];
        if (!maintenance_candidate(finding)) {
            continue;
        }
        const std::time_t observed = finding_time(finding);
        if (observed == static_cast<std::time_t>(-1)) {
            continue;
        }
        candidates.push_back(index);
        earliest = earliest == static_cast<std::time_t>(-1)
            ? observed : std::min(earliest, observed);
        latest = latest == static_cast<std::time_t>(-1)
            ? observed : std::max(latest, observed);
        apt_acquisition = apt_acquisition ||
            contains(finding.detail, "/usr/lib/apt/methods/http");
        transaction_engine = transaction_engine ||
            contains(finding.detail, "/usr/sbin/aptd") ||
            contains(finding.detail, "/usr/bin/dpkg");
        package_configuration = package_configuration ||
            contains(finding.detail, "/var/lib/dpkg/info/") ||
            contains(finding.detail, "/usr/sbin/update-initramfs") ||
            contains(finding.detail, "/usr/sbin/mkinitramfs") ||
            contains(finding.detail, "/usr/share/initramfs-tools/") ||
            contains(finding.detail, "/usr/sbin/apparmor_parser") ||
            contains(finding.detail, "/usr/bin/mandb");
        kernel_package_configuration = kernel_package_configuration ||
            contains(finding.detail, "/var/lib/dpkg/info/linux-image-") ||
            contains(finding.detail, "/var/lib/dpkg/info/linux-modules-") ||
            contains(finding.detail, "/usr/lib/linux/triggers/") ||
            contains(finding.detail, "/etc/kernel/postinst.d/") ||
            contains(finding.detail, "/usr/sbin/grub-mkconfig") ||
            contains(finding.detail, "/etc/grub.d/");
    }

    if (!kernel_package_configuration) {
        candidates.erase(
            std::remove_if(
                candidates.begin(), candidates.end(),
                [&findings](std::size_t index) {
                    return findings[index].rule.rfind("kernel.", 0) == 0;
                }),
            candidates.end());
        earliest = static_cast<std::time_t>(-1);
        latest = static_cast<std::time_t>(-1);
        for (std::size_t index : candidates) {
            const std::time_t observed = finding_time(findings[index]);
            earliest = earliest == static_cast<std::time_t>(-1)
                ? observed : std::min(earliest, observed);
            latest = latest == static_cast<std::time_t>(-1)
                ? observed : std::max(latest, observed);
        }
    }

    constexpr std::time_t maximum_chain_seconds = 10 * 60;
    if (candidates.size() < 4 || !apt_acquisition || !transaction_engine ||
        !package_configuration || earliest == static_cast<std::time_t>(-1) ||
        latest - earliest > maximum_chain_seconds) {
        return {};
    }

    const Finding& first = findings[candidates.front()];
    const Finding& last = findings[candidates.back()];
    FindingGroup group;
    group.classification = FindingClassification::needs_review;
    group.title = "Correlated Ubuntu package-maintenance chain";
    group.first_seen = first.timestamp;
    group.last_seen = last.timestamp;
    group.rationale =
        "APT acquisition, a package transaction engine, and package "
        "configuration hooks appeared together within ten minutes. This is "
        "consistent with one software-update operation, but Nightwatch does not "
        "treat temporal correlation alone as package authorization.";
    group.observation_summary =
        std::to_string(candidates.size()) +
        " low-priority observations covered APT downloads, AptDaemon/dpkg or "
        "debconf activity, and package configuration work such as AppArmor, "
        "man-db, or initramfs processing.";
    if (kernel_package_configuration) {
        group.observation_summary +=
            " Kernel-package post-install, GRUB, signed module lifecycle, and "
            "expected systemd BPF lifecycle observations in the same window "
            "were included.";
    }
    group.recommended_action =
        "Confirm the same time window in APT and dpkg logs and verify package "
        "provenance. Recalibrate after an authorized update changes installed "
        "files. The complete member findings remain in the Alerts appendix.";
    group.finding_indexes = std::move(candidates);
    return {std::move(group)};
}

std::string outcome_narrative(
    const std::vector<Finding>& findings,
    const std::vector<Degradation>& degradations,
    const std::vector<DomainStatus>& domains) {
    if (findings.empty() && degradations.empty()) {
        return "All monitored domains completed without a finding or known "
               "visibility loss.";
    }

    std::ostringstream output;
    const std::size_t high = static_cast<std::size_t>(std::count_if(
        findings.begin(), findings.end(), [](const Finding& finding) {
            return finding.priority == FindingPriority::high;
        }));
    const std::size_t probably_normal = static_cast<std::size_t>(std::count_if(
        findings.begin(), findings.end(), [](const Finding& finding) {
            return finding.classification ==
                   FindingClassification::probably_normal;
        }));
    const bool network_only = !findings.empty() &&
        std::all_of(findings.begin(), findings.end(), [](const Finding& finding) {
            return finding.domain == MonitoringDomain::network;
        });
    const std::vector<FindingGroup> groups = correlate_finding_groups(findings);
    std::size_t grouped_findings = 0;
    for (const FindingGroup& group : groups) {
        grouped_findings += group.finding_indexes.size();
    }
    const std::size_t attention_items =
        findings.size() - grouped_findings + groups.size();

    if (high == 0 && network_only) {
        output << count_phrase(
            findings.size(), "low-priority network behavior pattern was",
            "low-priority network behavior patterns were") << " observed";
        if (probably_normal == findings.size()) {
            output << " during active use. "
                   << (findings.size() == 1 ? "It was" : "All were")
                   << " attributed to calibrated or fingerprint-reviewed "
                      "applications and met low-risk policy conditions";
        }
        output << ". ";
    } else if (high == 0 && !groups.empty()) {
        output << findings.size() << " low-priority findings were condensed into "
               << attention_items << " attention item"
               << (attention_items == 1 ? "" : "s")
               << ", including one correlated software-maintenance chain. ";
    } else if (!findings.empty()) {
        output << count_phrase(findings.size(), "security finding was",
                               "security findings were")
               << " recorded, including " << high << " high-priority. ";
    }

    if (degradations.empty()) {
        output << "Monitoring visibility remained complete";
    } else {
        output << count_phrase(degradations.size(),
                               "monitoring degradation reduced",
                               "monitoring degradations reduced")
               << " verification coverage";
    }

    const bool correlated_integrity_clear =
        domain_clear(domains, MonitoringDomain::executable) &&
        domain_clear(domains, MonitoringDomain::script) &&
        domain_clear(domains, MonitoringDomain::kernel) &&
        domain_clear(domains, MonitoringDomain::bpf) &&
        domain_clear(domains, MonitoringDomain::media) &&
        domain_clear(domains, MonitoringDomain::pipewire);
    if (correlated_integrity_clear) {
        output << ", and no correlated executable, script, kernel, BPF, "
                  "microphone, or camera findings were detected";
    }
    output << '.';
    return output.str();
}

std::string render_assurance_sections(
    const SessionMetadata& metadata,
    const std::vector<Finding>& findings,
    const std::vector<Degradation>& degradations,
    const std::vector<DomainStatus>& domains) {
    const SessionConclusion conclusion =
        summarize_session(domains, degradations);
    const std::size_t high_findings = static_cast<std::size_t>(std::count_if(
        findings.begin(), findings.end(), [](const Finding& finding) {
            return finding.priority == FindingPriority::high;
        }));

    std::ostringstream output;
    output << "Assurance summary\n"
           << "-----------------\n"
           << "Overall result: " << session_conclusion_name(conclusion) << '\n'
           << "Security findings: " << findings.size() << " ("
           << high_findings << " high, "
           << findings.size() - high_findings << " notice)\n"
           << "Monitoring degradations: " << degradations.size() << '\n'
           << outcome_narrative(findings, degradations, domains) << '\n';
    for (const DomainStatus& status : domains) {
        output << "- " << domain_name(status.domain) << ": "
               << verification_state_name(status.state);
        if (status.finding_count != 0 || status.degradation_count != 0) {
            output << " (" << status.finding_count << " finding(s), "
                   << status.degradation_count << " degradation(s))";
        }
        output << '\n';
    }

    output << "\nWhat went well\n"
           << "--------------\n";
    if (metadata.skipped_snapshots == 0 && metadata.deadline_overruns == 0) {
        output << "- All " << metadata.snapshots
               << " snapshots completed without a failed scan or cadence "
                  "overrun.\n";
    } else if (metadata.skipped_snapshots == 0) {
        output << "- All " << metadata.snapshots
               << " snapshots completed successfully; "
               << metadata.deadline_overruns
               << " cadence overrun(s) are quantified below.\n";
    } else {
        output << "- " << metadata.snapshots
               << " snapshots completed successfully; see visibility problems "
                  "below for skipped scans.\n";
    }
    if (degradations.empty()) {
        output << "- Monitoring visibility remained complete; no helper, "
                  "sampling, retention, or evidence degradation was recorded.\n";
    }
    for (const DomainStatus& status : domains) {
        if (status.state == VerificationState::verified) {
            output << "- " << domain_name(status.domain)
                   << " completed with no finding.\n";
        }
    }

    output << "\nWhat needs attention\n"
           << "--------------------\n";
    if (findings.empty() && degradations.empty()) {
        output << "Nothing requires attention from this session.\n";
    } else {
        const std::vector<FindingGroup> groups =
            correlate_finding_groups(findings);
        std::set<std::size_t> grouped_indexes;
        for (const FindingGroup& group : groups) {
            grouped_indexes.insert(group.finding_indexes.begin(),
                                   group.finding_indexes.end());
            output << '['
                   << finding_classification_name(group.classification)
                   << "] " << group.title << " ("
                   << group.finding_indexes.size() << " observations)\n"
                   << "  Window: " << group.first_seen << " through "
                   << group.last_seen << '\n'
                   << "  Why it matters: " << group.rationale << '\n'
                   << "  Observed: " << group.observation_summary << '\n'
                   << "  Recommended follow-up: "
                   << group.recommended_action << '\n';
        }
        for (std::size_t index = 0; index < findings.size(); ++index) {
            if (grouped_indexes.find(index) != grouped_indexes.end()) {
                continue;
            }
            const Finding& finding = findings[index];
            output << '['
                   << finding_classification_name(finding.classification)
                   << "] " << finding.title << " ("
                   << finding_priority_name(finding.priority) << ", "
                   << finding.rule << ")\n"
                   << "  Why it matters: " << finding.rationale << '\n'
                   << "  Observed: " << finding.detail << '\n'
                   << "  Recommended follow-up: "
                   << finding.recommended_action << '\n';
        }
        for (const Degradation& degradation : degradations) {
            output << "[VISIBILITY PROBLEM] " << degradation.rule << " ("
                   << domain_name(degradation.domain) << ")\n"
                   << "  Effect: " << degradation.detail << '\n'
                   << "  Recommended follow-up: "
                   << degradation_recommended_action(degradation) << '\n';
        }
    }
    output << '\n';
    return output.str();
}
