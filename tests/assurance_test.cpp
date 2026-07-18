#include "assurance.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

int main() {
    assert(domain_for_rule("process.not-in-baseline") ==
           MonitoringDomain::executable);
    assert(domain_for_rule("reviewed-script.unverified") ==
           MonitoringDomain::script);
    assert(domain_for_rule("kernel.bpf-program-new") ==
           MonitoringDomain::bpf);
    assert(domain_for_rule("network.event-limit-reached") ==
           MonitoringDomain::retention);
    assert(domain_for_rule("retention.media-limit-reached") ==
           MonitoringDomain::retention);
    assert(domain_for_rule("monitor.snapshot-failed") ==
           MonitoringDomain::sampling);
    assert(domain_for_rule("monitor.cadence-overrun") ==
           MonitoringDomain::sampling);
    assert(domain_for_rule("persistence.entry-added") ==
           MonitoringDomain::persistence);
    assert(domain_for_rule("authentication.failed") ==
           MonitoringDomain::authentication);

    std::vector<Finding> findings;
    std::vector<Degradation> degradations;
    auto domains = summarize_domains(findings, degradations);
    assert(summarize_session(domains, degradations) ==
           SessionConclusion::fully_verified);

    const RuleMetadata network_metadata = rule_metadata(
        "network.not-in-baseline", FindingPriority::notice);
    assert(network_metadata.classification ==
           FindingClassification::probably_normal);
    assert(!network_metadata.rationale.empty());
    assert(!network_metadata.recommended_action.empty());
    findings.push_back({
        "now",
        MonitoringDomain::network,
        FindingPriority::notice,
        network_metadata.classification,
        "network.not-in-baseline",
        network_metadata.title,
        "new behavior",
        network_metadata.rationale,
        network_metadata.recommended_action
    });
    domains = summarize_domains(findings, degradations);
    assert(summarize_session(domains, degradations) ==
           SessionConclusion::verified_with_findings);

    degradations.push_back({"now", MonitoringDomain::script,
                            "reviewed-script.unverified",
                            "short-lived script could not be hashed", 1, false});
    domains = summarize_domains(findings, degradations);
    assert(summarize_session(domains, degradations) ==
           SessionConclusion::partially_verified);
    for (const DomainStatus& status : domains) {
        if (status.domain == MonitoringDomain::script) {
            assert(status.state == VerificationState::unknown);
            assert(status.degradation_count == 1);
        }
    }

    degradations.push_back({"now", MonitoringDomain::evidence,
                            "report.write-failed", "evidence was not preserved",
                            1, true});
    domains = summarize_domains(findings, degradations);
    assert(summarize_session(domains, degradations) ==
           SessionConclusion::inconclusive);

    assert(finding_priority("HIGH") == FindingPriority::high);
    assert(finding_priority("NOTICE") == FindingPriority::notice);
    assert(rule_metadata("network.new-external-bind", FindingPriority::high)
               .classification == FindingClassification::high_concern);
    assert(rule_metadata("process.not-in-baseline", FindingPriority::notice)
               .classification == FindingClassification::needs_review);
    assert(rule_metadata("persistence.entry-removed", FindingPriority::notice)
               .classification == FindingClassification::needs_review);
    assert(rule_metadata("authentication.session-started",
                         FindingPriority::notice)
               .classification == FindingClassification::needs_review);
    assert(rule_metadata("authentication.failed", FindingPriority::notice)
               .title == "Failed authentication");
    assert(finding_classification_name(
               FindingClassification::probably_normal) == "PROBABLY NORMAL");
    assert(session_conclusion_name(SessionConclusion::partially_verified) ==
           "PARTIALLY VERIFIED");

    std::vector<Degradation> no_degradations;
    domains = summarize_domains(findings, no_degradations);
    const std::string narrative =
        outcome_narrative(findings, no_degradations, domains);
    assert(narrative.find("low-priority network behavior pattern") !=
           std::string::npos);
    assert(narrative.find("calibrated or fingerprint-reviewed") !=
           std::string::npos);
    assert(narrative.find("It was attributed") != std::string::npos);
    assert(narrative.find("All were attributed") == std::string::npos);
    assert(narrative.find("Monitoring visibility remained complete") !=
           std::string::npos);

    const SessionMetadata metadata{
        "test-host", "test-kernel", "start", "stop", "baseline", "created",
        600, 601, 0, 0, 0, 0, 0, 0, 0, {}, {}
    };
    SessionMetadata jitter = metadata;
    jitter.sampling_interval_seconds = 1;
    jitter.deadline_overruns = 4;
    jitter.cumulative_overrun_microseconds = 4000;
    jitter.maximum_scan_microseconds = 1001000;
    assert(!cadence_visibility_degraded(jitter));
    jitter.cumulative_overrun_microseconds = 1000000;
    assert(cadence_visibility_degraded(jitter));
    jitter.cumulative_overrun_microseconds = 1;
    jitter.maximum_scan_microseconds = 2000000;
    assert(cadence_visibility_degraded(jitter));
    const std::string rendered = render_assurance_sections(
        metadata, findings, no_degradations, domains);
    assert(rendered.find("Overall result: VERIFIED WITH FINDINGS") !=
           std::string::npos);
    assert(rendered.find("What went well") != std::string::npos);
    assert(rendered.find("What needs attention") != std::string::npos);
    assert(rendered.find("[PROBABLY NORMAL] New low-risk network behavior") !=
           std::string::npos);
    assert(rendered.find("Why it matters:") != std::string::npos);
    assert(rendered.find("Recommended follow-up:") != std::string::npos);
    assert(rendered.find("All 601 snapshots completed") !=
           std::string::npos);

    const RuleMetadata high_metadata = rule_metadata(
        "network.new-external-bind", FindingPriority::high);
    std::vector<Finding> high_findings{{
        "now", MonitoringDomain::network, FindingPriority::high,
        high_metadata.classification, "network.new-external-bind",
        high_metadata.title, "external bind", high_metadata.rationale,
        high_metadata.recommended_action
    }};
    const auto high_domains = summarize_domains(high_findings, no_degradations);
    const std::string high_rendered = render_assurance_sections(
        metadata, high_findings, no_degradations, high_domains);
    assert(high_rendered.find("[HIGH CONCERN]") != std::string::npos);
    assert(high_rendered.find("[PROBABLY NORMAL]") == std::string::npos);

    const Degradation reviewed_race{
        "now", MonitoringDomain::script, "reviewed-script.unverified",
        "short-lived script could not be hashed", 1, false
    };
    assert(degradation_recommended_action(reviewed_race).find(
               "process may have ended") != std::string::npos);
    const std::vector<Degradation> reviewed_degradations{reviewed_race};
    const auto degraded_domains =
        summarize_domains({}, reviewed_degradations);
    const std::string degraded_rendered = render_assurance_sections(
        metadata, {}, reviewed_degradations, degraded_domains);
    assert(degraded_rendered.find("earlier capture or event-driven observation") !=
           std::string::npos);

    auto notice = [](const std::string& timestamp, MonitoringDomain domain,
                     const std::string& rule, const std::string& detail) {
        const RuleMetadata metadata = rule_metadata(
            rule, FindingPriority::notice);
        return Finding{
            timestamp, domain, FindingPriority::notice,
            metadata.classification, rule, metadata.title, detail,
            metadata.rationale, metadata.recommended_action
        };
    };
    const std::vector<Finding> maintenance_findings{
        notice("2026-07-16 12:10:38 EDT", MonitoringDomain::script,
               "script.not-in-baseline",
               "python invoked script /usr/sbin/aptd"),
        notice("2026-07-16 12:10:40 EDT", MonitoringDomain::network,
               "network.not-in-baseline",
               "socket held by /usr/lib/apt/methods/http"),
        notice("2026-07-16 12:11:07 EDT", MonitoringDomain::executable,
               "process.not-in-baseline",
               "executable /usr/bin/dpkg was observed"),
        notice("2026-07-16 12:11:08 EDT", MonitoringDomain::script,
               "script.not-in-baseline",
               "script /var/lib/dpkg/info/example.postinst was observed"),
        notice("2026-07-16 12:11:10 EDT", MonitoringDomain::executable,
               "process.not-in-baseline",
               "executable /usr/bin/mandb was observed"),
        notice("2026-07-16 12:11:13 EDT", MonitoringDomain::script,
               "script.not-in-baseline",
               "script /usr/sbin/update-initramfs was observed"),
        notice("2026-07-16 12:17:08 EDT", MonitoringDomain::executable,
               "process.not-in-baseline",
               "executable /usr/bin/pluma was observed")
    };
    const std::vector<FindingGroup> maintenance_groups =
        correlate_finding_groups(maintenance_findings);
    assert(maintenance_groups.size() == 1);
    assert(maintenance_groups.front().finding_indexes.size() == 6);
    const auto maintenance_domains =
        summarize_domains(maintenance_findings, no_degradations);
    const std::string maintenance_rendered = render_assurance_sections(
        metadata, maintenance_findings, no_degradations, maintenance_domains);
    assert(maintenance_rendered.find(
               "Correlated Ubuntu package-maintenance chain (6 observations)") !=
           std::string::npos);
    assert(maintenance_rendered.find(
               "7 low-priority findings were condensed into 2 attention items") !=
           std::string::npos);
    assert(maintenance_rendered.find(
               "executable /usr/bin/pluma was observed") != std::string::npos);
    assert(maintenance_rendered.find(
               "python invoked script /usr/sbin/aptd") == std::string::npos);
    assert(maintenance_rendered.find(
               "complete member findings remain in the Alerts appendix") !=
           std::string::npos);

    const std::vector<Finding> incomplete_maintenance{
        maintenance_findings[1],
        maintenance_findings[2],
        maintenance_findings[6]
    };
    assert(correlate_finding_groups(incomplete_maintenance).empty());

    std::vector<Finding> kernel_maintenance = maintenance_findings;
    kernel_maintenance.push_back(notice(
        "2026-07-16 12:11:14 EDT", MonitoringDomain::script,
        "script.not-in-baseline",
        "script /var/lib/dpkg/info/linux-image-7.0.0.postinst was observed"));
    kernel_maintenance.push_back(notice(
        "2026-07-16 12:11:15 EDT", MonitoringDomain::kernel,
        "kernel.module-loaded",
        "New signed in-tree module cpuid was loaded"));
    kernel_maintenance.push_back(notice(
        "2026-07-16 12:11:16 EDT", MonitoringDomain::script,
        "script.not-in-baseline",
        "script /usr/sbin/grub-mkconfig was observed"));
    kernel_maintenance.push_back(notice(
        "2026-07-16 12:11:17 EDT", MonitoringDomain::bpf,
        "kernel.bpf-program-lifecycle",
        "New expected systemd cgroup BPF program was observed"));
    kernel_maintenance.push_back(notice(
        "2026-07-16 12:11:18 EDT", MonitoringDomain::executable,
        "process.not-in-baseline",
        "executable /usr/bin/pkexec was observed"));
    const auto kernel_groups = correlate_finding_groups(kernel_maintenance);
    assert(kernel_groups.size() == 1);
    assert(kernel_groups.front().finding_indexes.size() == 10);
    const auto kernel_domains =
        summarize_domains(kernel_maintenance, no_degradations);
    const std::string kernel_rendered = render_assurance_sections(
        metadata, kernel_maintenance, no_degradations, kernel_domains);
    assert(kernel_rendered.find(
               "Kernel-package post-install, GRUB, signed module lifecycle") !=
           std::string::npos);
    assert(kernel_rendered.find(
               "executable /usr/bin/pkexec was observed") != std::string::npos);
    assert(kernel_rendered.find(
               "New signed in-tree module cpuid was loaded") ==
           std::string::npos);

    std::vector<Finding> non_kernel_chain = maintenance_findings;
    non_kernel_chain.push_back(notice(
        "2026-07-16 12:11:14 EDT", MonitoringDomain::kernel,
        "kernel.module-loaded",
        "New signed in-tree module cpuid was loaded"));
    const auto non_kernel_groups =
        correlate_finding_groups(non_kernel_chain);
    assert(non_kernel_groups.size() == 1);
    assert(non_kernel_groups.front().finding_indexes.size() == 6);

    std::vector<Finding> high_maintenance = maintenance_findings;
    high_maintenance[2] = high_findings.front();
    const auto high_maintenance_groups =
        correlate_finding_groups(high_maintenance);
    assert(high_maintenance_groups.size() == 1);
    assert(high_maintenance_groups.front().finding_indexes.size() == 5);
    const auto high_maintenance_domains =
        summarize_domains(high_maintenance, no_degradations);
    const std::string high_maintenance_rendered = render_assurance_sections(
        metadata, high_maintenance, no_degradations, high_maintenance_domains);
    assert(high_maintenance_rendered.find("[HIGH CONCERN]") !=
           std::string::npos);
    assert(high_maintenance_rendered.find(
               "Correlated Ubuntu package-maintenance chain (5 observations)") !=
           std::string::npos);

    std::cout << "assurance tests passed\n";
    return 0;
}
