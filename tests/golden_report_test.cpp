#include "assurance.hpp"
#include "sha256.hpp"

#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

namespace {
Finding make_finding(const std::string& timestamp, MonitoringDomain domain,
                     FindingPriority priority, const std::string& rule,
                     const std::string& detail) {
    const RuleMetadata metadata = rule_metadata(rule, priority);
    return {
        timestamp, domain, priority, metadata.classification, rule,
        metadata.title, detail, metadata.rationale,
        metadata.recommended_action
    };
}

SessionMetadata metadata() {
    return {
        "golden-host",
        "Linux golden-kernel x86_64",
        "2026-07-16 01:00:00 EDT",
        "2026-07-16 02:00:00 EDT",
        "config/baseline.db",
        "2026-07-16 00:55:00 EDT",
        3600,
        3601,
        0, 0, 0, 0, 0, 0, 0, {}, {}
    };
}

std::string render(const std::vector<Finding>& findings,
                   const std::vector<Degradation>& degradations) {
    const auto domains = summarize_domains(findings, degradations);
    return render_assurance_sections(
        metadata(), findings, degradations, domains);
}

std::map<std::string, std::string> scenarios() {
    const Finding network = make_finding(
        "2026-07-16 01:10:00 EDT", MonitoringDomain::network,
        FindingPriority::notice, "network.not-in-baseline",
        "Firefox used one new local DNS socket pattern");
    const Finding high = make_finding(
        "2026-07-16 01:12:00 EDT", MonitoringDomain::network,
        FindingPriority::high, "network.new-external-bind",
        "An unexpected executable opened an externally reachable listener");
    const Degradation partial{
        "2026-07-16 01:15:00 EDT", MonitoringDomain::script,
        "reviewed-script.unverified",
        "A short-lived reviewed script ended before fingerprinting", 1, false
    };
    const Degradation critical{
        "2026-07-16 01:16:00 EDT", MonitoringDomain::evidence,
        "report.write-failed", "The durable report could not be preserved",
        1, true
    };
    const Finding persistence = make_finding(
        "2026-07-16 01:18:00 EDT", MonitoringDomain::persistence,
        FindingPriority::high, "persistence.entry-added",
        "systemd entry /etc/systemd/system/example.service appeared after calibration");
    const Degradation persistence_unknown{
        "2026-07-16 01:19:00 EDT", MonitoringDomain::persistence,
        "persistence.inventory-unavailable",
        "A protected user systemd directory could not be read", 1, false
    };
    const Finding authentication = make_finding(
        "2026-07-16 01:19:30 EDT", MonitoringDomain::authentication,
        FindingPriority::notice, "authentication.failed",
        "authentication failed for user user on seat seat0 [source "
        "mate-screensaver-dialog]");
    const Degradation authentication_unknown{
        "2026-07-16 01:19:31 EDT", MonitoringDomain::authentication,
        "authentication.journal-unavailable",
        "journalctl could not establish a readable cursor", 1, false
    };

    const std::vector<Finding> maintenance{
        make_finding(
            "2026-07-16 01:20:00 EDT", MonitoringDomain::script,
            FindingPriority::notice, "script.not-in-baseline",
            "python invoked script /usr/sbin/aptd"),
        make_finding(
            "2026-07-16 01:20:02 EDT", MonitoringDomain::network,
            FindingPriority::notice, "network.not-in-baseline",
            "APT socket held by /usr/lib/apt/methods/http"),
        make_finding(
            "2026-07-16 01:20:05 EDT", MonitoringDomain::executable,
            FindingPriority::notice, "process.not-in-baseline",
            "executable /usr/bin/dpkg was observed"),
        make_finding(
            "2026-07-16 01:20:06 EDT", MonitoringDomain::script,
            FindingPriority::notice, "script.not-in-baseline",
            "script /var/lib/dpkg/info/example.postinst was observed"),
        make_finding(
            "2026-07-16 01:20:08 EDT", MonitoringDomain::script,
            FindingPriority::notice, "script.not-in-baseline",
            "script /usr/sbin/update-initramfs was observed"),
        make_finding(
            "2026-07-16 01:20:09 EDT", MonitoringDomain::script,
            FindingPriority::notice, "script.not-in-baseline",
            "script /var/lib/dpkg/info/linux-image-7.0.0.postinst was observed"),
        make_finding(
            "2026-07-16 01:20:10 EDT", MonitoringDomain::kernel,
            FindingPriority::notice, "kernel.module-loaded",
            "New signed in-tree module cpuid was loaded"),
        make_finding(
            "2026-07-16 01:20:11 EDT", MonitoringDomain::script,
            FindingPriority::notice, "script.not-in-baseline",
            "script /usr/sbin/grub-mkconfig was observed"),
        make_finding(
            "2026-07-16 01:20:12 EDT", MonitoringDomain::bpf,
            FindingPriority::notice, "kernel.bpf-program-lifecycle",
            "New expected systemd cgroup BPF program was observed")
    };
    std::vector<Finding> maintenance_with_unrelated = maintenance;
    maintenance_with_unrelated.push_back(make_finding(
        "2026-07-16 01:30:00 EDT", MonitoringDomain::executable,
        FindingPriority::notice, "process.not-in-baseline",
        "executable /usr/bin/pluma was observed"));

    const std::vector<Finding> incomplete_chain{
        make_finding(
            "2026-07-16 01:40:00 EDT", MonitoringDomain::network,
            FindingPriority::notice, "network.not-in-baseline",
            "APT socket held by /usr/lib/apt/methods/http"),
        make_finding(
            "2026-07-16 01:40:02 EDT", MonitoringDomain::executable,
            FindingPriority::notice, "process.not-in-baseline",
            "executable /usr/bin/dpkg was observed"),
        make_finding(
            "2026-07-16 01:40:04 EDT", MonitoringDomain::executable,
            FindingPriority::notice, "process.not-in-baseline",
            "executable /opt/unrelated/tool was observed")
    };

    return {
        {"clean", render({}, {})},
        {"probably_normal_network", render({network}, {})},
        {"high_security_finding", render({high}, {})},
        {"partially_verified", render({}, {partial})},
        {"inconclusive", render({}, {critical})},
        {"persistence_added", render({persistence}, {})},
        {"persistence_unavailable", render({}, {persistence_unknown})},
        {"authentication_failed", render({authentication}, {})},
        {"authentication_unavailable", render({}, {authentication_unknown})},
        {"maintenance_chain", render(maintenance, {})},
        {"unrelated_findings_separate",
         render(maintenance_with_unrelated, {}) + "\n--- incomplete ---\n" +
         render(incomplete_chain, {})}
    };
}

std::string digest(const std::string& value) {
    char path[] = "/tmp/nightwatch-golden-report-XXXXXX";
    const int descriptor = mkstemp(path);
    if (descriptor < 0) {
        throw std::runtime_error("mkstemp failed");
    }
    unlink(path);
    std::size_t written = 0;
    while (written < value.size()) {
        const ssize_t count = write(
            descriptor, value.data() + written, value.size() - written);
        if (count <= 0) {
            close(descriptor);
            throw std::runtime_error("temporary fixture write failed");
        }
        written += static_cast<std::size_t>(count);
    }
    if (lseek(descriptor, 0, SEEK_SET) < 0) {
        close(descriptor);
        throw std::runtime_error("temporary fixture seek failed");
    }
    const std::string result = sha256_fd(descriptor);
    close(descriptor);
    return result;
}

std::map<std::string, std::string> read_manifest(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("cannot read " + path);
    }
    std::map<std::string, std::string> result;
    std::string name;
    std::string expected;
    while (input >> name >> expected) {
        result[name] = expected;
    }
    return result;
}
}

int main(int argc, char** argv) {
    try {
        const auto actual = scenarios();
        if (argc == 2 && std::string(argv[1]) == "--print-digests") {
            for (const auto& [name, contents] : actual) {
                std::cout << name << ' ' << digest(contents) << '\n';
            }
            return 0;
        }

        const auto expected = read_manifest(
            "tests/golden/assurance-reports.sha256");
        bool failed = false;
        for (const auto& [name, contents] : actual) {
            const auto fixture = expected.find(name);
            const std::string current = digest(contents);
            if (fixture == expected.end()) {
                std::cerr << "missing golden fixture: " << name << '\n';
                failed = true;
            } else if (fixture->second != current) {
                std::cerr << "golden report changed: " << name << "\n"
                          << "expected " << fixture->second << "\n"
                          << "actual   " << current << "\n\n"
                          << contents << '\n';
                failed = true;
            }
        }
        for (const auto& [name, expected_digest] : expected) {
            (void)expected_digest;
            if (actual.find(name) == actual.end()) {
                std::cerr << "orphaned golden fixture: " << name << '\n';
                failed = true;
            }
        }
        if (failed) {
            return 1;
        }
        std::cout << "golden assurance report tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
