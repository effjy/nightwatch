#include "assurance_json.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    SessionMetadata metadata{
        "test-\"host", "Linux test\\kernel", "start", "stop",
        "config/baseline.db", "created", 60, 61, 0,
        1, 60, 2, 1500000, 1000000, 2000000,
        {{"process collection", 61, 61000, 2000}}, {}
    };
    metadata.retention = {
        {1, 10000, 0}, {1, 1024, 0}, {2, 50000, 3},
        {4, 10000, 5}, {6, 100000, 7}, {2, 4096, 1},
        8192, 67108864, 9
    };
    const RuleMetadata rule = rule_metadata(
        "network.not-in-baseline", FindingPriority::notice);
    const std::vector<Finding> findings{{
        "now", MonitoringDomain::network, FindingPriority::notice,
        rule.classification, "network.not-in-baseline", rule.title,
        "line one\nline two\tquoted \"value\"", rule.rationale,
        rule.recommended_action
    }};
    const std::vector<Degradation> degradations{{
        "later", MonitoringDomain::script, "reviewed-script.unverified",
        "short-lived script", 2, false
    }};
    const auto domains = summarize_domains(findings, degradations);
    AuthenticationStatus authentication;
    authentication.journal_available = true;
    authentication.session_state_available = true;
    const std::vector<AuthenticationEvent> authentication_events{{
        "auth-now", "cursor", AuthenticationEventType::authentication_failed,
        "c2", "user", "1000", "seat0", ":0", "", "mate-screensaver",
        "authentication failure"
    }};
    LoginSession active;
    active.id = "c2";
    active.uid = "1000";
    active.user = "user";
    active.seat = "seat0";
    active.state = "active";
    active.locked_known = true;
    const std::map<std::string, LoginSession> active_sessions{{"c2", active}};
    const std::string json = render_json_report(
        metadata, findings, degradations, domains, authentication,
        authentication_events, active_sessions);
    if (argc == 2 && std::string(argv[1]) == "--print") {
        std::cout << json;
        return 0;
    }

    assert(json.find("\"schema\": \"nightwatch.report\"") !=
           std::string::npos);
    assert(json.find("\"schema_version\": 4") != std::string::npos);
    assert(json.find("\"deadline_overruns\": 2") != std::string::npos);
    assert(json.find("\"maximum_scan_microseconds\": 2000000") !=
           std::string::npos);
    assert(json.find("\"phase\": \"process collection\"") !=
           std::string::npos);
    assert(json.find("\"media_sessions\": {\"retained\": 2, \"limit\": "
                     "50000, \"dropped\": 3}") != std::string::npos);
    assert(json.find("\"journal_entries_dropped\": 9") !=
           std::string::npos);
    assert(json.find("\"authentication_events\": {\"retained\": 2, "
                     "\"limit\": 4096, \"dropped\": 1}") !=
           std::string::npos);
    assert(json.find("\"conclusion\": \"partially_verified\"") !=
           std::string::npos);
    assert(json.find("\"id\": \"network\"") != std::string::npos);
    assert(json.find("\"state\": \"finding_detected\"") !=
           std::string::npos);
    assert(json.find("\"id\": \"script\"") != std::string::npos);
    assert(json.find("\"id\": \"persistence\"") != std::string::npos);
    assert(json.find("\"id\": \"authentication\"") != std::string::npos);
    assert(json.find("\"journal_available\": true") != std::string::npos);
    assert(json.find("\"type\": \"authentication failed\"") !=
           std::string::npos);
    assert(json.find("\"provider\": \"mate-screensaver\"") !=
           std::string::npos);
    assert(json.find("\"active_sessions\": [") != std::string::npos);
    assert(json.find("\"state\": \"unknown\"") != std::string::npos);
    assert(json.find("test-\\\"host") != std::string::npos);
    assert(json.find("Linux test\\\\kernel") != std::string::npos);
    assert(json.find("line one\\nline two\\tquoted \\\"value\\\"") !=
           std::string::npos);
    assert(json.find("\"session_critical\": false") != std::string::npos);
    assert(json.find("\"finding_count\": 1") != std::string::npos);
    assert(json.find("\"degradation_count\": 1") != std::string::npos);

    const std::string clean = render_json_report(
        metadata, {}, {}, summarize_domains({}, {}));
    assert(clean.find("\"conclusion\": \"fully_verified\"") !=
           std::string::npos);
    assert(clean.find("\"findings\": [\n  ]") != std::string::npos);
    assert(clean.find("\"degradations\": [\n  ]") != std::string::npos);

    std::cout << "JSON report schema and escaping tests passed\n";
    return 0;
}
