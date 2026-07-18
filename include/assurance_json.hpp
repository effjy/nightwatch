#pragma once

#include "assurance.hpp"
#include "authentication.hpp"

#include <string>
#include <map>
#include <vector>

constexpr unsigned int NIGHTWATCH_JSON_SCHEMA_VERSION = 4;

std::string render_json_report(
    const SessionMetadata& metadata,
    const std::vector<Finding>& findings,
    const std::vector<Degradation>& degradations,
    const std::vector<DomainStatus>& domains,
    const AuthenticationStatus& authentication = {},
    const std::vector<AuthenticationEvent>& authentication_events = {},
    const std::map<std::string, LoginSession>& active_sessions = {});
