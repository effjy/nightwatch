#pragma once

#include <string>
#include <vector>

enum class PreflightStatus {
    pass,
    warning,
    failure,
};

struct PreflightCheck {
    PreflightStatus status{PreflightStatus::pass};
    std::string name;
    std::string detail;
};

struct PreflightOptions {
    std::string baseline_path;
    std::string reviewed_path;
    std::string report_directory;
};

int preflight_exit_code(const std::vector<PreflightCheck>& checks);
int run_preflight(const PreflightOptions& options);
