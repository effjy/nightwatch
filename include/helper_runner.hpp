#pragma once

#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>

enum class HelperStatus {
    succeeded,
    validation_failed,
    launch_failed,
    timed_out,
    output_limit_reached,
    exited_nonzero,
    terminated_by_signal,
};

struct HelperIdentity {
    uid_t uid{0};
    gid_t gid{0};
    std::string user;
};

struct HelperRequest {
    std::string executable;
    std::vector<std::string> arguments;
    std::chrono::milliseconds timeout{5000};
    std::size_t maximum_output_bytes{16U * 1024U * 1024U};
    std::map<std::string, std::string> environment;
    std::optional<HelperIdentity> identity;
    std::optional<uid_t> required_owner{0};
};

struct HelperValidation {
    bool valid{false};
    std::string resolved_path;
    std::string error;
};

struct HelperResult {
    HelperStatus status{HelperStatus::launch_failed};
    std::string standard_output;
    std::string standard_error;
    std::string resolved_executable;
    std::string error;
    int exit_code{-1};
    int signal_number{0};
    std::chrono::milliseconds elapsed{0};

    bool succeeded() const { return status == HelperStatus::succeeded; }
};

HelperValidation validate_helper_executable(
    const std::string& path, std::optional<uid_t> required_owner = 0);
HelperResult run_helper(const HelperRequest& request);
std::string helper_status_name(HelperStatus status);
std::string helper_result_summary(const HelperResult& result);
