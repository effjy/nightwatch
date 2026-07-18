#pragma once

#include <string_view>

namespace nightwatch_paths {
inline constexpr std::string_view executable = "/usr/local/sbin/nightwatch";
inline constexpr std::string_view configuration_directory = "/etc/nightwatch";
inline constexpr std::string_view reviewed_fingerprints =
    "/etc/nightwatch/reviewed-executables.db";
inline constexpr std::string_view state_directory = "/var/lib/nightwatch";
inline constexpr std::string_view baseline = "/var/lib/nightwatch/baseline.db";
inline constexpr std::string_view report_directory = "/var/log/nightwatch";
}

