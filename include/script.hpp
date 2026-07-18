#pragma once

#include <optional>
#include <string>
#include <vector>

std::vector<std::string> split_process_arguments(const std::string& contents);
std::optional<std::string> find_script_entrypoint(
    const std::string& executable,
    const std::vector<std::string>& arguments,
    const std::string& working_directory);
