#include "paths.hpp"

#include <array>
#include <cassert>
#include <iostream>
#include <string_view>

int main() {
    const std::array<std::string_view, 6> paths{
        nightwatch_paths::executable,
        nightwatch_paths::configuration_directory,
        nightwatch_paths::reviewed_fingerprints,
        nightwatch_paths::state_directory,
        nightwatch_paths::baseline,
        nightwatch_paths::report_directory
    };
    for (const std::string_view path : paths) {
        assert(!path.empty());
        assert(path.front() == '/');
        assert(path.find("/home/") == std::string_view::npos);
        assert(path.find("..") == std::string_view::npos);
    }
    assert(nightwatch_paths::baseline.substr(
               0, nightwatch_paths::state_directory.size()) ==
           nightwatch_paths::state_directory);
    assert(nightwatch_paths::reviewed_fingerprints.substr(
               0, nightwatch_paths::configuration_directory.size()) ==
           nightwatch_paths::configuration_directory);
    assert(nightwatch_paths::report_directory !=
           nightwatch_paths::state_directory);

    std::cout << "Installed path layout tests passed\n";
    return 0;
}
