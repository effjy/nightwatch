#include "persistence.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--live") {
        const PersistenceSnapshot live = collect_persistence(
            default_persistence_roots());
        std::cout << "records=" << live.records.size()
                  << " errors=" << live.errors.size()
                  << " truncated=" << (live.truncated ? "yes" : "no")
                  << '\n';
        for (const std::string& error : live.errors) {
            std::cout << "error: " << error << '\n';
        }
        return live.errors.empty() && !live.truncated ? 0 : 1;
    }
    char directory_template[] = "/tmp/nightwatch-persistence-test-XXXXXX";
    const char* created = mkdtemp(directory_template);
    assert(created != nullptr);
    const fs::path directory(created);
    const fs::path unit = directory / "example.service";
    const fs::path timer = directory / "example.timer";
    {
        std::ofstream output(unit);
        output << "[Service]\nExecStart=/usr/bin/true\n";
    }
    chmod(unit.c_str(), 0644);
    assert(symlink("example.service", timer.c_str()) == 0);

    const std::vector<PersistenceRoot> roots{
        {directory.string(), PersistenceKind::systemd, true}
    };
    const PersistenceSnapshot baseline = collect_persistence(roots);
    assert(baseline.errors.empty());
    assert(!baseline.truncated);
    assert(baseline.records.size() == 2);
    assert(!baseline.records.at(unit.string()).symlink);
    assert(baseline.records.at(timer.string()).symlink);
    assert(baseline.records.at(timer.string()).symlink_target ==
           "example.service");

    {
        std::ofstream output(unit);
        output << "[Service]\nExecStart=/usr/bin/false\n";
    }
    const fs::path added = directory / "added.conf";
    {
        std::ofstream output(added);
        output << "enabled=true\n";
    }
    assert(unlink(timer.c_str()) == 0);
    const PersistenceSnapshot current = collect_persistence(roots);
    const PersistenceDiff diff = compare_persistence(
        baseline.records, current.records);
    assert(diff.added.size() == 1 && diff.added.front().path == added.string());
    assert(diff.changed.size() == 1 && diff.changed.front().path == unit.string());
    assert(diff.removed.size() == 1 && diff.removed.front().path == timer.string());

    const PersistenceSnapshot limited = collect_persistence(roots, 1);
    assert(limited.truncated);
    assert(limited.records.size() == 1);

    fs::remove_all(directory);
    std::cout << "Persistence inventory and comparison tests passed\n";
    return 0;
}
