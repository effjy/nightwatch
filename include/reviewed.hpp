#pragma once

#include "fingerprint.hpp"

#include <map>
#include <set>
#include <string>

struct ReviewedExecutable {
    ExecutableFingerprint fingerprint;
    std::string reason;
};

struct ReviewedExecutableFile {
    bool loaded{false};
    std::map<std::string, ReviewedExecutable> entries;
    std::map<std::string, ReviewedExecutable> scripts;
};

enum class ReviewedStatus {
    not_reviewed,
    matched,
    changed,
};

struct ReviewedStateUpdate {
    bool first_match{false};
    bool first_change{false};
};

ReviewedExecutableFile load_reviewed_executables(const std::string& path);
ReviewedStatus reviewed_status(
    const std::map<std::string, ReviewedExecutable>& reviewed,
    const std::string& path,
    const ExecutableFingerprint& current);
ReviewedStateUpdate note_reviewed_verification(
    const std::string& path, ReviewedStatus status,
    std::set<std::string>& matched, std::set<std::string>& changed,
    std::set<std::string>& unverified);
