#pragma once

#include "fingerprint.hpp"

#include <cstddef>
#include <map>
#include <string>
#include <vector>

enum class PersistenceKind {
    systemd,
    cron,
    autostart,
    legacy
};

struct PersistenceRoot {
    std::string path;
    PersistenceKind kind{PersistenceKind::legacy};
    bool recursive{true};
};

struct PersistenceRecord {
    std::string path;
    PersistenceKind kind{PersistenceKind::legacy};
    bool symlink{false};
    std::string symlink_target;
    ExecutableFingerprint fingerprint;
};

struct PersistenceSnapshot {
    std::map<std::string, PersistenceRecord> records;
    std::vector<std::string> errors;
    bool truncated{false};
};

struct PersistenceDiff {
    std::vector<PersistenceRecord> added;
    std::vector<PersistenceRecord> changed;
    std::vector<PersistenceRecord> removed;
};

std::string persistence_kind_name(PersistenceKind kind);
bool parse_persistence_kind(const std::string& value, PersistenceKind& kind);
std::vector<PersistenceRoot> default_persistence_roots();
PersistenceSnapshot collect_persistence(
    const std::vector<PersistenceRoot>& roots,
    std::size_t maximum_records = 10000,
    std::size_t maximum_file_bytes = 1024U * 1024U);
PersistenceDiff compare_persistence(
    const std::map<std::string, PersistenceRecord>& expected,
    const std::map<std::string, PersistenceRecord>& current);
bool same_persistence_record(const PersistenceRecord& left,
                             const PersistenceRecord& right);
