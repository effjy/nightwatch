#include "persistence.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <pwd.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {
void add_error(PersistenceSnapshot& snapshot, const std::string& detail) {
    if (snapshot.errors.size() < 128U) {
        snapshot.errors.push_back(detail);
    }
}

void collect_path(const fs::path& path, PersistenceKind kind,
                  std::size_t maximum_records,
                  std::size_t maximum_file_bytes,
                  PersistenceSnapshot& snapshot) {
    if (snapshot.records.size() >= maximum_records) {
        snapshot.truncated = true;
        return;
    }
    struct stat details {};
    if (lstat(path.c_str(), &details) != 0) {
        add_error(snapshot, path.string() + ": " + std::strerror(errno));
        return;
    }

    PersistenceRecord record;
    record.path = path.lexically_normal().string();
    record.kind = kind;
    if (S_ISLNK(details.st_mode)) {
        record.symlink = true;
        std::string target(4096, '\0');
        const ssize_t length = readlink(path.c_str(), target.data(), target.size());
        if (length < 0 || static_cast<std::size_t>(length) == target.size()) {
            add_error(snapshot, record.path + ": cannot read symlink target");
            return;
        }
        target.resize(static_cast<std::size_t>(length));
        record.symlink_target = std::move(target);
        record.fingerprint.valid = true;
        record.fingerprint.size = static_cast<std::uint64_t>(details.st_size);
        record.fingerprint.mode = static_cast<unsigned int>(details.st_mode);
        record.fingerprint.uid = static_cast<unsigned int>(details.st_uid);
        record.fingerprint.gid = static_cast<unsigned int>(details.st_gid);
    } else if (S_ISREG(details.st_mode)) {
        if (details.st_size < 0 ||
            static_cast<std::uint64_t>(details.st_size) > maximum_file_bytes) {
            add_error(snapshot, record.path + ": file exceeds persistence limit");
            return;
        }
        record.fingerprint = fingerprint_file(record.path, true, true);
        if (!record.fingerprint.valid) {
            add_error(snapshot, record.path + ": fingerprint unavailable");
            return;
        }
    } else {
        return;
    }
    snapshot.records.emplace(record.path, std::move(record));
}

void add_root(std::vector<PersistenceRoot>& roots, std::set<std::string>& seen,
              const fs::path& path, PersistenceKind kind, bool recursive = true) {
    const std::string normalized = path.lexically_normal().string();
    if (seen.insert(normalized).second) {
        roots.push_back({normalized, kind, recursive});
    }
}
}  // namespace

std::string persistence_kind_name(PersistenceKind kind) {
    switch (kind) {
    case PersistenceKind::systemd: return "systemd";
    case PersistenceKind::cron: return "cron";
    case PersistenceKind::autostart: return "autostart";
    case PersistenceKind::legacy: return "legacy";
    }
    return "legacy";
}

bool parse_persistence_kind(const std::string& value, PersistenceKind& kind) {
    if (value == "systemd") kind = PersistenceKind::systemd;
    else if (value == "cron") kind = PersistenceKind::cron;
    else if (value == "autostart") kind = PersistenceKind::autostart;
    else if (value == "legacy") kind = PersistenceKind::legacy;
    else return false;
    return true;
}

std::vector<PersistenceRoot> default_persistence_roots() {
    std::vector<PersistenceRoot> roots;
    std::set<std::string> seen;
    add_root(roots, seen, "/etc/systemd/system", PersistenceKind::systemd);
    add_root(roots, seen, "/usr/lib/systemd/system", PersistenceKind::systemd);
    add_root(roots, seen, "/usr/lib/systemd/user", PersistenceKind::systemd);
    add_root(roots, seen, "/usr/local/lib/systemd/system", PersistenceKind::systemd);
    add_root(roots, seen, "/etc/crontab", PersistenceKind::cron, false);
    add_root(roots, seen, "/etc/cron.d", PersistenceKind::cron);
    add_root(roots, seen, "/etc/cron.hourly", PersistenceKind::cron);
    add_root(roots, seen, "/etc/cron.daily", PersistenceKind::cron);
    add_root(roots, seen, "/etc/cron.weekly", PersistenceKind::cron);
    add_root(roots, seen, "/etc/cron.monthly", PersistenceKind::cron);
    add_root(roots, seen, "/var/spool/cron/crontabs", PersistenceKind::cron);
    add_root(roots, seen, "/var/spool/cron/atjobs", PersistenceKind::cron);
    add_root(roots, seen, "/etc/xdg/autostart", PersistenceKind::autostart);
    add_root(roots, seen, "/etc/init.d", PersistenceKind::legacy);
    add_root(roots, seen, "/etc/rc.local", PersistenceKind::legacy, false);
    add_root(roots, seen, "/etc/profile", PersistenceKind::legacy, false);
    add_root(roots, seen, "/etc/bash.bashrc", PersistenceKind::legacy, false);
    add_root(roots, seen, "/etc/profile.d", PersistenceKind::legacy);
    add_root(roots, seen, "/etc/X11/Xsession.d", PersistenceKind::legacy);

    setpwent();
    while (const passwd* account = getpwent()) {
        if ((account->pw_uid == 0 || account->pw_uid >= 1000) &&
            account->pw_dir != nullptr && account->pw_dir[0] == '/') {
            const fs::path home(account->pw_dir);
            add_root(roots, seen, home / ".config/systemd/user",
                     PersistenceKind::systemd);
            add_root(roots, seen, home / ".config/autostart",
                     PersistenceKind::autostart);
            add_root(roots, seen, home / ".local/share/systemd/user",
                     PersistenceKind::systemd);
            add_root(roots, seen, home / ".profile",
                     PersistenceKind::legacy, false);
            add_root(roots, seen, home / ".bash_profile",
                     PersistenceKind::legacy, false);
            add_root(roots, seen, home / ".bash_login",
                     PersistenceKind::legacy, false);
            add_root(roots, seen, home / ".bashrc",
                     PersistenceKind::legacy, false);
            add_root(roots, seen, home / ".xprofile",
                     PersistenceKind::legacy, false);
            add_root(roots, seen, home / ".xsessionrc",
                     PersistenceKind::legacy, false);
        }
    }
    endpwent();
    return roots;
}

PersistenceSnapshot collect_persistence(
    const std::vector<PersistenceRoot>& roots, std::size_t maximum_records,
    std::size_t maximum_file_bytes) {
    PersistenceSnapshot snapshot;
    if (maximum_records == 0 || maximum_file_bytes == 0) {
        snapshot.truncated = true;
        return snapshot;
    }
    for (const PersistenceRoot& root : roots) {
        if (snapshot.truncated) break;
        std::error_code error;
        const fs::file_status status = fs::symlink_status(root.path, error);
        if (error) {
            if (error != std::errc::no_such_file_or_directory) {
                add_error(snapshot, root.path + ": " + error.message());
            }
            continue;
        }
        if (!fs::is_directory(status) || !root.recursive) {
            collect_path(root.path, root.kind, maximum_records,
                         maximum_file_bytes, snapshot);
            continue;
        }
        fs::recursive_directory_iterator iterator(
            root.path, fs::directory_options::none, error);
        const fs::recursive_directory_iterator end;
        if (error) {
            add_error(snapshot, root.path + ": " + error.message());
            continue;
        }
        while (iterator != end && !snapshot.truncated) {
            collect_path(iterator->path(), root.kind, maximum_records,
                         maximum_file_bytes, snapshot);
            iterator.increment(error);
            if (error) {
                add_error(snapshot, root.path + ": " + error.message());
                error.clear();
            }
        }
    }
    return snapshot;
}

bool same_persistence_record(const PersistenceRecord& left,
                             const PersistenceRecord& right) {
    if (left.kind != right.kind || left.symlink != right.symlink) return false;
    if (left.symlink) {
        return left.symlink_target == right.symlink_target &&
               left.fingerprint.mode == right.fingerprint.mode &&
               left.fingerprint.uid == right.fingerprint.uid &&
               left.fingerprint.gid == right.fingerprint.gid;
    }
    return same_security_fingerprint(left.fingerprint, right.fingerprint);
}

PersistenceDiff compare_persistence(
    const std::map<std::string, PersistenceRecord>& expected,
    const std::map<std::string, PersistenceRecord>& current) {
    PersistenceDiff diff;
    for (const auto& [path, record] : current) {
        const auto baseline = expected.find(path);
        if (baseline == expected.end()) diff.added.push_back(record);
        else if (!same_persistence_record(baseline->second, record)) {
            diff.changed.push_back(record);
        }
    }
    for (const auto& [path, record] : expected) {
        if (current.find(path) == current.end()) diff.removed.push_back(record);
    }
    return diff;
}
