#include "reviewed.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace {
bool valid_sha256(const std::string& value) {
    return value.size() == 64 &&
        std::all_of(value.begin(), value.end(), [](unsigned char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f');
        });
}

std::string read_secure_file(int descriptor, off_t size,
                             const std::string& path) {
    std::string contents(static_cast<std::size_t>(size), '\0');
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const ssize_t count = read(descriptor, contents.data() + offset,
                                   contents.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw std::runtime_error("cannot read reviewed-fingerprint file " +
                                     path + ": " + std::strerror(errno));
        }
        offset += static_cast<std::size_t>(count);
    }
    return contents;
}
}  // namespace

bool same_executable_metadata(const ExecutableFingerprint& left,
                              const ExecutableFingerprint& right) {
    return left.valid && right.valid && left.device == right.device &&
           left.inode == right.inode && left.size == right.size &&
           left.modified_nanoseconds == right.modified_nanoseconds &&
           left.mode == right.mode && left.uid == right.uid && left.gid == right.gid;
}

bool same_security_fingerprint(const ExecutableFingerprint& left,
                               const ExecutableFingerprint& right) {
    // Mount identity and timestamps trigger rehashing, but do not establish a
    // security change when the bytes and security-relevant metadata still match.
    return left.valid && right.valid && !left.sha256.empty() &&
           left.sha256 == right.sha256 && left.size == right.size &&
           left.mode == right.mode && left.uid == right.uid && left.gid == right.gid;
}

bool executable_rehash_required(const ExecutableFingerprint& expected,
                                const ExecutableFingerprint& metadata,
                                const ExecutableFingerprint* cached,
                                bool periodic_recheck,
                                bool background_check_allowed) {
    const bool changed_from_baseline = expected.valid &&
        !same_executable_metadata(expected, metadata);
    const bool changed_during_run = cached != nullptr &&
        !same_executable_metadata(*cached, metadata);
    if (changed_during_run) {
        return true;
    }
    if (changed_from_baseline && (cached == nullptr || periodic_recheck)) {
        return true;
    }
    return background_check_allowed && (cached == nullptr || periodic_recheck);
}

ReviewedExecutableFile load_reviewed_executables(const std::string& path) {
    ReviewedExecutableFile result;
    const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 && errno == ENOENT) {
        return result;
    }
    if (descriptor < 0) {
        throw std::runtime_error("cannot open reviewed-fingerprint file " + path +
                                 ": " + std::strerror(errno));
    }

    struct stat details {};
    if (fstat(descriptor, &details) != 0 || !S_ISREG(details.st_mode)) {
        close(descriptor);
        throw std::runtime_error("reviewed-fingerprint file is not a regular file: " +
                                 path);
    }
    if ((details.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(descriptor);
        throw std::runtime_error(
            "reviewed-fingerprint file must not be writable by group or others");
    }
    if (geteuid() == 0 && details.st_uid != 0) {
        close(descriptor);
        throw std::runtime_error(
            "root will not trust a reviewed-fingerprint file not owned by root");
    }
    constexpr off_t maximum_size = 1024 * 1024;
    if (details.st_size < 0 || details.st_size > maximum_size) {
        close(descriptor);
        throw std::runtime_error("reviewed-fingerprint file is unreasonably large");
    }

    std::string contents;
    try {
        contents = read_secure_file(descriptor, details.st_size, path);
    } catch (...) {
        close(descriptor);
        throw;
    }
    close(descriptor);

    std::istringstream input(contents);
    std::string header;
    if (!std::getline(input, header) ||
        (header != "nightwatch-reviewed-v1" &&
         header != "nightwatch-reviewed-v2")) {
        throw std::runtime_error("unsupported reviewed-fingerprint file format");
    }
    const bool version_two = header == "nightwatch-reviewed-v2";
    std::string line;
    unsigned int line_number = 1;
    while (std::getline(input, line)) {
        ++line_number;
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::istringstream fields(line);
        std::string type;
        std::string executable;
        ReviewedExecutable entry;
        fields >> type >> std::quoted(executable) >> entry.fingerprint.size >>
            entry.fingerprint.mode >> entry.fingerprint.uid >> entry.fingerprint.gid >>
            std::quoted(entry.fingerprint.sha256) >> std::quoted(entry.reason);
        std::string extra;
        const bool executable_entry =
            (!version_two && type == "reviewed") ||
            (version_two && type == "executable");
        const bool script_entry = version_two && type == "script";
        if (!fields || fields >> extra ||
            (!executable_entry && !script_entry) || executable.empty() ||
            executable[0] != '/' || entry.reason.empty() ||
            !valid_sha256(entry.fingerprint.sha256)) {
            throw std::runtime_error("invalid reviewed entry at line " +
                                     std::to_string(line_number));
        }
        entry.fingerprint.valid = true;
        auto& destination = script_entry ? result.scripts : result.entries;
        if (!destination.emplace(executable, std::move(entry)).second) {
            throw std::runtime_error("duplicate reviewed entry at line " +
                                     std::to_string(line_number));
        }
    }
    result.loaded = true;
    return result;
}

ReviewedStatus reviewed_status(
    const std::map<std::string, ReviewedExecutable>& reviewed,
    const std::string& path,
    const ExecutableFingerprint& current) {
    const auto expected = reviewed.find(path);
    if (expected == reviewed.end()) {
        return ReviewedStatus::not_reviewed;
    }
    return same_security_fingerprint(expected->second.fingerprint, current)
        ? ReviewedStatus::matched
        : ReviewedStatus::changed;
}

ReviewedStateUpdate note_reviewed_verification(
    const std::string& path, ReviewedStatus status,
    std::set<std::string>& matched, std::set<std::string>& changed,
    std::set<std::string>& unverified) {
    ReviewedStateUpdate result;
    if (status == ReviewedStatus::matched) {
        unverified.erase(path);
        result.first_match = matched.insert(path).second;
    } else if (status == ReviewedStatus::changed) {
        unverified.erase(path);
        result.first_change = changed.insert(path).second;
    }
    return result;
}
