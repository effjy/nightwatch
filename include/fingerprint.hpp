#pragma once

#include <cstdint>
#include <string>

struct ExecutableFingerprint {
    std::uint64_t device{};
    std::uint64_t inode{};
    std::uint64_t size{};
    std::int64_t modified_nanoseconds{};
    unsigned int mode{};
    unsigned int uid{};
    unsigned int gid{};
    std::string sha256;
    bool valid{false};
};

ExecutableFingerprint fingerprint_file(const std::string& path,
                                       bool include_hash,
                                       bool no_follow = false);

bool same_executable_metadata(const ExecutableFingerprint& left,
                              const ExecutableFingerprint& right);
bool same_security_fingerprint(const ExecutableFingerprint& left,
                               const ExecutableFingerprint& right);
bool executable_rehash_required(const ExecutableFingerprint& expected,
                                const ExecutableFingerprint& metadata,
                                const ExecutableFingerprint* cached,
                                bool periodic_recheck,
                                bool background_check_allowed);
