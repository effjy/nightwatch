#include "fingerprint.hpp"
#include "sha256.hpp"

#include <exception>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

ExecutableFingerprint fingerprint_file(const std::string& path,
                                       bool include_hash,
                                       bool no_follow) {
    ExecutableFingerprint result;
    const int flags = O_RDONLY | O_CLOEXEC | (no_follow ? O_NOFOLLOW : 0);
    const int descriptor = open(path.c_str(), flags);
    if (descriptor < 0) {
        return result;
    }

    struct stat details {};
    if (fstat(descriptor, &details) != 0 || !S_ISREG(details.st_mode)) {
        close(descriptor);
        return result;
    }
    result.device = static_cast<std::uint64_t>(details.st_dev);
    result.inode = static_cast<std::uint64_t>(details.st_ino);
    result.size = static_cast<std::uint64_t>(details.st_size);
    result.modified_nanoseconds =
        static_cast<std::int64_t>(details.st_mtim.tv_sec) * 1000000000LL +
        static_cast<std::int64_t>(details.st_mtim.tv_nsec);
    result.mode = static_cast<unsigned int>(details.st_mode);
    result.uid = static_cast<unsigned int>(details.st_uid);
    result.gid = static_cast<unsigned int>(details.st_gid);
    try {
        if (include_hash) {
            result.sha256 = sha256_fd(descriptor);
        }
        result.valid = true;
    } catch (const std::exception&) {
        result = ExecutableFingerprint{};
    }
    close(descriptor);
    return result;
}
