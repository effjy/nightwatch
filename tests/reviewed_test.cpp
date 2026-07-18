#include "reviewed.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr const char* path = "/usr/bin/example";
constexpr const char* hash_a =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
constexpr const char* hash_b =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

ExecutableFingerprint fingerprint(const std::string& hash,
                                  std::uint64_t size = 4096) {
    ExecutableFingerprint result;
    result.device = 1;
    result.inode = 2;
    result.size = size;
    result.modified_nanoseconds = 3;
    result.mode = 0100755;
    result.uid = 0;
    result.gid = 0;
    result.sha256 = hash;
    result.valid = true;
    return result;
}

bool expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
    }
    return condition;
}
}  // namespace

int main() {
    std::map<std::string, ReviewedExecutable> reviewed;
    reviewed.emplace(path, ReviewedExecutable{fingerprint(hash_a), "test package"});

    bool passed = true;
    passed &= expect(reviewed_status(reviewed, path, fingerprint(hash_a)) ==
                         ReviewedStatus::matched,
                     "an exact reviewed fingerprint should match");

    ExecutableFingerprint remounted = fingerprint(hash_a);
    remounted.device = 99;
    remounted.inode = 100;
    remounted.modified_nanoseconds = 101;
    passed &= expect(reviewed_status(reviewed, path, remounted) ==
                         ReviewedStatus::matched,
                     "mount identity changes should not invalidate identical bytes");

    passed &= expect(reviewed_status(reviewed, path, fingerprint(hash_b)) ==
                         ReviewedStatus::changed,
                     "a same-size changed binary should be rejected by SHA-256");
    passed &= expect(reviewed_status(reviewed, path, fingerprint(hash_b, 8192)) ==
                         ReviewedStatus::changed,
                     "a package update should require fingerprint review");

    const ExecutableFingerprint expected = fingerprint(hash_a);
    ExecutableFingerprint updated_metadata = fingerprint(hash_b, 8192);
    updated_metadata.inode = 50;
    passed &= expect(executable_rehash_required(expected, updated_metadata, nullptr,
                                                false, false),
                     "a newly observed baseline mismatch should be hashed");
    passed &= expect(!executable_rehash_required(expected, updated_metadata,
                                                 &updated_metadata, false, false),
                     "a cached unchanged mismatch should not be rehashed every scan");
    ExecutableFingerprint replaced_again = updated_metadata;
    replaced_again.inode = 51;
    passed &= expect(executable_rehash_required(expected, replaced_again,
                                                &updated_metadata, false, false),
                     "a second runtime replacement should be rehashed immediately");
    passed &= expect(executable_rehash_required(expected, updated_metadata,
                                                &updated_metadata, true, false),
                     "a cached mismatch should be periodically rechecked");
    passed &= expect(reviewed_status(reviewed, "/usr/bin/not-reviewed",
                                     fingerprint(hash_a)) ==
                         ReviewedStatus::not_reviewed,
                     "an unknown path should remain unreviewed");

    std::set<std::string> matched;
    std::set<std::string> changed;
    std::set<std::string> unverified{path};
    const ReviewedStateUpdate recovered = note_reviewed_verification(
        path, ReviewedStatus::matched, matched, changed, unverified);
    passed &= expect(recovered.first_match && matched.count(path) == 1 &&
                         unverified.count(path) == 0,
                     "a later successful match should clear transient unverified state");
    const ReviewedStateUpdate repeated = note_reviewed_verification(
        path, ReviewedStatus::matched, matched, changed, unverified);
    passed &= expect(!repeated.first_match,
                     "a repeated successful match should not create a new event");
    unverified.insert(path);
    const ReviewedStateUpdate verified_change = note_reviewed_verification(
        path, ReviewedStatus::changed, matched, changed, unverified);
    passed &= expect(verified_change.first_change && changed.count(path) == 1 &&
                         unverified.count(path) == 0,
                     "a verified change should also clear transient unverified state");

    char temporary[] = "/tmp/nightwatch-reviewed-test-XXXXXX";
    const int descriptor = mkstemp(temporary);
    if (descriptor < 0) {
        std::cerr << "FAIL: mkstemp failed\n";
        return 1;
    }
    close(descriptor);
    {
        std::ofstream output(temporary);
        output << "nightwatch-reviewed-v1\n"
               << "reviewed \"" << path << "\" 4096 " << 0100755
               << " 0 0 \"" << hash_a << "\" \"test package\"\n";
    }
    chmod(temporary, 0600);
    try {
        const ReviewedExecutableFile loaded = load_reviewed_executables(temporary);
        passed &= expect(loaded.loaded && loaded.entries.size() == 1,
                         "a valid protected review file should load");
        passed &= expect(loaded.entries.at(path).reason == "test package",
                         "the review reason should be preserved");
    } catch (const std::exception& error) {
        std::cerr << "FAIL: parser rejected a valid file: " << error.what() << '\n';
        passed = false;
    }
    unlink(temporary);

    try {
        const ReviewedExecutableFile public_template =
            load_reviewed_executables("packaging/reviewed-executables.db");
        passed &= expect(public_template.loaded &&
                             public_template.entries.empty() &&
                             public_template.scripts.empty(),
                         "the public review template should load without "
                         "granting trust");
    } catch (const std::exception& error) {
        std::cerr << "FAIL: public review template is invalid: "
                  << error.what() << '\n';
        passed = false;
    }

    char version_two[] = "/tmp/nightwatch-reviewed-v2-test-XXXXXX";
    const int version_two_descriptor = mkstemp(version_two);
    if (version_two_descriptor < 0) {
        std::cerr << "FAIL: v2 mkstemp failed\n";
        return 1;
    }
    close(version_two_descriptor);
    {
        std::ofstream output(version_two);
        output << "nightwatch-reviewed-v2\n"
               << "executable \"" << path << "\" 4096 " << 0100755
               << " 0 0 \"" << hash_a << "\" \"test executable\"\n"
               << "script \"/usr/lib/example.py\" 2048 " << 0100755
               << " 0 0 \"" << hash_b << "\" \"test script\"\n";
    }
    chmod(version_two, 0600);
    try {
        const ReviewedExecutableFile loaded = load_reviewed_executables(version_two);
        passed &= expect(loaded.loaded && loaded.entries.size() == 1 &&
                             loaded.scripts.size() == 1,
                         "version two should separate executable and script records");
        passed &= expect(reviewed_status(
                             loaded.scripts, "/usr/lib/example.py",
                             fingerprint(hash_b, 2048)) == ReviewedStatus::matched,
                         "an exact reviewed script fingerprint should match");
        passed &= expect(reviewed_status(
                             loaded.scripts, "/usr/lib/example.py",
                             fingerprint(hash_a, 2048)) == ReviewedStatus::changed,
                         "a same-size reviewed script change should be rejected");
    } catch (const std::exception& error) {
        std::cerr << "FAIL: parser rejected a valid v2 file: "
                  << error.what() << '\n';
        passed = false;
    }
    unlink(version_two);

    if (!passed) {
        return 1;
    }
    std::cout << "Reviewed executable and script tests passed\n";
    return 0;
}
