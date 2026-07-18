#include "fingerprint.hpp"
#include "script.hpp"

#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
bool expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
    }
    return condition;
}

bool write_contents(int descriptor, const std::string& contents) {
    if (ftruncate(descriptor, 0) != 0 || lseek(descriptor, 0, SEEK_SET) < 0) {
        return false;
    }
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const ssize_t count = write(descriptor, contents.data() + offset,
                                    contents.size() - offset);
        if (count <= 0) {
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    return fsync(descriptor) == 0;
}
}  // namespace

int main() {
    bool passed = true;

    const std::string raw(
        "python3\0-u\0/usr/local/libexec/helper\0argument\0",
        sizeof("python3\0-u\0/usr/local/libexec/helper\0argument\0") - 1);
    const std::vector<std::string> split = split_process_arguments(raw);
    passed &= expect(split.size() == 4 && split[2] == "/usr/local/libexec/helper",
                     "NUL-separated process arguments should retain boundaries");

    const auto python = find_script_entrypoint(
        "/usr/bin/python3.12",
        {"python3", "-u", "/usr/local/libexec/helper", "argument"}, "/tmp");
    passed &= expect(python && *python == "/usr/local/libexec/helper",
                     "Python should expose an extensionless script entrypoint");

    const auto relative = find_script_entrypoint(
        "/usr/bin/bash", {"bash", "scripts/check.sh"}, "/opt/application");
    passed &= expect(relative && *relative == "/opt/application/scripts/check.sh",
                     "relative scripts should resolve through the process cwd");

    passed &= expect(!find_script_entrypoint(
                         "/usr/bin/python3", {"python3", "-m", "http.server"}, "/tmp"),
                     "Python module mode must not be mistaken for a script");
    passed &= expect(!find_script_entrypoint(
                         "/usr/bin/bash", {"bash", "-c", "echo hello"}, "/tmp"),
                     "shell inline-code mode must not be mistaken for a script");
    passed &= expect(!find_script_entrypoint(
                         "/usr/bin/cat", {"cat", "/tmp/example.py"}, "/tmp"),
                     "non-interpreters must not produce script entrypoints");

    char temporary[] = "/tmp/nightwatch-script-test-XXXXXX";
    const int descriptor = mkstemp(temporary);
    if (descriptor < 0) {
        std::cerr << "FAIL: mkstemp failed\n";
        return 1;
    }
    chmod(temporary, 0700);
    if (!write_contents(descriptor, "#!/usr/bin/python3\nprint('first')\n")) {
        std::cerr << "FAIL: initial script write failed\n";
        close(descriptor);
        unlink(temporary);
        return 1;
    }
    const ExecutableFingerprint first = fingerprint_file(temporary, true);
    const ExecutableFingerprint unchanged = fingerprint_file(temporary, true);
    passed &= expect(first.valid && unchanged.valid &&
                     first.sha256 == unchanged.sha256 && first.size == unchanged.size,
                     "an unchanged script fingerprint should match");

    if (!write_contents(descriptor, "#!/usr/bin/python3\nprint('other')\n")) {
        std::cerr << "FAIL: changed script write failed\n";
        close(descriptor);
        unlink(temporary);
        return 1;
    }
    const ExecutableFingerprint changed = fingerprint_file(temporary, true);
    passed &= expect(changed.valid && first.sha256 != changed.sha256,
                     "a same-size script content change should alter SHA-256");
    close(descriptor);
    unlink(temporary);

    if (!passed) {
        return 1;
    }
    std::cout << "Script entrypoint and fingerprint tests passed\n";
    return 0;
}
