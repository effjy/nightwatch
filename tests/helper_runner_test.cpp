#include "helper_runner.hpp"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
bool expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
    }
    return condition;
}

HelperRequest shell_request(const std::string& command) {
    HelperRequest request;
    request.executable = "/bin/sh";
    request.arguments = {"-c", command};
    request.timeout = std::chrono::seconds(2);
    request.maximum_output_bytes = 4096;
    request.required_owner = std::nullopt;
    return request;
}
}

int main() {
    bool passed = true;
    setenv("NIGHTWATCH_SHOULD_NOT_LEAK", "secret", 1);

    HelperRequest success = shell_request(
        "printf '%s:%s:%s' \"$LC_ALL\" "
        "\"${NIGHTWATCH_SHOULD_NOT_LEAK-unset}\" \"$NIGHTWATCH_ALLOWED\"; "
        "printf 'diagnostic' >&2");
    success.environment["NIGHTWATCH_ALLOWED"] = "yes";
    const HelperResult successful = run_helper(success);
    if (!successful.succeeded()) {
        std::cerr << "success fixture: " << helper_result_summary(successful)
                  << '\n';
    }
    passed &= expect(successful.succeeded(), "successful helper should succeed");
    passed &= expect(successful.standard_output == "C:unset:yes",
                     "helper should receive a controlled environment");
    passed &= expect(successful.standard_error == "diagnostic",
                     "stderr should be captured separately");
    passed &= expect(successful.resolved_executable == "/usr/bin/dash",
                     "validated symlink target should be reported");

    const int source_descriptor = open("/dev/null", O_RDONLY);
    const int inherited_descriptor = source_descriptor < 0
        ? -1 : fcntl(source_descriptor, F_DUPFD, 200);
    if (source_descriptor >= 0) close(source_descriptor);
    if (inherited_descriptor < 0) {
        std::cerr << "FAIL: could not create descriptor-inheritance fixture\n";
        passed = false;
    } else {
        const HelperResult descriptor_check = run_helper(shell_request(
            "if [ -e /proc/self/fd/" + std::to_string(inherited_descriptor) +
            " ]; then exit 9; fi"));
        passed &= expect(descriptor_check.succeeded(),
                         "helper should not inherit unrelated descriptors");
        close(inherited_descriptor);
    }

    const HelperResult nonzero = run_helper(shell_request("exit 7"));
    passed &= expect(nonzero.status == HelperStatus::exited_nonzero &&
                         nonzero.exit_code == 7,
                     "nonzero exit status should be typed");

    const HelperResult signaled = run_helper(shell_request("kill -TERM $$"));
    passed &= expect(signaled.status == HelperStatus::terminated_by_signal &&
                         signaled.signal_number == SIGTERM,
                     "terminating signal should be typed");

    HelperRequest timeout = shell_request("sleep 5 & wait");
    timeout.timeout = std::chrono::milliseconds(80);
    const HelperResult timed_out = run_helper(timeout);
    passed &= expect(timed_out.status == HelperStatus::timed_out,
                     "helper deadline should be enforced");
    passed &= expect(timed_out.elapsed < std::chrono::seconds(1),
                     "timed-out process group should be terminated promptly");

    HelperRequest output_limit = shell_request(
        "while :; do printf '0123456789abcdef'; done");
    output_limit.maximum_output_bytes = 128;
    const HelperResult limited = run_helper(output_limit);
    passed &= expect(limited.status == HelperStatus::output_limit_reached,
                     "combined helper output limit should be enforced");
    passed &= expect(limited.standard_output.size() <= 128,
                     "retained output should remain bounded");

    HelperRequest relative = shell_request("exit 0");
    relative.executable = "sh";
    const HelperResult invalid_path = run_helper(relative);
    passed &= expect(invalid_path.status == HelperStatus::validation_failed,
                     "relative helper path should be rejected");

    char unsafe_path[] = "/tmp/nightwatch-unsafe-helper-XXXXXX";
    const int unsafe = mkstemp(unsafe_path);
    if (unsafe < 0) {
        std::cerr << "FAIL: could not create unsafe-helper fixture\n";
        return 1;
    }
    const std::string script = "#!/bin/sh\nexit 0\n";
    if (write(unsafe, script.data(), script.size()) !=
        static_cast<ssize_t>(script.size())) {
        std::cerr << "FAIL: could not write unsafe-helper fixture\n";
        close(unsafe);
        unlink(unsafe_path);
        return 1;
    }
    close(unsafe);
    HelperRequest unsafe_request;
    unsafe_request.executable = unsafe_path;
    unsafe_request.required_owner = geteuid();
    chmod(unsafe_path, 0700);
    passed &= expect(run_helper(unsafe_request).succeeded(),
                     "safely owned test helper should be accepted");
    chmod(unsafe_path, 0777);
    const HelperResult unsafe_result = run_helper(unsafe_request);
    passed &= expect(unsafe_result.status == HelperStatus::validation_failed,
                     "group/world-writable helper should be rejected");
    unlink(unsafe_path);

    HelperRequest invalid_limit = shell_request("exit 0");
    invalid_limit.maximum_output_bytes = 0;
    passed &= expect(run_helper(invalid_limit).status ==
                         HelperStatus::validation_failed,
                     "zero output budget should be rejected");

    HelperRequest invalid_environment = shell_request("exit 0");
    invalid_environment.environment["INVALID=NAME"] = "value";
    passed &= expect(run_helper(invalid_environment).status ==
                         HelperStatus::validation_failed,
                     "invalid environment names should be rejected");

    if (!passed) {
        return 1;
    }
    std::cout << "Helper runner boundary tests passed\n";
    return 0;
}
