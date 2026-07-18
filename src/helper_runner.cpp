#include "helper_runner.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
bool valid_environment_name(const std::string& name) {
    if (name.empty() || name.find('=') != std::string::npos ||
        name.find('\0') != std::string::npos) {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](unsigned char value) {
        return (value >= 'A' && value <= 'Z') ||
               (value >= 'a' && value <= 'z') ||
               (value >= '0' && value <= '9') || value == '_';
    });
}

void close_descriptor(int& descriptor) {
    if (descriptor >= 0) {
        close(descriptor);
        descriptor = -1;
    }
}

bool set_nonblocking(int descriptor) {
    const int flags = fcntl(descriptor, F_GETFL, 0);
    return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool append_bounded(std::string& destination, const char* data,
                    std::size_t count, std::size_t& total,
                    std::size_t maximum) {
    if (count > maximum - total) {
        const std::size_t remaining = maximum - total;
        destination.append(data, remaining);
        total = maximum;
        return false;
    }
    destination.append(data, count);
    total += count;
    return true;
}

bool drain_descriptor(int& descriptor, std::string& destination,
                      std::size_t& total, std::size_t maximum) {
    std::array<char, 16384> buffer{};
    while (descriptor >= 0) {
        const ssize_t count = read(descriptor, buffer.data(), buffer.size());
        if (count > 0) {
            if (!append_bounded(destination, buffer.data(),
                                static_cast<std::size_t>(count), total,
                                maximum)) {
                return false;
            }
            continue;
        }
        if (count == 0) {
            close_descriptor(descriptor);
        } else if (errno == EINTR) {
            continue;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            close_descriptor(descriptor);
        }
        break;
    }
    return true;
}

void terminate_group(pid_t child) {
    if (child > 0) {
        kill(-child, SIGKILL);
        kill(child, SIGKILL);
    }
}

void close_inherited_descriptors(long maximum_descriptor) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, ~0U, 0U) == 0) {
        return;
    }
#endif
    const long limit = std::max(3L, maximum_descriptor);
    for (long descriptor = 3; descriptor < limit; ++descriptor) {
        close(static_cast<int>(descriptor));
    }
}
}

HelperValidation validate_helper_executable(
    const std::string& path, std::optional<uid_t> required_owner) {
    HelperValidation result;
    if (path.empty() || path.front() != '/' || path.find('\0') != std::string::npos) {
        result.error = "helper path must be an absolute NUL-free path";
        return result;
    }
    char resolved[PATH_MAX]{};
    if (realpath(path.c_str(), resolved) == nullptr) {
        result.error = "cannot resolve helper path: " +
                       std::string(std::strerror(errno));
        return result;
    }
    struct stat details {};
    if (stat(resolved, &details) != 0) {
        result.error = "cannot stat resolved helper: " +
                       std::string(std::strerror(errno));
        return result;
    }
    if (!S_ISREG(details.st_mode)) {
        result.error = "resolved helper is not a regular file";
        return result;
    }
    if (required_owner && details.st_uid != *required_owner) {
        result.error = "resolved helper has an unexpected owner";
        return result;
    }
    if ((details.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        result.error = "resolved helper is writable by group or others";
        return result;
    }
    if ((details.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        result.error = "resolved helper is not executable";
        return result;
    }
    result.valid = true;
    result.resolved_path = resolved;
    return result;
}

HelperResult run_helper(const HelperRequest& request) {
    HelperResult result;
    const auto started = std::chrono::steady_clock::now();
    const HelperValidation validation = validate_helper_executable(
        request.executable, request.required_owner);
    result.resolved_executable = validation.resolved_path;
    if (!validation.valid) {
        result.status = HelperStatus::validation_failed;
        result.error = validation.error;
        return result;
    }
    if (request.timeout.count() <= 0 || request.maximum_output_bytes == 0) {
        result.status = HelperStatus::validation_failed;
        result.error = "helper timeout and output limit must be positive";
        return result;
    }
    if (request.identity && geteuid() != 0 &&
        (request.identity->uid != geteuid() || request.identity->gid != getegid())) {
        result.status = HelperStatus::validation_failed;
        result.error = "insufficient privilege for requested helper identity";
        return result;
    }
    if (request.identity && request.identity->user.empty()) {
        result.status = HelperStatus::validation_failed;
        result.error = "helper identity requires a user name";
        return result;
    }
    if (request.executable.find('\0') != std::string::npos ||
        std::any_of(request.arguments.begin(), request.arguments.end(),
                    [](const std::string& value) {
                        return value.find('\0') != std::string::npos;
                    })) {
        result.status = HelperStatus::validation_failed;
        result.error = "helper arguments must not contain NUL bytes";
        return result;
    }
    std::map<std::string, std::string> environment{
        {"HOME", "/"},
        {"LANG", "C"},
        {"LC_ALL", "C"},
        {"PATH", "/usr/sbin:/usr/bin:/sbin:/bin"},
    };
    for (const auto& [name, value] : request.environment) {
        if (!valid_environment_name(name) || value.find('\0') != std::string::npos) {
            result.status = HelperStatus::validation_failed;
            result.error = "invalid helper environment entry";
            return result;
        }
        environment[name] = value;
    }

    int standard_output[2]{-1, -1};
    int standard_error[2]{-1, -1};
    if (pipe2(standard_output, O_CLOEXEC) != 0 ||
        pipe2(standard_error, O_CLOEXEC) != 0) {
        const int saved_errno = errno;
        close_descriptor(standard_output[0]);
        close_descriptor(standard_output[1]);
        close_descriptor(standard_error[0]);
        close_descriptor(standard_error[1]);
        result.status = HelperStatus::launch_failed;
        result.error = "cannot create helper output pipes: " +
                       std::string(std::strerror(saved_errno));
        return result;
    }

    const long maximum_descriptor = sysconf(_SC_OPEN_MAX);
    const pid_t child = fork();
    if (child < 0) {
        const int saved_errno = errno;
        for (int& descriptor : standard_output) close_descriptor(descriptor);
        for (int& descriptor : standard_error) close_descriptor(descriptor);
        result.status = HelperStatus::launch_failed;
        result.error = "cannot fork helper: " +
                       std::string(std::strerror(saved_errno));
        return result;
    }
    if (child == 0) {
        setpgid(0, 0);
        close(standard_output[0]);
        close(standard_error[0]);
        if (dup2(standard_output[1], STDOUT_FILENO) < 0 ||
            dup2(standard_error[1], STDERR_FILENO) < 0) {
            _exit(126);
        }
        close(standard_output[1]);
        close(standard_error[1]);
        const int null_input = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (null_input >= 0) {
            dup2(null_input, STDIN_FILENO);
            close(null_input);
        }
        if (request.identity) {
            const HelperIdentity& identity = *request.identity;
            if (geteuid() == 0 &&
                (initgroups(identity.user.c_str(), identity.gid) != 0 ||
                 setgid(identity.gid) != 0 || setuid(identity.uid) != 0)) {
                _exit(126);
            }
        }
        close_inherited_descriptors(maximum_descriptor > 0
                                        ? maximum_descriptor
                                        : 1024L);
        std::vector<char*> arguments;
        arguments.reserve(request.arguments.size() + 2);
        arguments.push_back(const_cast<char*>(request.executable.c_str()));
        for (const std::string& argument : request.arguments) {
            arguments.push_back(const_cast<char*>(argument.c_str()));
        }
        arguments.push_back(nullptr);
        std::vector<std::string> environment_storage;
        environment_storage.reserve(environment.size());
        for (const auto& [name, value] : environment) {
            environment_storage.push_back(name + "=" + value);
        }
        std::vector<char*> environment_values;
        environment_values.reserve(environment_storage.size() + 1);
        for (std::string& value : environment_storage) {
            environment_values.push_back(value.data());
        }
        environment_values.push_back(nullptr);
        execve(request.executable.c_str(), arguments.data(),
               environment_values.data());
        _exit(127);
    }

    setpgid(child, child);
    close_descriptor(standard_output[1]);
    close_descriptor(standard_error[1]);
    if (!set_nonblocking(standard_output[0]) ||
        !set_nonblocking(standard_error[0])) {
        terminate_group(child);
        int ignored = 0;
        while (waitpid(child, &ignored, 0) < 0 && errno == EINTR) {}
        close_descriptor(standard_output[0]);
        close_descriptor(standard_error[0]);
        result.status = HelperStatus::launch_failed;
        result.error = "cannot configure helper output pipes";
        return result;
    }

    const auto deadline = started + request.timeout;
    std::size_t output_size = 0;
    bool child_finished = false;
    bool limit_reached = false;
    bool timed_out = false;
    int status = 0;
    while (!child_finished || standard_output[0] >= 0 || standard_error[0] >= 0) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            timed_out = true;
            break;
        }
        std::array<pollfd, 2> events{{
            {standard_output[0], POLLIN | POLLHUP, 0},
            {standard_error[0], POLLIN | POLLHUP, 0},
        }};
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now).count();
        const int poll_timeout = static_cast<int>(std::min<long long>(50, remaining));
        const int polled = poll(events.data(), events.size(), poll_timeout);
        if (polled < 0 && errno != EINTR) {
            result.error = "polling helper output failed: " +
                           std::string(std::strerror(errno));
            break;
        }
        if (!drain_descriptor(standard_output[0], result.standard_output,
                              output_size, request.maximum_output_bytes) ||
            !drain_descriptor(standard_error[0], result.standard_error,
                              output_size, request.maximum_output_bytes)) {
            limit_reached = true;
            break;
        }
        if (!child_finished) {
            const pid_t waited = waitpid(child, &status, WNOHANG);
            if (waited == child) {
                child_finished = true;
            } else if (waited < 0 && errno != EINTR) {
                result.error = "waiting for helper failed: " +
                               std::string(std::strerror(errno));
                break;
            }
        }
    }

    if (timed_out || limit_reached || !result.error.empty()) {
        terminate_group(child);
    }
    if (!child_finished) {
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    }
    close_descriptor(standard_output[0]);
    close_descriptor(standard_error[0]);
    result.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    if (limit_reached) {
        result.status = HelperStatus::output_limit_reached;
    } else if (timed_out) {
        result.status = HelperStatus::timed_out;
    } else if (!result.error.empty()) {
        result.status = HelperStatus::launch_failed;
    } else if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
        result.status = result.exit_code == 0 ? HelperStatus::succeeded
                                              : HelperStatus::exited_nonzero;
    } else if (WIFSIGNALED(status)) {
        result.signal_number = WTERMSIG(status);
        result.status = HelperStatus::terminated_by_signal;
    } else {
        result.status = HelperStatus::launch_failed;
        result.error = "helper returned an unknown wait status";
    }
    return result;
}

std::string helper_status_name(HelperStatus status) {
    switch (status) {
    case HelperStatus::succeeded: return "succeeded";
    case HelperStatus::validation_failed: return "validation failed";
    case HelperStatus::launch_failed: return "launch failed";
    case HelperStatus::timed_out: return "timed out";
    case HelperStatus::output_limit_reached: return "output limit reached";
    case HelperStatus::exited_nonzero: return "exited nonzero";
    case HelperStatus::terminated_by_signal: return "terminated by signal";
    }
    return "unknown status";
}

std::string helper_result_summary(const HelperResult& result) {
    std::ostringstream output;
    output << helper_status_name(result.status);
    if (result.status == HelperStatus::exited_nonzero) {
        output << " (exit " << result.exit_code << ')';
    } else if (result.status == HelperStatus::terminated_by_signal) {
        output << " (signal " << result.signal_number << ')';
    }
    if (!result.error.empty()) {
        output << ": " << result.error;
    } else if (!result.standard_error.empty() && !result.succeeded()) {
        std::string detail = result.standard_error.substr(0, 240);
        std::replace(detail.begin(), detail.end(), '\n', ' ');
        output << ": " << detail;
    }
    return output.str();
}
