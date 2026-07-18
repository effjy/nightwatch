#include "kernel.hpp"

#include <algorithm>
#include <sstream>
#include <tuple>
#include <cctype>

bool BpfProgram::operator<(const BpfProgram& other) const {
    return std::tie(type, name, tag, owner) <
           std::tie(other.type, other.name, other.tag, other.owner);
}

bool BpfProgram::operator==(const BpfProgram& other) const {
    return type == other.type && name == other.name && tag == other.tag &&
           owner == other.owner;
}

std::set<std::string> parse_loaded_modules(const std::string& contents) {
    std::set<std::string> result;
    std::istringstream input(contents);
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string name;
        std::uint64_t size = 0;
        if (!(fields >> name >> size)) {
            continue;
        }
        const bool valid = !name.empty() &&
            std::all_of(name.begin(), name.end(), [](unsigned char character) {
                return std::isalnum(character) != 0 || character == '_';
            });
        if (valid) {
            result.insert(std::move(name));
        }
    }
    return result;
}

KernelModule parse_modinfo(const std::string& name, const std::string& contents) {
    KernelModule result;
    result.name = name;
    std::istringstream input(contents);
    std::string line;
    while (std::getline(input, line)) {
        const std::size_t separator = line.find(':');
        if (separator == std::string::npos) continue;
        std::string key = line.substr(0, separator);
        std::string value = line.substr(separator + 1);
        const std::size_t first = value.find_first_not_of(" \t");
        value = first == std::string::npos ? std::string{} : value.substr(first);
        if (key == "filename") result.path = value;
        else if (key == "signer") result.signer = value;
        else if (key == "intree") result.in_tree = value == "Y";
        else if (key == "vermagic") result.version_magic = value;
    }
    result.resolved = !result.path.empty() && result.path != "(builtin)";
    return result;
}

std::map<std::string, KernelModule> parse_modinfo_batch(
    const std::string& contents) {
    std::map<std::string, KernelModule> result;
    std::istringstream input(contents);
    std::string line;
    std::ostringstream block;
    auto finish = [&]() {
        const std::string value = block.str();
        block.str({});
        block.clear();
        if (value.empty()) {
            return;
        }
        std::istringstream lines(value);
        std::string candidate;
        std::string current;
        while (std::getline(lines, current)) {
            if (current.rfind("name:", 0) != 0) {
                continue;
            }
            candidate = current.substr(5);
            const std::size_t first = candidate.find_first_not_of(" \t");
            candidate = first == std::string::npos
                ? std::string{} : candidate.substr(first);
            break;
        }
        const bool valid = !candidate.empty() &&
            std::all_of(candidate.begin(), candidate.end(),
                        [](unsigned char character) {
                            return std::isalnum(character) != 0 ||
                                   character == '_';
                        });
        if (valid) {
            result.emplace(candidate, parse_modinfo(candidate, value));
        }
    };
    while (std::getline(input, line)) {
        if (line.rfind("filename:", 0) == 0 && block.tellp() > 0) {
            finish();
        }
        block << line << '\n';
    }
    finish();
    return result;
}

std::string parse_lockdown_mode(const std::string& contents) {
    std::istringstream fields(contents);
    std::string value;
    while (fields >> value) {
        if (value.size() >= 2 && value.front() == '[' && value.back() == ']') {
            return value.substr(1, value.size() - 2);
        }
    }
    return contents.empty() ? "unavailable" : "unknown";
}

std::set<BpfProgram> parse_bpftool_programs(const std::string& contents) {
    std::set<BpfProgram> result;
    std::istringstream input(contents);
    std::string line;
    BpfProgram current;
    bool active = false;
    auto finish = [&]() {
        if (active && !current.type.empty() && !current.tag.empty()) {
            result.insert(current);
        }
        current = BpfProgram{};
        active = false;
    };
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string first;
        fields >> first;
        if (!first.empty() && first.back() == ':') {
            finish();
            active = true;
            fields >> current.type;
            std::string key;
            while (fields >> key) {
                if (key == "name") {
                    fields >> current.name;
                } else if (key == "tag") {
                    fields >> current.tag;
                }
            }
        } else if (active) {
            const std::size_t pids = line.find("pids ");
            if (pids != std::string::npos) {
                current.owner = line.substr(pids + 5);
                while (!current.owner.empty() &&
                       (current.owner.back() == ' ' || current.owner.back() == '\r')) {
                    current.owner.pop_back();
                }
                for (std::size_t open = current.owner.find('(');
                     open != std::string::npos;) {
                    const std::size_t close = current.owner.find(')', open + 1);
                    if (close == std::string::npos) break;
                    bool numeric = close > open + 1;
                    for (std::size_t index = open + 1; index < close; ++index) {
                        numeric = numeric &&
                            std::isdigit(static_cast<unsigned char>(current.owner[index])) != 0;
                    }
                    if (numeric) current.owner.replace(open + 1, close - open - 1, "*");
                    open = current.owner.find('(', close + (numeric ? 2 : 1));
                }
            }
        }
    }
    finish();
    return result;
}

std::vector<KernelFinding> compare_kernel_snapshots(const KernelSnapshot& baseline,
                                                    const KernelSnapshot& current) {
    std::vector<KernelFinding> result;
    auto add = [&](std::string severity, std::string rule, std::string detail) {
        result.push_back({std::move(severity), std::move(rule), std::move(detail)});
    };
    if (current.posture.release != baseline.posture.release) {
        add("HIGH", "kernel.release-changed", "Kernel release changed from " +
            baseline.posture.release + " to " + current.posture.release);
    }
    if (current.posture.taint != baseline.posture.taint) {
        add("HIGH", "kernel.taint-changed", "Kernel taint changed from " +
            std::to_string(baseline.posture.taint) + " to " +
            std::to_string(current.posture.taint));
    }
    if (baseline.posture.signature_enforcement &&
        !current.posture.signature_enforcement) {
        add("HIGH", "kernel.signature-enforcement-weakened",
            "Kernel module signature enforcement changed from enabled to disabled");
    }
    if (current.posture.lockdown != baseline.posture.lockdown) {
        add("HIGH", "kernel.lockdown-changed", "Kernel lockdown mode changed from " +
            baseline.posture.lockdown + " to " + current.posture.lockdown);
    }
    for (const auto& [name, expected] : baseline.modules) {
        const auto found = current.modules.find(name);
        if (found == current.modules.end()) {
            add("NOTICE", "kernel.module-unloaded", "Calibrated module " + name +
                " is no longer loaded");
            continue;
        }
        const KernelModule& actual = found->second;
        if (!actual.resolved || !actual.file_secure || actual.signer.empty() ||
            !actual.in_tree) {
            add("HIGH", "kernel.module-untrusted", "Loaded module " + name +
                " is unresolved, unsigned, out-of-tree, or has unsafe file permissions");
        } else if (actual.path != expected.path || actual.sha256 != expected.sha256 ||
                   actual.signer != expected.signer ||
                   actual.version_magic != expected.version_magic ||
                   actual.in_tree != expected.in_tree) {
            add("HIGH", "kernel.module-fingerprint-changed",
                "Loaded module " + name + " no longer matches its calibrated file and metadata");
        }
    }
    for (const auto& [name, module] : current.modules) {
        if (baseline.modules.find(name) != baseline.modules.end()) {
            continue;
        }
        if (!module.resolved || !module.file_secure || module.signer.empty() ||
            !module.in_tree) {
            add("HIGH", "kernel.module-untrusted", "New module " + name +
                " is unresolved, unsigned, out-of-tree, or has unsafe file permissions");
        } else {
            add("NOTICE", "kernel.module-loaded", "New signed in-tree module " + name +
                " was loaded from " + module.path);
        }
    }
    if (baseline.bpf_available && current.bpf_available) {
        for (const BpfProgram& program : current.bpf_programs) {
            if (baseline.bpf_programs.find(program) == baseline.bpf_programs.end()) {
                const bool expected_manager_lifecycle =
                    (program.type == "cgroup_device" || program.type == "cgroup_skb") &&
                    (program.name.rfind("sd_", 0) == 0 ||
                     program.name.rfind("s_", 0) == 0);
                add(expected_manager_lifecycle ? "NOTICE" : "HIGH",
                    expected_manager_lifecycle ? "kernel.bpf-program-lifecycle" :
                                                 "kernel.bpf-program-new",
                    "New BPF program type=" +
                    program.type + " name=" + program.name + " tag=" + program.tag +
                    " owner=" + (program.owner.empty() ? "[unavailable]" : program.owner));
            }
        }
        for (const BpfProgram& program : baseline.bpf_programs) {
            if (current.bpf_programs.find(program) == current.bpf_programs.end()) {
                add("NOTICE", "kernel.bpf-program-removed", "Calibrated BPF program type=" +
                    program.type + " name=" + program.name + " tag=" + program.tag +
                    " is no longer present");
            }
        }
    }
    return result;
}
