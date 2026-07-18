#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

struct KernelPosture {
    std::string release;
    std::uint64_t taint{};
    bool signature_enforcement{false};
    std::string lockdown;
};

struct KernelModule {
    std::string name;
    std::string path;
    std::string sha256;
    std::string signer;
    std::string version_magic;
    bool in_tree{false};
    bool resolved{false};
    bool file_secure{false};
};

struct BpfProgram {
    std::string type;
    std::string name;
    std::string tag;
    std::string owner;

    bool operator<(const BpfProgram& other) const;
    bool operator==(const BpfProgram& other) const;
};

struct KernelSnapshot {
    KernelPosture posture;
    std::map<std::string, KernelModule> modules;
    std::string module_error;
    std::set<BpfProgram> bpf_programs;
    bool bpf_available{false};
    std::string bpf_error;
};

KernelModule parse_modinfo(const std::string& name, const std::string& contents);
std::map<std::string, KernelModule> parse_modinfo_batch(
    const std::string& contents);

struct KernelFinding {
    std::string severity;
    std::string rule;
    std::string detail;
};

std::set<std::string> parse_loaded_modules(const std::string& contents);
std::string parse_lockdown_mode(const std::string& contents);
std::set<BpfProgram> parse_bpftool_programs(const std::string& contents);
std::vector<KernelFinding> compare_kernel_snapshots(const KernelSnapshot& baseline,
                                                    const KernelSnapshot& current);
