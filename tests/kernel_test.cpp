#include "kernel.hpp"

#include <iostream>
#include <stdexcept>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

KernelModule trusted(std::string name, std::string hash = std::string(64, 'a')) {
    return {std::move(name), "/lib/modules/test/kernel/example.ko", std::move(hash),
            "Ubuntu Secure Boot Module Signature key", "test SMP", true, true, true};
}
}

int main() {
    const auto modules = parse_loaded_modules(
        "snd 126976 3 snd_hda_intel,snd_pcm, Live 0x0\n"
        "i915 4325376 41 - Live 0x0\ninvalid\n");
    require(modules.size() == 2 && modules.count("snd") == 1, "module parsing failed");
    require(parse_lockdown_mode("none [integrity] confidentiality\n") == "integrity",
            "lockdown parsing failed");
    const auto info = parse_modinfo("example",
        "filename: /lib/modules/test/example.ko\nintree: Y\nsigner: Ubuntu key\n"
        "vermagic: 6.test SMP\n");
    require(info.resolved && info.in_tree && info.signer == "Ubuntu key",
            "modinfo parsing failed");
    const auto batch = parse_modinfo_batch(
        "filename: /lib/modules/test/first.ko\nintree: Y\nname: first\n"
        "signer: Ubuntu key\nvermagic: test SMP\n"
        "filename: /lib/modules/test/second.ko\nintree: Y\nname: second\n"
        "signer: Ubuntu key\nvermagic: test SMP\n");
    require(batch.size() == 2 && batch.at("first").resolved &&
                batch.at("second").path.find("second.ko") != std::string::npos,
            "batched modinfo parsing failed");

    const auto bpf = parse_bpftool_programs(
        "12: cgroup_device name sd_devices tag abcdef0123456789 gpl\n"
        "\tloaded_at 2026-07-15 uid 0\n"
        "\tpids systemd(1)\n"
        "19: tracepoint name burrow_send tag 1111222233334444 gpl\n"
        "\tpids burrow(42)\n");
    require(bpf.size() == 2, "BPF parsing failed");

    KernelSnapshot base;
    base.posture = {"6.test", 0, true, "integrity"};
    base.modules.emplace("example", trusted("example"));
    base.bpf_programs = bpf;
    base.bpf_available = true;
    require(compare_kernel_snapshots(base, base).empty(), "identical snapshot produced finding");

    KernelSnapshot changed = base;
    changed.modules["example"].sha256 = std::string(64, 'b');
    KernelModule unsigned_module;
    unsigned_module.name = "new_unsigned";
    changed.modules.emplace("new_unsigned", std::move(unsigned_module));
    changed.posture.taint = 1;
    BpfProgram unexpected{"kprobe", "probe", "9999000011112222", "unknown(9)"};
    changed.bpf_programs.insert(unexpected);
    changed.bpf_programs.insert(
        BpfProgram{"cgroup_device", "sd_devices", "7777888899990000", ""});
    const auto findings = compare_kernel_snapshots(base, changed);
    bool hash = false, untrusted = false, taint = false, new_bpf = false,
         managed_bpf = false;
    for (const auto& finding : findings) {
        hash |= finding.rule == "kernel.module-fingerprint-changed";
        untrusted |= finding.rule == "kernel.module-untrusted";
        taint |= finding.rule == "kernel.taint-changed";
        new_bpf |= finding.rule == "kernel.bpf-program-new";
        managed_bpf |= finding.rule == "kernel.bpf-program-lifecycle" &&
                       finding.severity == "NOTICE";
    }
    require(hash && untrusted && taint && new_bpf && managed_bpf,
            "changed snapshot findings incomplete");
    std::cout << "kernel tests passed\n";
}
