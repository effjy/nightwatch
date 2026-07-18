# Nightwatch threat model

## Purpose

Nightwatch is a passive, host-specific Linux observation tool. It is intended
to answer: “What changed or behaved differently while the owner was away, and
how complete was the observation?” It does not claim to prove that a computer
is clean, prevent compromise, or replace endpoint protection, Secure Boot,
timely updates, backups, or offline forensic inspection.

The intended operating mode is a foreground root process started by the owner,
using a recently created baseline and protected reviewed-fingerprint database,
running until Ctrl-C and then producing a durable human-readable report.

## Security objectives

Nightwatch aims to:

- detect unexpected or changed executables and interpreter entrypoint scripts;
- attribute sampled microphone, camera, PipeWire, and network activity;
- detect changes in kernel posture, loaded modules, and stable BPF identities;
- preserve explainable evidence during a long-running session;
- distinguish a verified check, a finding, and unavailable evidence;
- avoid modifying or terminating observed processes;
- fail visibly when critical trust inputs are stale, unsafe, or unreadable.

Nightwatch does not aim to:

- block malware or network traffic;
- detect every event shorter than the sampling interval;
- inspect process memory, packet contents, encrypted traffic, firmware, or
  another network namespace comprehensively;
- remain trustworthy after the running kernel has been fully compromised;
- authenticate reports against an attacker who gains root and can rewrite all
  local evidence;
- prove that behavior recorded during calibration was legitimate.

## Assets

The assets Nightwatch attempts to protect or preserve are:

- the integrity of the installed Nightwatch executable;
- the meaning and integrity of the calibration baseline;
- the meaning and integrity of reviewed executable/script fingerprints;
- monitoring coverage across process, script, media, network, kernel, module,
  and BPF domains;
- the accuracy and durability of the recovery journal and final report;
- the owner’s ability to distinguish findings from missing visibility.

Nightwatch observes the host but is not itself the authority that grants access
to the microphone, camera, kernel, or network.

## Chain of trust

Nightwatch’s conclusions depend on the following chain:

1. The owner starts the intended `/usr/local/sbin/nightwatch` binary.
2. The binary is root-owned and not writable by group or others.
3. The baseline is a root-owned, protected regular file for the current host.
4. The baseline was created during a period the owner considers representative.
5. The reviewed database contains exact, investigated fingerprints rather than
   path-only approvals.
6. `/proc`, sysfs, the BPF interface, and kernel socket tables report truthful
   state.
7. Fixed external helpers such as `modinfo`, `bpftool`, and `pw-cli` are the
   intended root-owned binaries and behave correctly.
8. The filesystem and storage stack preserve the bytes Nightwatch reads and
   writes.
9. The running kernel and firmware have not been subverted beneath Nightwatch.

The `preflight` command checks several local links in this chain. It cannot
establish that calibration was clean, that helper binaries are semantically
correct, or that the kernel is telling the truth.

## Attacker classes

### Ordinary user-space malware

Examples include a process running as the desktop user, an unwanted browser
child, or a malicious script without root privileges.

Expected visibility is comparatively strong when activity lasts for at least a
sampling interval. Nightwatch may observe new executable paths, changed files,
interpreter scripts, media handles, PipeWire clients, or attributed sockets.
Short-lived activity can be missed. Activity hidden inside a calibrated
process, injected into its memory, or performed through an already-open file
descriptor may not create a new identity.

### Root-level user-space malware

Root can read or change most local files, enter namespaces, alter processes,
load permitted kernel functionality, replace helpers, interfere with
Nightwatch, or rewrite reports. Nightwatch may still record unexpected state
before interference, but local root compromise is outside its reliable trust
boundary.

Protected ownership and mode checks prevent accidental trust of unprivileged
files. They do not protect against a hostile root account.

### Malware present during calibration

Calibration records observed state; it does not certify that state as clean.
Malware active during calibration may become part of the executable, script,
media, network, module, or BPF baseline. Calibration should therefore follow
updates and an independent review, and should occur while the machine is in a
known, controlled state.

Session comparison must never treat a previous session as authorization.

### Replaced or compromised helper binaries

Nightwatch currently uses fixed paths for `modinfo`, `bpftool`, and `pw-cli`.
Preflight verifies that these resolve to root-owned executable regular files
that are not writable by group or others. This detects unsafe placement and
permissions but not a malicious root-owned replacement. Exact helper
fingerprints or package verification may be added later.

Helper failure, timeout, malformed output, or unavailable permissions must be
represented as unknown/degraded visibility, not as a clean result.

### Kernel-level compromise

A compromised kernel can hide processes, sockets, devices, modules, BPF
programs, files, and audit evidence, and can falsify `/proc` or sysfs. It can
also tamper with Nightwatch’s memory and writes. Nightwatch cannot provide a
trustworthy clean conclusion under this attacker.

Secure Boot, signed modules, lockdown, measured boot, and offline inspection
can improve assurance but do not turn Nightwatch into a kernel-independent
monitor.

### Physical or offline tampering

An attacker with physical access or offline write access may replace the
binary, baseline, reviewed database, helpers, kernel, or reports. Full-disk
encryption helps when the machine is powered off. Authenticated baselines and
reports with a TPM, removable key, or remote verifier are future work.

## Trust inputs and failure behavior

| Input | Current protection | Required interpretation on failure |
|---|---|---|
| Running binary | Root ownership and mode check; baseline fingerprint | Failure; do not run unattended |
| Baseline | `O_NOFOLLOW`, regular-file, size, ownership, mode, version and host checks | Failure; no calibrated conclusion |
| Reviewed database | `O_NOFOLLOW`, regular-file, size, ownership, mode and strict parser | Warning if absent; failure if unsafe or malformed |
| Report directory | Protected directory checks and exclusive report creation | Failure if unsafe or unwritable |
| `/proc` snapshots | Repeated sampling and skipped-snapshot accounting | Degraded if reads fail or retention is exhausted |
| PipeWire graph | Best-effort `pw-cli` attribution | Media domain partially unknown if unavailable |
| Module metadata | Fixed `modinfo` helper plus file fingerprints | Kernel/module domain unknown if unavailable |
| BPF inventory | Fixed `bpftool` helper | BPF domain unknown if unavailable |
| Kernel state | `/proc`, sysfs and kernel APIs | Cannot be independently verified after kernel compromise |
| Reports/journals | Root-protected files, early reservation, syncing | Locally durable, but not cryptographically authenticated |

## Result language

“No findings” means only that no configured rule detected a finding in the
evidence Nightwatch successfully collected. It must never be phrased as proof
that the host is clean.

The intended session conclusions are:

- **Fully verified with no findings:** every required domain completed and no
  finding was produced.
- **Fully verified with findings:** observation completed and findings require
  review.
- **Partially verified:** no decisive failure occurred, but one or more domains
  were unavailable or degraded.
- **Inconclusive:** a core collector, trust input, or evidence budget failed
  enough that a reliable session conclusion cannot be made.

These conclusion types are now implemented using typed findings, monitoring
degradations, and per-domain verification states. The current implementation
conservatively marks a domain unknown when a recorded visibility failure
occurs. Additional helper, parser, and resource failures still need to be
migrated into this model as collector boundaries are extracted.

## Residual risks

- Polling may miss activity shorter than the interval.
- Process identity based on paths and sampled metadata cannot detect every
  form of code injection.
- PipeWire attribution depends on graph properties supplied by clients.
- Network attribution can miss short sessions, unconnected UDP destinations,
  and activity in other namespaces.
- Stable BPF identity does not yet include a complete attachment-site inventory.
- A reviewed fingerprint becomes stale after a legitimate package update and
  must be reinvestigated rather than automatically accepted.
- Reports and baselines are not yet cryptographically authenticated.
- Much of the monitor still runs in one privileged process.

## Operational assumptions

- The owner controls the Dell Latitude 5400 and its root account.
- Preflight is run before an unattended watch.
- The current installed binary and baseline must match exactly.
- Recalibration follows intentional Nightwatch, kernel, module, or relevant
  service changes.
- Findings are investigated before fingerprints are reviewed.
- Nightwatch remains passive; automatic remediation is out of scope.

This document should be updated whenever a new collector, helper, trust input,
automatic action, or privilege boundary is introduced.
