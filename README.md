<div align="center">
<a href="https://github.com/effjy/nightwatch/"><img src="titles/nightwatch-title.svg" height="52" alt="Nightwatch"></a>
</div>
<br>

> A passive, baseline-driven Linux security monitor that detects suspicious
> system activity and produces clear, evidence-backed overnight reports.

## Repository preview

Nightwatch is being prepared for its hackathon presentation. The complete
source code, build instructions, test suite, sample reports, and demonstration
materials will be published here soon.

The current version is actively running on and being validated against a Dell
Latitude 5400 Linux workstation. This repository is private while final
long-duration testing, documentation review, and presentation preparation are
completed.

## What is Nightwatch?

Nightwatch watches a Linux computer while its owner is asleep or away. It
learns a protected, host-specific baseline and then passively compares live
system activity against that known state until the user presses Ctrl-C.

Instead of dumping thousands of unexplained events, Nightwatch produces an
outcome-driven report that answers three practical questions:

1. **What went well?** Which monitoring domains completed successfully without
   a finding?
2. **What needs attention?** What changed, why does it matter, and what should
   the owner check next?
3. **How complete was the evidence?** Was the session fully observed, partially
   verified, or inconclusive?

Nightwatch is deliberately passive. It observes and explains; it does not kill
processes, block devices, modify the firewall, load kernel modules, or make
automatic trust decisions on the owner's behalf.

## Why we built it

Personal computers produce a large amount of legitimate background activity.
Browsers open short-lived sockets, package managers run maintenance scripts,
desktop services appear on demand, and kernel BPF programs can change as
services start and stop. A useful security monitor must distinguish these
normal lifecycle events from changes that genuinely deserve investigation.

Nightwatch combines exact integrity checks, host-specific calibration,
process attribution, conservative policy, and real-world validation to make
that distinction explainable.

## Key features

- **Protected host calibration** — records the expected idle state, trusted
  microphone and webcam behavior, network patterns, kernel posture, modules,
  and stable BPF identities.
- **Executable integrity** — fingerprints observed executable files with
  SHA-256 and security metadata, detecting replacements, metadata changes, and
  deleted executables.
- **Interpreter script integrity** — identifies and fingerprints script
  entrypoints instead of trusting only the Python, shell, or Perl interpreter.
- **Exact reviewed fingerprints** — allows investigated executables and scripts
  to be recognized by hash, size, ownership, group, and permissions rather
  than by pathname alone.
- **Microphone and webcam observation** — monitors direct device handles and
  performs best-effort PipeWire client attribution.
- **Process-attributed networking** — observes TCP, UDP, raw, and packet sockets
  and reduces volatile connections into stable behavior patterns.
- **Kernel assurance** — tracks kernel release, taint, module-signature
  enforcement, lockdown mode, loaded-module fingerprints, and BPF program
  lifecycle.
- **Preflight readiness checks** — verifies privileges, protected files,
  baseline compatibility, helper safety, kernel alignment, and live BPF access
  before an unattended run.
- **Outcome-driven reporting** — separates probable normal activity, items that
  need review, high-concern findings, and visibility degradations.
- **Correlated maintenance activity** — conservatively groups verified Ubuntu
  package and kernel-update chains while retaining every raw member finding.
- **Crash-aware evidence** — reserves the report before monitoring, maintains a
  synchronized recovery journal, and preserves evidence after interruption.
- **Human and machine-readable output** — saves a detailed text report and an
  independently versioned JSON assurance report with root-only permissions.

## Assurance model

Nightwatch never treats missing evidence as clean evidence. Each monitoring
domain retains one of three states:

- **Verified** — the check completed and no finding was detected;
- **Finding detected** — observation succeeded and policy identified something
  requiring attention;
- **Unknown or unavailable** — the check could not be completed reliably.

Those domain states produce one of four overall conclusions:

- `FULLY VERIFIED - NO FINDINGS`
- `VERIFIED WITH FINDINGS`
- `PARTIALLY VERIFIED`
- `INCONCLUSIVE`

Confidence describes the completeness of Nightwatch's visibility—not a claim
that any computer is certainly free of compromise.

## A typical Nightwatch session

```text
Calibrate the known host
        ↓
Run preflight checks
        ↓
Start passive monitoring
        ↓
Sleep, work, or leave the computer unattended
        ↓
Press Ctrl-C
        ↓
Read the conclusion and prioritized follow-up
        ↓
Inspect complete evidence only when necessary
```

## Example report opening

```text
Assurance summary
-----------------
Overall result: VERIFIED WITH FINDINGS
Security findings: 3 (0 high, 3 notice)
Monitoring degradations: 0

What went well
--------------
- All scheduled snapshots completed without a skipped scan.
- Executable, script, kernel, BPF, and media checks completed successfully.
- Monitoring visibility remained complete.

What needs attention
--------------------
[PROBABLY NORMAL] New low-risk network behavior
  Why it matters: A calibrated application used a socket pattern absent from
  calibration.
  Recommended follow-up: Confirm that the named application was expected.
```

The complete raw findings remain available below the summary for audit and
deeper investigation.

## Built for explainability

Every Nightwatch finding carries:

- a stable rule identity;
- the affected monitoring domain;
- priority and classification;
- a human-readable title;
- the observation that triggered it;
- an explanation of why it matters;
- a recommended next check.

Classification never silently authorizes future behavior or changes the
baseline. The owner remains in control of every trust decision.

## Security-conscious implementation

Nightwatch is written in C++17 and builds with GNU Make without third-party C++
libraries. It collects local evidence primarily from Linux `/proc` and sysfs,
with bounded use of `pw-cli`, `modinfo`, and `bpftool`.

Protected inputs and evidence use strict ownership and permission checks,
bounded file sizes, no-symlink file opening, exclusive report creation, helper
timeouts, output limits, and durable synchronization. Reports, baselines, and
reviewed fingerprints are root-owned and restricted to the owner when
Nightwatch runs as root.

## Tested on a real workstation

Nightwatch has progressed through repeated attended and unattended validation
on a Dell Latitude 5400. Testing has included:

- multi-hour overnight monitoring;
- normal desktop and browser use;
- microphone and webcam calibration;
- Ubuntu package and kernel updates;
- reboot and new-kernel validation;
- executable and same-size content changes;
- interpreter-script integrity changes;
- transient and persistent network behavior;
- kernel module and BPF lifecycle changes;
- report recovery and cadence regression tests.
- monotonic runtime, deadline-overrun accounting, maximum scan latency, and
  collector/policy timing in schema-versioned reports.

The automated suite currently contains 11 optimized test suites, matching
AddressSanitizer and UndefinedBehaviorSanitizer builds, deterministic golden
human reports, a separately tested JSON schema, and reproducible mutation
fuzzing for exposed network, kernel/helper-output, and process-argument parsers.
The first campaign completed 200,000 distinct malformed cases without a
sanitizer or undefined-behavior finding.

## Current project status

- Foreground monitoring and reports: **complete and validated**
- Calibration, media attribution, and recovery journals: **complete and
  validated**
- Network monitoring: **complete and validated**
- Kernel, module, and BPF monitoring: **complete and validated**
- Reviewed executable and script fingerprints: **complete and validated**
- Typed assurance and outcome-driven reporting: **implemented and validated**
- Versioned JSON assurance reports: **schema 3 implemented and root-smoke-
  validated; schemas 1 and 2 attended/overnight-validated**
- Unified bounded helper execution for `modinfo`, `bpftool`, and privilege-
  dropped `pw-cli`: **implemented, sanitizer-tested, installed, preflight-
  validated, and normal-use attended-validated**
- Session-anchored one-second sampling cadence: **implemented, fully tested,
  root-smoke-validated, recalibrated, and preflight-validated**
- Bounded findings, degradations, media/PipeWire/network sessions, and recovery
  journal with explicit dropped-record accounting: **implemented, sanitizer-
  tested, installed, root-smoke-validated, recalibrated, and preflight-
  validated**
- Persistence and authentication/session monitoring: **planned**
- Privilege separation and optional daemon operation: **future hardening**

## Limitations

Nightwatch is a host-specific heuristic monitor, not an antivirus engine or a
proof that a machine is clean. Its current limitations include:

- polling can miss activity shorter than the sampling interval;
- `/proc` visibility does not cover every network namespace or unconnected UDP
  destination;
- PipeWire attribution depends on the properties exposed by the active graph;
- external helper availability can reduce visibility;
- malware present during calibration may become part of the baseline;
- root or kernel-level compromise may hide or alter the evidence Nightwatch
  observes;
- physical and offline tampering require additional controls.

Nightwatch reports these limitations and any session-specific loss of
visibility rather than presenting uncertainty as a clean result.

## Roadmap

Near-term work includes:

- persistence checks for systemd units, scheduled tasks, and startup entries;
- authentication and session evidence for unauthorized-use detection;
- independent BPF attachment-site inventory;
- broader coverage-guided parser fuzzing and additional resource ceilings;
- session-to-session comparison;
- authenticated baselines and tamper-evident reports;
- a smaller privileged collection boundary;
- optional systemd service integration.

## Technology

- C++17
- GNU Make
- Linux `/proc` and sysfs
- PipeWire tooling
- `modinfo` and `bpftool`
- SHA-256 file fingerprints
- Human-readable text and JSON schema-versioned evidence

## Source and documentation

The following will be available in this repository for the judges:

- complete C++ source code;
- Makefile and prerequisite instructions;
- calibration, preflight, and monitoring guide;
- threat model and architecture design;
- automated and sanitizer tests;
- safe synthetic test fixtures;
- sample human and JSON reports;
- hackathon demonstration instructions.

**Full repository content coming soon.**

---

Nightwatch is not trying to produce the most alerts. It is trying to produce
the clearest evidence—and to be honest when that evidence is incomplete.
