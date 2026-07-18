<div align="center">
<a href="https://github.com/effjy/nightwatch/"><img src="titles/nightwatch-title.svg" height="52" alt="Nightwatch"></a>
</div>
<br>

> A passive, baseline-driven Linux security monitor that detects suspicious
> system activity and produces clear, evidence-backed overnight reports.

## Release status

Nightwatch `0.1.0` is feature-frozen and release-package validated for its
hackathon release. The repository
contains the complete C++17 source, build system, automated tests, threat model,
design notes, release checklist, and demonstration guide. The frozen candidate
passed 14 optimized and 14 AddressSanitizer/UndefinedBehaviorSanitizer suites,
an all-pass 16-check host preflight, short attended validation, and a final
4.6-hour unattended watch with 16,593 completed snapshots and no skipped scan,
high-severity finding, integrity change, media capture, persistence change, or
dropped evidence. Its deterministic allow-list archive also passed an exact
privacy scan, clean-room optimized and sanitizer suites, and staged installation
inspection.

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

## Install and run Nightwatch

### Requirements

Nightwatch targets a systemd-based Linux host and currently has its strongest
validation on Ubuntu. Building requires:

- a C++17 compiler (`g++`);
- GNU Make;
- standard Linux development headers and tools.

Runtime collection uses these system tools:

- `modinfo` from `kmod` for kernel-module metadata;
- `bpftool` for BPF inventory;
- `pw-cli` from PipeWire for best-effort media-client attribution;
- `journalctl` and `loginctl` from systemd for authentication/session evidence.

On Ubuntu or Debian, install the prerequisites with:

```bash
sudo apt update
sudo apt install build-essential bpftool kmod pipewire-bin
```

`journalctl` and `loginctl` are normally already supplied by the running
systemd installation. `jq` is optional but convenient for inspecting JSON:

```bash
sudo apt install jq
```

Package names differ on other distributions. Confirm that the five runtime
commands above are available before relying on an unattended watch.

### Download, compile, and test

```bash
git clone https://github.com/effjy/nightwatch.git
cd nightwatch
make
make test
```

`make test` builds Nightwatch and runs all 14 optimized unit, regression,
golden-report, schema, parser, and policy suites. The optional sanitizer pass is:

```bash
make sanitize
```

### Install

Install the binary and create the protected system directories:

```bash
sudo make install
```

This installs:

```text
/usr/local/sbin/nightwatch
/etc/nightwatch/                 root-owned configuration
/var/lib/nightwatch/             protected baseline state
/var/log/nightwatch/             protected reports and recovery evidence
```

On a **brand-new Nightwatch installation only**, install the empty reviewed-
fingerprint database:

```bash
sudo make install-reviewed
```

Do not run `install-reviewed` during an upgrade: it intentionally copies the
public empty template and would replace a locally curated reviewed database.
Ordinary `sudo make install` updates only the program and preserves that policy.

### Calibrate the host

Inspect the machine first, then create its protected baseline:

```bash
sudo /usr/local/sbin/nightwatch calibrate
```

The default ceremony records 120 seconds of ordinary idle behavior. Nightwatch
then prompts for a 30-second media phase; intentionally exercise the microphone
and webcam behavior that should be recognized later. Calibration records what
is present—it does not prove that the machine is clean. Investigate unexpected
processes, listeners, modules, BPF programs, or persistence entries before
accepting them as expected state.

Calibration must be repeated after installing a different Nightwatch binary,
changing kernels, or intentionally changing monitored baseline state.

### Run preflight

Before every unattended watch, verify that the installed binary, baseline,
kernel, protected files, helper tools, journal access, login-session access,
report directory, and BPF visibility are ready:

```bash
sudo /usr/local/sbin/nightwatch preflight
```

Proceed only when the command ends with `READY for an unattended watch` and no
warning or failure remains unexplained.

### Monitor

```bash
sudo /usr/local/sbin/nightwatch monitor
```

Leave Nightwatch in the foreground while the computer is unattended. Press
Ctrl-C when the watch is finished. Nightwatch finalizes and prints paths for a
human-readable report and schema-versioned JSON report under
`/var/log/nightwatch`.

The default interval is one second. It can be stated explicitly with:

```bash
sudo /usr/local/sbin/nightwatch monitor --interval 1
```

### Read the reports

Reports are root-owned and mode `0600` because they can contain usernames,
command lines, local paths, socket addresses, and other sensitive host context:

```bash
sudo less /var/log/nightwatch/nightwatch-YYYYMMDD-HHMMSS.txt
sudo jq . /var/log/nightwatch/nightwatch-YYYYMMDD-HHMMSS.json
```

Read the assurance summary first: overall conclusion, domain states, what went
well, prioritized findings, and monitoring degradations. Raw evidence remains
below it for verification. Do not publish an unreviewed real-host report.

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
- **Persistence integrity** — fingerprints systemd, cron/at, desktop autostart,
  legacy init, and login-startup entries, including systemd enablement symlinks,
  with explicit added, changed, removed, and unavailable states.
- **Authentication and session evidence** — uses bounded incremental journal
  evidence and sampled systemd-logind state for login/session lifecycle, failed
  authentication, and reliable lock/unlock transitions, with explicit unknown
  or degraded status when evidence cannot be read.
- **Preflight readiness checks** — verifies privileges, protected files,
  baseline compatibility, helper safety, kernel alignment, journal and session
  access, and live BPF access before an unattended run.
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
with bounded use of `pw-cli`, `modinfo`, `bpftool`, `journalctl`, and `loginctl`.

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
- persistence and authentication/session evidence;
- report recovery and cadence regression tests;
- monotonic runtime, deadline-overrun accounting, maximum scan latency, and
  collector/policy timing in schema-versioned reports.

The automated suite currently contains 14 optimized test suites, matching
AddressSanitizer and UndefinedBehaviorSanitizer builds, deterministic golden
human reports, a separately tested JSON schema, and reproducible mutation
fuzzing for exposed network, kernel/helper-output, and process-argument parsers.
The first campaign completed 200,000 distinct malformed cases without a
sanitizer or undefined-behavior finding.

## Current project status

The hackathon detection scope is implemented and feature-frozen. Foreground
monitoring, host calibration, exact reviewed fingerprints, media attribution,
network behavior, kernel/module/BPF integrity, persistence, authentication and
login sessions, typed assurance, schema-4 JSON, recovery evidence, retention
budgets, and the 16-check preflight are implemented and tested.

The final 4.6-hour unattended candidate validation completed 16,593 snapshots
with no skipped scan, high-priority finding, integrity change, media capture,
persistence change, malformed/truncated authentication evidence, or dropped
record. Four low-priority socket patterns were attributed to expected browser,
DNS, model-service, and package-refresh activity. One short-lived, subsequently
verified maintenance command conservatively produced a noncritical visibility
degradation, demonstrating that unavailable evidence is not mislabeled clean.

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

- hackathon screenshots, demonstration recording, and publication checks;
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
- MIT licensed

## Source and documentation

This repository includes:

- complete C++ source code;
- Makefile and prerequisite instructions;
- calibration, preflight, and monitoring guide;
- threat model and architecture design;
- automated and sanitizer tests;
- safe synthetic test fixtures;
- hackathon demonstration instructions.

Release archives are assembled from an explicit source allow-list. Real host
baselines, reviewed fingerprints, reports, binaries, local shortcuts, and
conversation state are excluded; the packaged reviewed database is an empty
template that grants no trust by default.

Nightwatch is available under the [MIT License](LICENSE).

---

Nightwatch is not trying to produce the most alerts. It is trying to produce
the clearest evidence—and to be honest when that evidence is incomplete.
