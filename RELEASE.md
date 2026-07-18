# Nightwatch v0.1.0

Nightwatch is a passive, baseline-driven Linux host-security monitor designed
to watch a computer while its owner is asleep or away. It observes integrity,
media, network, kernel, persistence, and authentication/session activity, then
produces prioritized human-readable and schema-versioned JSON reports when
stopped with Ctrl-C.

This is the first public hackathon release. The detection scope is feature-
frozen, privacy-reviewed, clean-room tested, and released under the MIT License.

## Release assets

- `nightwatch-0.1.0.tar.gz` — deterministic source release
- `nightwatch-0.1.0.tar.gz.sha256` — SHA-256 checksum sidecar

Expected archive SHA-256:

```text
d2e210a0a24b803bc33006bda1319741df912d998cfeac722203a65e832ab61c
```

Verify the downloaded archive from the directory containing both files:

```bash
sha256sum -c nightwatch-0.1.0.tar.gz.sha256
```

Expected result:

```text
nightwatch-0.1.0.tar.gz: OK
```

## Highlights

- Protected 120-second idle and 30-second intentional media calibration.
- SHA-256 executable, interpreter-script, kernel-module, and persistence
  fingerprints with ownership, group, size, and permission checks.
- Exact reviewed executable and script identities instead of pathname-only
  allowlisting.
- Direct microphone/webcam-device observation and best-effort PipeWire client
  attribution.
- Process-attributed TCP, UDP, raw, and packet socket monitoring.
- Kernel release, taint, signature enforcement, lockdown, module, and BPF
  integrity monitoring.
- Systemd, cron/at, desktop autostart, legacy init, shell, and login-startup
  persistence monitoring.
- Bounded authentication and login-session evidence from the system journal
  and systemd-logind, including explicit unavailable/degraded states.
- A 16-check `preflight` command for unattended-watch readiness.
- Conclusion-first text reports and independently versioned schema-4 JSON.
- Explicit evidence-retention ceilings and visible dropped-record accounting.
- Crash-aware report reservation, recovery journaling, restrictive permissions,
  and clean finalization.
- Passive operation: Nightwatch reports and explains but does not kill
  processes, block devices, change the firewall, or modify the monitored host.

## Release validation

The frozen release source passed:

- all 14 optimized unit, regression, golden-report, schema, and policy suites;
- all 14 AddressSanitizer/UndefinedBehaviorSanitizer suites;
- a final deterministic 50,000-case parser-mutation campaign;
- an all-pass 16-check preflight on the target Linux workstation;
- attended schema-4 human/JSON validation;
- a final 4.6-hour unattended watch with 16,593 completed snapshots, no skipped
  scan, no high-priority finding, no integrity or persistence change, no media
  capture, and no dropped evidence;
- exact-archive privacy scanning and a clean-room warning-free build;
- staged installation checks for ownership, permissions, empty public policy,
  and absence of a shipped host baseline.

The clean-room, staged, workspace, and installed optimized binaries all had
SHA-256:

```text
9085bb08fcab412ad80d15e78076b6edf77d2d6e483bf0eb73f2f3babb97c1ef
```

## Requirements

Nightwatch targets a systemd-based Linux host and has its strongest validation
on Ubuntu. It requires a C++17 compiler and GNU Make to build. Runtime
collection uses `modinfo`, `bpftool`, `pw-cli`, `journalctl`, and `loginctl`.

On Ubuntu or Debian:

```bash
sudo apt update
sudo apt install build-essential bpftool kmod pipewire-bin
```

Optional JSON inspection:

```bash
sudo apt install jq
```

Package names may differ on other distributions.

## Build and test

```bash
tar -xzf nightwatch-0.1.0.tar.gz
cd nightwatch-0.1.0
make
make test
```

Optional sanitizer validation:

```bash
make sanitize
```

## Install

Install the binary and create the protected system directories:

```bash
sudo make install
```

On a **brand-new Nightwatch installation only**, install the empty reviewed-
fingerprint template:

```bash
sudo make install-reviewed
```

Do not run `install-reviewed` during an upgrade. It intentionally installs the
empty public template and would replace an existing locally curated reviewed
database. Ordinary `sudo make install` preserves that database.

The standard layout is:

```text
/usr/local/sbin/nightwatch
/etc/nightwatch/
/var/lib/nightwatch/
/var/log/nightwatch/
```

## Calibrate and monitor

Inspect the current machine before calibration. Calibration records expected
state; it does not prove that the state is benign.

```bash
sudo /usr/local/sbin/nightwatch calibrate
sudo /usr/local/sbin/nightwatch preflight
sudo /usr/local/sbin/nightwatch monitor
```

During calibration, leave the computer ordinarily idle for the first phase,
then intentionally exercise the expected microphone and webcam behavior during
the prompted media phase. Proceed to monitoring only when preflight reports:

```text
Result: READY for an unattended watch.
```

Leave Nightwatch running in the foreground and press Ctrl-C when the watch is
finished. It prints the paths of the finalized text and JSON reports under
`/var/log/nightwatch`.

Reports can contain sensitive usernames, command lines, paths, and network
context. Review and sanitize them before sharing screenshots or excerpts.

## Important limitations

Nightwatch is a heuristic observation tool, not proof that a computer is clean.

- Sampling can miss activity shorter than the configured interval.
- PipeWire attribution depends on properties exposed by the active graph.
- Network namespaces and unconnected UDP can reduce attribution coverage.
- Authentication evidence depends on journal retention and session-state
  availability.
- Calibration can normalize malware already present on the host.
- A root or kernel attacker may hide activity, alter the monitor, or tamper with
  its evidence.

Nightwatch reports unknown or unavailable evidence instead of silently treating
it as clean.

## Documentation

The source archive includes the full manual, judge-facing project page, threat
model, design document, release checklist, demonstration plan, tests, and safe
synthetic fixtures.

Nightwatch v0.1.0 is available under the [MIT License](LICENSE).
