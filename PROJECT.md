# Nightwatch

## Inspiration

Nightwatch began with a practical question: can a personal Linux computer
watch for suspicious activity while its owner is asleep, without making risky
or destructive changes to the system? The goal was to build an understandable,
host-specific monitor that runs in the foreground until Ctrl-C, records what
happened, and highlights behavior worth investigating.

## What it does

Nightwatch is a baseline-driven Linux security monitor. It observes processes,
executables, interpreter-launched scripts, direct microphone and webcam device
access, PipeWire capture streams, network sockets, kernel security posture,
loaded kernel modules, BPF programs, common persistence mechanisms, and
authentication/login-session evidence.

A calibration period creates a protected fingerprinted model of the computer's
expected state and normal behavior. During a watch, Nightwatch compares live
observations with that baseline and produces explainable `NOTICE` and `HIGH`
findings. It runs passively: it does not terminate processes, block devices,
load modules, or alter network and security settings. When stopped, it prints
and securely saves a detailed report.

## How we built it

Nightwatch is written in C++17 and builds with GNU Make without third-party C++
libraries. It collects process, file-descriptor, socket, and kernel information
from Linux `/proc` and sysfs. It uses `pw-cli` for PipeWire client attribution,
`modinfo` for kernel-module metadata, `bpftool` for root-only BPF inventory,
and bounded `journalctl`/`loginctl` access for authentication and session state.

The protected version-6 baseline stores SHA-256 hashes and security metadata
for executables, scripts, and kernel modules, along with calibrated media,
network, kernel-posture, and stable BPF identities. Reports and recovery
journals are created with restrictive permissions and updated durably during a
run. Parsing, fingerprint comparison, classification, and state transitions are
covered by automated tests using safe synthetic data rather than loading real
modules or executing untrusted samples.

## Challenges we ran into

Linux desktop activity is noisy and highly dynamic. Short-lived system helpers,
Snap refreshes, browser UDP behavior, Discord traffic, PipeWire routing, and
volatile BPF program IDs can resemble suspicious changes without additional
context. We had to distinguish a meaningful security signal from ordinary
system lifecycle events without broadly trusting executable paths.

Other challenges included safely fingerprinting processes that can disappear
mid-scan, preventing repeated expensive hashing, preserving useful reports
after interruptions, normalizing network behavior without trusting remote IP
addresses, recognizing interpreter script entrypoints, and keeping monitoring
close to its requested one-second cadence. Root execution also required strict
ownership, permission, file-size, symlink, timeout, and output-limit checks.

## Accomplishments that we're proud of

- Built an explainable, read-only monitor that has completed multiple attended
  and unattended target-system validations on a Dell Latitude 5400.
- Added exact reviewed-executable fingerprints rather than a path-only allow
  list, including detection of changed binaries after package updates.
- Implemented script-entrypoint integrity monitoring to close the gap between a
  trusted interpreter and the code it actually launches.
- Attributed TCP, UDP, raw, and packet sockets to processes while grouping
  volatile connections into stable behavior patterns.
- Added kernel-posture, loaded-module, and stable BPF-program monitoring with a
  protected version-6 baseline.
- Completed a 28-minute normal-use validation with 1,589 snapshots, no skipped
  snapshots, and no kernel/BPF or file-integrity findings.
- Maintained automated regression tests while refining real findings from
  overnight and normal-use reports.
- Added typed assurance reporting that leads with an overall conclusion,
  per-domain verification status, what went well, prioritized follow-up, and
  complete supporting evidence.
- Added golden complete-report fixtures plus isolated AddressSanitizer and
  UndefinedBehaviorSanitizer builds for all 14 automated test suites.
- Added an independently versioned, protected JSON assurance report beside the
  human report for reliable tooling, comparisons, and hackathon demonstrations.
- Added explicit limits for findings, degradations, media, PipeWire, network,
  and recovery-journal evidence. Any exhaustion becomes a visible monitoring
  degradation with exact retained and dropped counts in both reports.
- Added reproducible sanitizer-backed mutation fuzzing for exposed network,
  kernel/helper-output, and interpreter-argument parsers; the first 200,000
  distinct malformed cases completed without a memory-safety or undefined-
  behavior finding.
- Completed persistence and authentication/session monitoring with explicit
  unknown/degraded states, independently versioned schema-4 JSON evidence, an
  all-pass 16-check preflight, and a clean 687-snapshot target-host validation.

## What we learned

A useful heuristic monitor needs context more than it needs a large number of
alerts. Exact hashes and security metadata make trust decisions safer, but
lifecycle, timing, and attribution are equally important. A short-lived process
may disappear before it can be fingerprinted; a browser may legitimately hold
an ephemeral UDP socket; and many BPF program IDs may reduce to a smaller set of
stable code identities.

We also learned that calibration describes a known host state—it does not prove
that the state is clean. Findings must remain explainable, reports must preserve
the evidence needed for investigation, and limitations must be stated clearly.
Repeated real-world validation was essential for finding performance issues,
classification edge cases, and integrity gaps that isolated unit tests would
not have revealed.

## What's next for Nightwatch

The July 16-17 4.5-hour text/JSON validation found no high-concern, integrity,
or media-capture activity and exposed one reporting gap: successful scans could
overrun their requested cadence without being counted as skipped. Schema-2
reports now measure monotonic duration, deadline overruns, maximum scan time,
and collector/policy phase timing. A subsequent 857-second attended watch
completed 858 snapshots with zero overruns or degradations and a 772 ms
slowest scan, validating the new cadence model on the target workstation. Its
scheduled Ubuntu Pro timer was package- and systemd-verified and added as an
exact reviewed-script fingerprint, bringing the protected database to 23
executables and eight scripts without requiring recalibration.

Nightwatch now has one hardened external-process boundary for `modinfo`,
`bpftool`, and privilege-dropped `pw-cli`. It validates helpers, controls their
environment and descriptors, bounds time/output, terminates process groups,
and returns typed failures. Eleven optimized and sanitizer suites, 50,000 new
parser mutations, and a 12-second staged root watch passed; batched module
metadata collection kept the slowest scan to 392 ms with zero overruns.

The first resource-budget slice is also installed and root-smoke-validated.
JSON schema 4 carries the schema-3 retained/limit/dropped evidence accounting
plus typed authentication-source status, active sessions, and authentication
events. A 65-second persistence validation completed 66 snapshots with
zero omitted records or monitoring degradation.

A following 35-minute noisy attended run retained all 36 findings, three
degradations, 33 direct-media sessions, one intentional Firefox microphone
session, and 379 network sessions with zero dropped evidence. Nightwatch
correctly separated owner-launched applications and an authorized Ubuntu
maintenance transaction from integrity, kernel, BPF, and retention health.

The release layout removes developer-specific paths from normal operation. An
installed Nightwatch now keeps protected configuration in `/etc/nightwatch`,
host state in `/var/lib/nightwatch`, and reports in `/var/log/nightwatch`, so
calibration, preflight, and monitoring can be launched from any directory.

The July 2026 OpenAI Hackathon feature set is frozen after fresh target
calibration, an all-pass 16-check preflight, attended human/schema-4 JSON
validation, and a final 4.6-hour unattended watch. Persistence coverage includes
systemd units, scheduled tasks, autostart and login/startup entries;
authentication evidence covers session start/end, failed authentication, and
reliable lock/unlock transitions with explicit unavailable/truncated state. The
deterministic `0.1.0` archive, privacy review, clean-room build/tests, sanitizer
suites, and staged installation are complete. The immediate work is repository
publication plus the hackathon screenshots and demonstration. Post-hackathon plans include
independent BPF attachment-site inventory, raw-observation JSON extensions,
report signing, optional systemd service integration, and privilege separation.

Longer term, Nightwatch could add configurable policies and carefully reviewed
response options while preserving its current strengths: passive operation,
host-specific fingerprints, clear evidence, and conservative trust decisions.
