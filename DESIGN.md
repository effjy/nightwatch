# Nightwatch design

## Status

This document defines the target internal boundaries for the Milestone 5A
refactor. It is not a claim that every interface below already exists.

Current code has separate fingerprint, network, script, kernel, persistence,
authentication/session, reviewed-file, and preflight modules, but `Monitor` still coordinates collection, policy,
state, baseline comparison, helper use, journaling, and reporting. Refactoring
must preserve current behavior with tests while the architecture evolves.

The installed storage boundary is already explicit: reviewed policy records
live under `/etc/nightwatch`, host calibration state under `/var/lib/nightwatch`,
and session evidence under `/var/log/nightwatch`. These defaults are centralized
in one path contract and remain independently overridable at the CLI boundary.

## Architectural invariants

- Collectors observe; they do not assign security severity.
- Policy owns classification, severity, rationale, and remediation metadata.
- Reporters consume typed results without knowing collector internals.
- Missing or truncated evidence is never equivalent to clean evidence.
- Baselines and reviewed records authorize only exact documented identities.
- A previous monitoring session never authorizes future behavior.
- External helpers are invoked only through one controlled abstraction.
- Every resource ceiling is visible when crossed.
- Raw evidence remains available beneath summaries.
- The foreground monitor remains passive.

## Data flow

```text
collectors
    |
    v
immutable typed observations
    |
    +----> baseline/review stores
    |
    v
policy engine
    |
    +----> typed findings
    +----> per-domain verification state
    +----> degradations
    |
    v
session result
    |
    +----> recovery journal
    +----> human report
    +----> versioned JSON report (schema v4 implemented)
```

## Proposed core types

Names may change during implementation, but responsibilities should not.

```cpp
enum class VerificationState {
    verified,
    finding_detected,
    unknown,
};

enum class FindingPriority {
    notice,
    high,
};

struct ObservationId;
struct Observation;
struct Finding;
struct Degradation;
struct DomainStatus;
struct SessionMetadata;
struct SessionResult;
```

`Observation` should be an immutable value containing:

- collector/domain identity;
- observation timestamp from the collection boundary;
- stable subject identity;
- typed payload;
- source and namespace context;
- optional evidence references.

`Finding` should contain:

- stable rule identifier;
- priority;
- title and rationale;
- aggregation key;
- first/last occurrence and count;
- related observation identifiers;
- recommended next check;
- policy-version metadata.

`Degradation` should contain:

- affected domain or whole-session scope;
- immediate timestamp;
- reason code;
- dropped/truncated count where applicable;
- whether verification can continue;
- final accumulated impact.

`DomainStatus` should retain an independent state for executable, script,
media, PipeWire, network, kernel posture, module, BPF, authentication/session,
helper, sampling, retention, journal, and reporting domains.

## Interfaces

```cpp
class Collector {
public:
    virtual CollectionBatch collect(const CollectionContext&) = 0;
};

class PolicyEngine {
public:
    virtual PolicyBatch evaluate(
        const CollectionBatch&,
        const BaselineView&,
        const ReviewedView&) = 0;
};

class Reporter {
public:
    virtual void begin(const SessionMetadata&) = 0;
    virtual void append(const SessionEvent&) = 0;
    virtual void finish(const SessionResult&) = 0;
};

class BaselineStore;
class ReviewedStore;
class HelperRunner;
class ResourceBudget;
```

The first refactor should introduce value types and adapter interfaces around
existing behavior. It should not simultaneously rewrite every collector.

## Timestamp ownership and ordering

- Collectors own observation timestamps because they know when state was read.
- Policy owns finding first/last times derived from observations.
- Reporters must not create event timestamps except for reporter-local
  operational failures.
- A monotonic clock controls intervals, timeouts, and duration.
- Wall-clock time is presentation metadata and evidence correlation.
- Events should carry a monotonically increasing session sequence number so
  ordering survives equal or adjusted wall-clock timestamps.

## Identity and deduplication

Deduplication must use typed stable identities, not rendered strings.

Examples:

- process: PID plus process start ticks;
- executable/script: normalized absolute path plus verified fingerprint state;
- media session: process identity plus device or PipeWire node identity;
- network pattern: executable plus normalized protocol/role/scope/ports;
- module: module name plus file fingerprint;
- BPF: normalized type/name/tag/owner, later attachment identity.

Policy should aggregate repeated findings using rule-defined keys. Reporters
may format aggregates but must not decide that two findings are equivalent.

## Stateful policy

Some rules require state across samples:

- first observation versus continuation;
- persistent versus transient network binds;
- changed fingerprints and periodic rechecks;
- media session start/end;
- module/BPF lifecycle;
- resource limit first-crossed and final dropped count.

State belongs to a policy/session state object, not to presentation code.
Collectors may retain only collection mechanics such as parser caches or open
descriptors.

## Unknown and degraded state

Unknown can attach to an individual check, a domain, or the whole session.

Examples:

- `pw-cli` unavailable: PipeWire attribution unknown, executable integrity still
  verified;
- one skipped `/proc` snapshot: sampling degraded, later snapshots continue;
- BPF helper timeout: BPF domain unknown;
- report/journal write failure: evidence integrity may make the session
  inconclusive.

Resource exhaustion should create:

1. one immediate degradation when the limit is first crossed;
2. a final summary with the total dropped or truncated records.

## Baseline and reviewed stores

Baseline format versions and report schema versions are independent.

The baseline store owns:

- protected file opening and size limits;
- format parsing and compatibility;
- host binding;
- atomic durable replacement;
- typed baseline views.

The reviewed store owns:

- protected file opening and size limits;
- exact executable and script fingerprint records;
- format compatibility;
- review reasons;
- no implicit path-only approval.

Neither store assigns finding severity.

## Helper runner

`HelperRunner` is now the sole external-process boundary for `bpftool`,
`modinfo`, `pw-cli`, `journalctl`, and `loginctl`. A request specifies:

- fixed validated executable identity;
- argument vector without shell interpretation;
- controlled environment;
- target UID/GID and allowed privileges;
- timeout;
- stdout/stderr limits;
- a zero-exit success policy.

A result contains separately captured stdout/stderr under one combined ceiling,
the resolved executable path, exit or signal status, elapsed time, and a typed
failure reason. The runner validates absolute paths, root ownership, execute
permissions, and group/world writability; constructs a minimal environment;
closes inherited descriptors; sends standard input to `/dev/null`; optionally
drops UID/GID and supplementary groups; and terminates the entire helper
process group on timeout or exhaustion. Helper failure flows into PipeWire,
module, BPF, authentication/session, or preflight degraded-state reporting.

`modinfo` is invoked once with the bounded loaded-module name set rather than
once per module. Its batch parser separates records by `filename:` and indexes
them by the validated `name:` field. This preserved the controlled helper
boundary while reducing the target system's first kernel/BPF policy scan from
2.62 seconds in the initial migration to 288 ms in the corrected integration
test.

## Preflight

The implemented `preflight` command is the first assurance boundary. It is
read-only and reports:

- privilege level;
- running binary ownership/mode;
- baseline protection, version, host, binary fingerprint, and kernel release;
- reviewed-file protection and record counts;
- report-directory safety;
- fixed helper availability and ownership/mode;
- whether root and validated `bpftool` are available for BPF inventory.
- validated `journalctl`/`loginctl` identities plus live journal-cursor and
  session-state access.

Statuses are:

- `PASS`: the check completed and met the requirement;
- `WARN`: monitoring can run but assurance is degraded;
- `FAIL`: do not begin an unattended watch.

Exit codes are `0` for ready, `3` for degraded, `1` for not ready, and `2` for
command-line usage errors.

Preflight does not prove calibration cleanliness or kernel integrity. Its live
`bpftool prog show` capability probe now uses the unified helper runner and
therefore exercises the same executable validation, environment, timeout,
output ceiling, and exit-status boundary as monitoring.

## Reporting target

The final `SessionResult` should deterministically derive:

1. overall conclusion;
2. what went well by domain;
3. prioritized items requiring attention;
4. monitoring degradations and confidence;
5. complete evidence appendix.

Golden tests cover clean, finding-bearing, partially verified, and
inconclusive human reports. The implemented JSON reporter independently emits
schema name `nightwatch.report`, version 4, with session metadata, conclusion,
domain states, correlated finding groups, findings, and degradations. Stable
machine identifiers are separate from display labels. Raw socket and media
observations remain a future schema extension rather than being inferred from
rendered human-report text. Version 2 adds monotonic and wall-clock duration,
explicit deadline-overrun accounting, maximum scan latency, and per-phase
collector/policy timing. Material cadence loss creates a sampling-domain
degradation; minor scheduler jitter remains visible without changing the
session conclusion. Version 3 adds typed evidence-retention and recovery-
journal budget accounting. Version 4 adds typed journal/session-source status,
active login sessions, authentication events, and their retention budget. An
857-second target-system validation completed 858
snapshots with zero overruns or degradations; its 772 ms slowest scan remained
inside the configured one-second interval.

A later 7,934-second helper-boundary validation completed 7,926 snapshots with
zero failed scans but exposed about eight seconds of accumulated sleep
overshoot. The monitor had calculated an absolute deadline from each cycle's
actual start, so a late wake-up became the origin for the following deadline.
The schedule is now anchored once at session start and advanced by exactly one
configured interval after every attempted snapshot. A 65-second root smoke
test of the corrected build completed 66 snapshots in 64 monotonic seconds
with zero failed scans, cadence overruns, helper failures, or monitoring
degradations. The target was subsequently recalibrated with the exact installed
binary; all 11 preflight checks passed with no warning or failure.

The first explicit resource-budget slice is implemented. Findings, unique
degradations, direct-media sessions, PipeWire sessions, network sessions,
authentication/session events, and
recovery-journal growth have fixed ceilings. The first crossing creates an
immediate retention-domain degradation, continued omitted sessions are not
counted once per sampling cycle, and final retained, limit, and dropped counts
appear in both reports. A reserved journal region preserves one final
exhaustion marker. Eleven optimized and sanitizer suites pass; a 65-second
root integration produced 66 snapshots and zero omitted records.
The exact installed resource-budget binary was then captured in a new
version-5 baseline; all 11 target preflight checks passed with no warning or
failure.

A subsequent 2,078-second noisy normal-use validation produced 2,080
snapshots, 36 fully attributed findings, three visible degradations, 33 direct-
media sessions, one intentional PipeWire microphone session, and 379 network
sessions. Every bounded category reported zero dropped records; the journal
used 104,232 bytes and finalized cleanly. This validates normal-path accounting
and report integration, while synthetic boundary tests validate first-crossing
and omission behavior without generating tens of thousands of live events.
A following 838-second quiet unattended control completed 840 snapshots with
zero failed scans, cadence overruns, security findings, captures, or dropped
records. Its sole degradation was a package- and fingerprint-verified
short-lived `timedatectl` race.

## Privilege separation

The future privileged component should be small and limited to collection that
requires root. It should transmit bounded typed observations to an
unprivileged policy/reporting process. Baseline policy, aggregation, report
formatting, and most parser logic should not remain in the privileged process.

This is a later phase. The current foreground program remains one root process,
and the refactor must not falsely imply otherwise.

## Refactor sequence

1. Preserve behavior with golden report and baseline fixtures.
2. **Implemented:** introduce verification, finding, degradation, and session
   value types, with a compatibility adapter for existing alert producers.
3. Extract baseline/review stores.
4. **Implemented:** introduce the unified helper runner, migrate `modinfo`,
   `bpftool`, `pw-cli`, and the BPF preflight probe, then batch module metadata
   collection to preserve cadence.
5. Move collectors one domain at a time behind typed interfaces.
6. Centralize policy and domain verification state.
7. **First version implemented:** add deterministic outcome-driven human
   reporting with rule metadata, safe classifications, correlated narrative,
   verified-domain results, recommended follow-up, and conservative
   Ubuntu-maintenance-chain aggregation—including a guarded kernel
   post-install extension—that preserves raw member findings.
8. **Implemented:** add independently versioned JSON schema-4 assurance output
   beside the human report, including protected reservation, an in-progress
   stub, synchronized finalization, and explicit degradation on write failure.
9. **Partially implemented:** all test suites have isolated sanitizer builds,
   and a deterministic sanitizer-backed mutation target covers exposed network,
   process-argument, authentication journal/session, module, lockdown,
   `modinfo`, and `bpftool` parsers with
   reproducible cases. The first evidence and journal resource budgets are
   implemented; process/supporting-state ceilings, coverage-guided fuzzing, and
   baseline/review/PipeWire parser targets remain.
10. Design and implement privilege separation.

## Authentication/session collector boundary

The implemented hackathon slice intentionally has two independent sources:

- incremental `journalctl` JSON records begin at a cursor established after
  Nightwatch starts and provide systemd-logind session lifecycle, SSH login
  source when present, and failed PAM/SSH authentication evidence;
- sampled `loginctl` state provides active session identity, user/UID, seat,
  TTY, remote host, state, and `LockedHint` transitions where logind exposes
  them reliably.

The collector emits typed `AuthenticationEvent` and `LoginSession` values.
Policy alone turns session starts, failed authentication, and unlocks into
review findings; session ends and locks remain evidence. Existing sessions are
captured as startup state and do not become findings. Journal and session-state
availability are tracked separately. Helper failure, malformed journal JSON,
missing reliable lock state, a 4 MiB helper-output limit, more than 4,096 events
in one batch, or the 4,096-event session-retention ceiling creates an explicit
authentication-domain degradation. If journal collection fails and later
recovers, the coverage gap remains visible for the final session conclusion.

The parser is bounded, uses no third-party JSON dependency, and is exercised by
normal, malformed, truncation, false-positive, report/JSON, sanitizer, and
mutation tests. It does not claim forensic completeness across journal rotation,
disabled logging, unexposed desktop lock state, or events hidden by a compromised
kernel/root environment.

Target acceptance used a fresh baseline matching the exact installed candidate.
All 16 expanded preflight checks passed, including live journal-cursor and
systemd-logind session access. A subsequent 685-second attended run completed
687 snapshots with zero skips, cadence overruns, degradations, malformed or
truncated authentication input, and dropped evidence. Both authentication
sources remained available, active-session/lock state rendered in schema 4,
and every unrelated assurance domain remained verified. Together with the
fixture, golden-report, mutation, and sanitizer coverage, this completed the
hackathon authentication/session slice and established the feature-freeze gate.

Further hardening should preserve these boundaries rather than broadening the
hackathon detection scope.
