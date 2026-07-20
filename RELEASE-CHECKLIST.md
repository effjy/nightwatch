# Nightwatch release checklist

This checklist records the completed, phase-gated path to the submitted
Nightwatch `v0.1.0` hackathon release. The earlier `0.1.0-rc1` work below was a
packaging rehearsal that validated the process and found defects; the final
hashes, calibration, long-watch evidence, privacy scans, screenshots, video,
publication, and submission were completed afterward.

## Phase 1 — Development (complete)

- [x] Define the exact feature scope required for the hackathon release:
      persistence plus narrow authentication/session evidence, then freeze.
- [x] Finish only those in-scope milestones; keep longer-term items documented
      as roadmap work rather than delaying the release indefinitely.
- [x] Continue attended and unattended watches when they provide engineering
      feedback, but do not treat their hashes or screenshots as final evidence.
- [x] Keep optimized and sanitizer tests passing after each implementation slice.
- [x] Resolve release-blocking bugs and documentation inaccuracies.
- [x] Add the MIT License.
- [x] Declare feature freeze; after this point, any build-affecting change
      restarts Phase 2 validation.

### Current must-ship implementation checkpoint

- [x] Implement bounded journal and systemd-logind session collection.
- [x] Cover session/login start and end, failed authentication, and reliable
      lock/unlock transitions with available user/session/source context.
- [x] Preserve explicit unavailable, malformed, missing-lock-state, helper-
      output, and retention-limit degradation semantics.
- [x] Add normal, false-positive, malformed, unavailable, truncation, golden
      report, schema-4 JSON, sanitizer, and mutation-parser coverage.
- [x] Pass all 14 optimized and 14 ASan/UBSan suites.
- [x] Complete an isolated 25-second root smoke with journal/session sources
      verified and valid schema-4 JSON.
- [x] Install the exact optimized candidate; source and installed SHA-256 are
      `9085bb08fcab412ad80d15e78076b6edf77d2d6e483bf0eb73f2f3babb97c1ef`.
- [x] Recalibrate the active host with the installed candidate.
- [x] Require the expanded preflight to pass without warning or failure.
- [x] Complete and inspect one short attended text/JSON watch.
- [x] Declare feature freeze immediately after that validation passed.

## Packaging rehearsal already completed

- [x] Explicit allow-list archive and SHA-256 sidecar generated reproducibly.
- [x] Real baselines, reports, reviewed policy, binaries, local shortcuts, and
      conversation state excluded.
- [x] Targeted identifier, network-context, credential, key, and token scan
      passed.
- [x] Clean archive extraction compiled and passed all 12 optimized suites.
- [x] Staged root installation produced the intended protected system layout,
      empty reviewed-policy template, and no baseline.
- [x] The rehearsal exposed and fixed a private reviewed-database test dependency
      and insecure source-template permissions.
- [x] Installed binary, active baseline, and private reviewed database remained
      unchanged.

## Phase 2 — After feature freeze (complete)

### Frozen build

- [x] Record and compare the final source and installed binary SHA-256 values.
- [x] Run all optimized and ASan/UBSan suites on the frozen source.
- [x] Run the final deterministic parser-fuzz campaign.
- [x] Generate the final versioned archive and checksum.
- [x] Extract the exact archive into a clean directory and run `make test`.
- [x] Stage `make install install-reviewed` with `DESTDIR` and inspect the full
      installed layout and permissions.

### Final host validation

- [x] Install and calibrate the frozen binary under the standard system layout.
- [x] Require an all-pass preflight from outside the source checkout.
- [x] Complete a short attended validation.
- [x] Complete the final multi-hour unattended validation.
- [x] Confirm text and JSON reports are mode `0600`, evidence is not dropped,
      and the recovery journal is removed after clean finalization.
- [x] Classify every final finding and degradation without silently trusting it.

### Final privacy review

- [x] Inspect the complete archive file list.
- [x] Confirm `config/`, `reports/`, private reviewed policy, local shortcuts,
      binaries, objects, build directories, and conversation state are absent.
- [x] Search the exact final archive for home paths, usernames, hostnames,
      addresses, credentials, tokens, conversation identifiers, and raw reports.
- [x] Confirm the reviewed database is the empty public template.
- [x] Prepare only synthetic or manually sanitized sample evidence; no real
      host report is included in the release archive.

## Phase 3 — Submission (complete)

- [x] Confirm the intended `effjy/nightwatch` repository link.
- [x] Confirm README/GitHub presentation rendering and all documentation links.
- [x] Capture the nine reviewed screenshots in `DEMO.md` from the frozen build.
- [x] Record the final demonstration only from publication-safe material.
- [x] Assemble, upload, and review the final video.
- [x] Upload the exact frozen archive and checksum used for validation.
- [x] Perform one final repository-visible-file and privacy review before making
      the repository available to judges.
- [x] Verify the repository, release page, archive download, checksum, and video
      while signed out.
- [x] Confirm the final submission text and intended YouTube URL.
- [x] Confirm no private information is exposed in the public materials.
- [x] Click the final hackathon **Submit** action on July 20.
- [x] Preserve the submission confirmation page or email.

Submission was completed successfully on July 20, 2026, and the confirmation
email was received and preserved. The hackathon release phase is complete.
