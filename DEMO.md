# Nightwatch judge demonstration

This is a Phase 3 submission artifact. Do not capture final screenshots or
record the final video until the feature freeze and Phase 2 validation in
`RELEASE-CHECKLIST.md` are complete. Draft rehearsals are fine, but they should
not be mistaken for frozen-build evidence.

This flow demonstrates the frozen release without exposing a developer home
directory or private host evidence. Use a prepared machine whose calibration
has already completed successfully.

## Before recording

1. Confirm the installed binary is the frozen candidate.
2. Run `sudo /usr/local/sbin/nightwatch preflight` and require 11 passes with
   no warning or failure.
3. Close unrelated terminals, reports, and applications that contain private
   information.
4. Use only a synthetic or manually sanitized sample report in repository and
   presentation material.

## Short demonstration flow

```bash
sudo /usr/local/sbin/nightwatch preflight
sudo /usr/local/sbin/nightwatch monitor
```

While monitoring, briefly create one deliberate, explainable observation if a
finding is needed for the presentation. Press Ctrl-C once, then show:

- the overall assurance conclusion;
- **What went well**;
- **What needs attention**, including rationale and recommended follow-up;
- per-domain verification status;
- monitoring-degradation and retention summaries;
- the matching schema-versioned JSON report.

Do not display the real baseline, reviewed database, network endpoints, user
home paths, process command lines, hostname, or unsanitized overnight reports.

## Nine screenshot plan

1. Project title and one-sentence purpose.
2. Main feature overview.
3. Threat-model and passive-operation boundary.
4. Calibration completion using system paths.
5. All-pass preflight result.
6. Monitor running in the foreground.
7. Final assurance summary and **What went well**.
8. Prioritized finding with rationale and recommended follow-up.
9. JSON evidence, test suite, or architecture data flow.

Crop screenshots to the relevant terminal or document region and inspect every
visible path, username, hostname, address, timestamp, and application name
before publication.
