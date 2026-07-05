# Sift Improvement Suggestions (formerly Flock-It)

Last reviewed: 2026-07-02
Reviewed from: current working tree, static review plus localhost flow run

This backlog is ordered by risk and practical impact. Line references point to the reviewed working tree — `flockit.py`/`modules/raven.py`/`modules/owl.py`/`modules/magpie.py`/`modules/kea.py` in the citations below refer to files that have since been renamed to `sift.py`/`modules/scanner.py`/`modules/reporter.py`/`modules/plugin_manager.py`/`modules/ai_prompts.py` respectively (see `docs/DESIGN.md`); the citations are left as-is since they're historical evidence, not current paths.

## Discovery Questionnaire

Use this section to capture product, workflow, feature, and integration ideas before turning them into prioritized improvements. Answer inline under each question.

### Core Purpose

1. What do you see as the main job of this tool today?
   - Answer: I see the main job of this tool is to help automate network penetration testing, internal and external specifically
2. Who is the primary user: you, your team, customers, admins, or multiple roles?
   - Answer: I'll be the primary user.
3. What is the most common task someone uses it for?
   - Answer: Network and port scanning
4. What part of the current experience feels slow, clunky, or unclear?
   - Answer: So far it just feels very simple
5. If the tool could do one thing dramatically better, what would it be?
   - Answer: I'd like the tool to be able to scan every port / service and perform tests as associated to it, including gathering evidence.

### Features

6. Are there any manual tasks you repeatedly do outside the tool that should be brought into it?
   - Answer: Mostly gathering evidence of the findings / vulnerabilities
7. What information do you wish the tool surfaced automatically?
   - Answer: I'd like the tool to be able to scan open ports, check for findings and gather evidence, and when in a specific mode, it could attempt to perform exploits
8. Are there workflows that need templates, presets, saved views, or bulk actions?
   - Answer: I think a template for report generation would be worth it; typically for a finding we use, Name, Description, Impact, Recommendation, CVSSv4 vector.
9. Should the tool support notifications, reminders, or alerts?
   - Answer: Notifications and alerts would be very useful, this can include notifications via web hooks
10. Would reporting, analytics, dashboards, or exports be useful?
    - Answer: I think all those would be useful, however reporting and analytics I'd say are very important.

### Integrations

11. What other tools or services do you already use alongside this?
    - Answer: I'd typically use Nessus Pro, so intergration to the API might be useful, for example I could use Nessus to do the initial scan, then this tool can monitor that scan and once it's completed, the tool can export the scan results and parse it and utilse it for the scanning phase.
12. Are there systems it should read data from?
    - Answer: No systems currently
13. Are there systems it should write, sync, or push data to?
    - Answer: No systems currently, ideally keep it local.
14. Would calendar, email, Slack/Discord, CRM, accounting, maps, payments, or file storage integrations help?
    - Answer: None of those intergration would work.
15. Do you need API access, webhooks, or automations for third-party systems?
    - Answer: API for Nessus, webhooks for other systems can be useful

### Collaboration

16. Does the tool need multiple users?
    - Answer: For now, a single user
17. Should different users have different permissions or roles?
    - Answer: Nope, if it's single user, have full access
18. Do people need comments, assignments, approval flows, or activity history?
    - Answer: Not needed
19. Should users be able to share records, links, reports, or views?
    - Answer: Not applicable
20. Do you need audit logs or accountability around changes?
    - Answer: Logs of what has happened should always be kept

### Data And Search

21. What data matters most in the tool?
    - Answer: Positive findings and valid vulnerabilites
22. Is anything currently hard to find?
    - Answer: No
23. Would better filtering, tagging, sorting, or saved searches help?
    - Answer: Yes, this can help.
24. Do you need import/export from CSV, Excel, PDF, or another format?
    - Answer: Export CSV/Excel is always useful
25. Are there any data quality problems, duplicates, missing fields, or inconsistent naming?
    - Answer: Not applicable

### User Experience

26. What screen do users spend the most time on?
    - Answer: Currently the terminal to watch it flow
27. What screen causes the most confusion?
    - Answer: Not applicable
28. Should the tool feel more like a dashboard, spreadsheet, calendar, kanban board, map, form system, or something else?
    - Answer: I'm happy to keep it mostly a cli dashboard.
29. What should be possible from mobile?
    - Answer: Only notifications through webhooks at the users decision.
30. Are there any accessibility or readability issues?
    - Answer: No issues

### Automation And AI

31. What decisions or recommendations could the tool help with?
    - Answer: It could help process large amounts of findings
32. Are there repetitive steps that could be automated?
    - Answer: Evidence gathering of findings
33. Would AI-assisted summaries, drafting, categorization, search, or anomaly detection be useful?
    - Answer: very useful
34. Should the tool proactively suggest actions?
    - Answer: yes, this would be helpful.
35. Are there places where human approval must always stay in the loop?
    - Answer: Generally any time an exploit is being used, but passive or non-harmful info gathering should be OK

### Business And Operational Goals

36. What outcome would make this tool feel 2x better?
    - Answer: It would be amazing to have this tool essentially automate the scanning phase of a penetration test, gather evidence and suggest actions
37. What outcome would save the most time or money?
    - Answer: Ensuring that scanning is as perfect as possible where it can be left to its own devices while I focus on other tasks
38. What needs to be measured to know improvements are working?
    - Answer: ensure that all ports are scanned, any service detected is checked to ensure if it's a finding, evidence is gathered and if a Nessus export is used, all findings are checked.
39. Are there upcoming business changes the tool should prepare for?
    - Answer: Nope
40. What features would make this feel more professional or scalable?
    - Answer: Ensuring that all actions are smooth, nothing breaks and better organisaion of data.

## Roadmap From Questionnaire

The questionnaire points to a CLI-first, local-first pentest automation tool that should reduce the manual scanning phase of an engagement. The main product goal is:

> Given a scope or Nessus scan, Sift should enumerate every reachable service, run relevant validation checks, gather evidence, organize the results, and produce a report-ready finding set while keeping exploit attempts behind explicit human approval.

### Priority 1 - Evidence-Backed Service Validation

- Build a service validation pipeline that runs after port discovery and before reporting.
- Treat every open port as an evidence target: banner, protocol probe output, screenshots where relevant, raw tool output, and structured observations.
- Expand plugin coverage beyond basic banners into service-specific checks for common ports and protocols.
- Store evidence consistently per host/service/finding, with stable artifact names and labels.
- Make "positive findings" the primary output, separating validated vulnerabilities from informational observations.

Success criteria:

- Every open port has a service record and evidence artifact.
- Every finding has `Name`, `Description`, `Impact`, `Recommendation`, `CVSSv4 vector`, affected assets, and linked evidence.
- Report output can be reviewed without manually hunting through raw scan folders.

### Priority 2 - Full-Port And Adaptive Scan Confidence

- Add a scan profile focused on complete coverage, including all TCP ports and optional UDP profiles.
- Track scan completeness explicitly: target count, discovered host count, scanned port ranges, skipped hosts, failed scans, and retry status.
- Improve adaptive scanning so deeper checks are not only "interesting host" based, but also "service requires follow-up" based.
- Add resumable/retry behavior for interrupted or failed host scans.

Success criteria:

- The tool can prove that all configured ports were scanned.
- Failed or incomplete scan segments are visible in the CLI dashboard and final report.
- A completed run leaves little ambiguity about what was and was not tested.

### Priority 3 - Nessus Pro Integration

- Add Nessus API configuration for local settings, keeping credentials local.
- Support launching or monitoring an existing Nessus scan.
- When a Nessus scan completes, export the results, parse them, and import findings into Sift's data model.
- Use Nessus findings as validation targets: confirm affected hosts/services, gather extra evidence, deduplicate findings, and enrich the report.
- Support importing Nessus exports from disk for offline workflows.

Success criteria:

- Sift can consume a Nessus scan without replacing the local-first workflow.
- Every imported Nessus finding is marked as checked, confirmed, not reproduced, duplicate, or needs manual review.
- Nessus data and Sift-native evidence appear in one coherent report.

### Priority 4 - Reporting, Analytics, And Exports

- Add a configurable report template with the preferred finding structure: `Name`, `Description`, `Impact`, `Recommendation`, and `CVSSv4 vector`.
- Add CSV and Excel exports for findings, affected assets, open services, and scan completeness.
- Add engagement analytics: severity distribution, affected host counts, recurring services, confirmed vs unconfirmed findings, and scan coverage.
- Keep markdown/PDF output, but make the finding model strong enough to support multiple export formats.

Success criteria:

- Findings are report-ready with minimal manual rewriting.
- CSV/Excel exports are useful for review, triage, and client-facing appendices.
- Analytics explain both risk and scan quality.

### Priority 5 - CLI Dashboard And Operator Feedback

- Keep the product primarily CLI-based, but make the run feel more like an operator dashboard.
- Show current phase, active host/service, scan progress, findings count, evidence count, warnings, and failures.
- Add filters and sorting for post-run review: severity, service, host, source, confirmed status, and finding type.
- Preserve detailed logs for every run, including tool commands, decisions, errors, skipped actions, and webhook delivery attempts.

Success criteria:

- The terminal becomes the main control surface, not just scrolling output.
- The operator can quickly tell whether the run is healthy, stuck, incomplete, or finding useful issues.
- Logs are detailed enough to explain what happened after the fact.

### Priority 6 - Notifications And Webhooks

- Add optional webhooks for run start, run complete, confirmed finding, high/critical finding, scan failure, and human approval required.
- Keep webhook configuration local and opt-in.
- Include concise payloads with project, event type, severity, host/service, finding name, and artifact/report path where applicable.

Success criteria:

- Mobile/remote awareness is handled through user-chosen webhook receivers.
- Notifications do not require collaboration features, accounts, or cloud storage.

### Priority 7 - Gated Exploit Mode

- Introduce an explicit mode for exploit attempts, separate from passive and non-harmful validation.
- Require human approval before each exploit attempt or before a clearly defined batch of exploit attempts.
- Record the approval decision, target, module/check used, command/config, result, and evidence.
- Prefer safe validation checks before active exploitation wherever possible.

Success criteria:

- Passive recon and safe validation can run unattended.
- Exploit attempts are deliberate, logged, and easy to exclude from normal runs.
- Reports clearly distinguish exploit-confirmed findings from scanner-detected or safely validated findings.

### Likely Build Order

1. Normalize findings and evidence into a stronger internal data model.
2. Add report templates and CSV/Excel exports on top of that model.
3. Expand service plugins into evidence-backed validation checks.
4. Add scan completeness tracking and resumable host/service tasks.
5. Add Nessus import/export monitoring.
6. Add CLI dashboard improvements and filters.
7. Add webhooks.
8. Add gated exploit mode.

### Implemented From This Roadmap

- Finding records now include report-template fields for `Description`, `Impact`, `Recommendation`, and `CVSSv4 Vector`; deterministic correlation populates the first three fields, and reports render them when present.
- Scan runs now track basic completeness metadata: discovered hosts, successfully scanned hosts, failed hosts, scan arguments used per host, and run notes. Reports include a `Scan Completeness` section.
- The full unittest suite now runs without missing fixture-file errors by making plugin-validator tests self-contained.
- DNS and TLS/HTTPS safe-analysis plugins were added after reviewing `PR00000`; `PR00001` confirmed they produce evidence, and DNS recursion evidence is now promoted into a deterministic finding.
- Report rendering now strips control characters from service/plugin output so binary-ish banners do not make markdown reports unreadable to text tooling.
- Reports now write `findings.csv` and `open_services.csv` beside `report.md` for spreadsheet review and client-facing appendices.

## Live Localhost Flow Evidence

A controlled run was performed with `scope.txt` containing only `127.0.0.1` and project output in `PR_LOCALHOST`.

Observed artifacts:

- Terminal log: `/tmp/flockit-localhost-run.log`
- Report: `PR_LOCALHOST/report.md`
- Preflight XML: `PR_LOCALHOST/scan_results.xml`
- Preflight summary: `PR_LOCALHOST/Pre-Flight-Summary.txt`
- Raw active scan CSV: `PR_LOCALHOST/Scan-Data/127.0.0.1/nmap.csv`

Key observations from the run:

- `127.0.0.1` was classified as external scope, so only `ext_scope.txt` was created.
- Preflight reported `127.0.0.1` as `Not Responded`, because the configured preflight common ports did not include the open localhost service.
- Active scanning found `631/tcp open ipp`, so the preflight status and active scan status disagreed.
- Answering `n` to AI analysis still ran AI analysis, confirming the prompt truthiness bug.
- Answering `y` to viewing the report printed the report and `generate_report()` returned `None`, so the caller printed `None`.
- SMB upload ran at the end and attempted to upload to the configured SMB destination without a visible explicit upload prompt in the captured flow.
- The report links to `Scan-Data/127.0.0.1/banner_631.txt`, but only `nmap.csv` exists for that host because banner grabbing did not save a banner.
- The markdown AI details block is malformed because the fenced code block is not closed before `</details>`.

## Implemented Since Review

The following items have been addressed in the current improvement pass:

- Yes/no prompts now return booleans, so `n` no longer behaves as an affirmative answer.
- `--mode full` is propagated into per-host nmap scans.
- Raven no longer loads plugins twice.
- Active scanning no longer requires Ollama at startup.
- Optional dependencies are lazy-loaded where possible.
- `--scope`, `--no-ai`, `--no-upload`, and `--check-dependencies` were added.
- External IP lookup is cached for the run and reused by preflight checks.
- External IP validation now runs only when external IP scope is present.
- Custom scope files are copied into the project folder.
- Hyphenated domains are no longer treated as IPv4 ranges unless they match the explicit range format.
- SMB upload now requires explicit confirmation or `--auto-upload`.
- Plugin names are de-duplicated and inherited `base_plugin` names fall back to the class name.
- Scan artifacts now carry saved paths so report links do not have to guess filenames.
- AI markdown details blocks now close their fenced code block.

## Implemented in the 2026-07-03 Rebuild

A full staged rebuild (see `docs/DESIGN.md` "Current Architecture") resolved the remaining P0-P2 items below and added four smart-pentesting tracks (adaptive scan orchestration, NVD-backed CVE matching, cross-host correlation, and a quarantine/review workflow for AI-generated plugins). Mapping back to the item numbers below:

- **#1** `AUTO["mode"]` (a bool) was being passed where `prompt_yes_no`'s auto-key argument was expected — fixed, and the automation mechanism itself was later replaced entirely: `AUTO`/`CUSTOM_SETTINGS` globals are gone from `utils/common.py`; `prompt_yes_no(prompt, auto=False)` now takes an explicit bool, and callers pass `ctx.config.automation.<flag>` directly.
- **#2** Settings keys are now normalized through `utils/config.py` dataclasses (`AIProviderConfig`, `SMBConfig`, `CVEConfig`, `AdaptiveScanConfig`) loaded via `Config.load()`. `settings.example.xml` documents the full schema including the new `<CVE>`/`<AdaptiveScan>` blocks.
- **#3** Scan mode now threads through `Scanner` correctly, including a new adaptive two-phase mode (`--scan-mode {quick,full,adaptive}`, default `adaptive`) — see `modules/adaptive.py`.
- **#5** `Reporter.generate_report()` no longer auto-opens the report on any answer; it prints only when the answer (or automation flag) is yes, and does nothing otherwise.
- **#7** Report artifact links are rendered directly from `Artifact` objects returned by `ArtifactStore` (`utils/artifacts.py`) — no more filename guessing.
- **#9** External IP is cached on `ProjectContext.external_ip`; a single `PreFlight.check_external_ip_validity()` path handles fetch/validate with a request timeout.
- **#13/#14/#17** Mutable globals replaced by `Config`/`ProjectContext`/`ArtifactStore`; scan results are typed dataclasses (`PortResult`/`HostResult`/`ScanRun`/`Finding` in `utils/models.py`) instead of loosely-shaped dicts. The old "final filter on malformed results" dict-shape guards in `sift.py` were deleted since the shape is now guaranteed by the type system.
- **#15/#16** Plugin loading is hardened: AI-generated candidates are quarantined (`modules/plugins_quarantine/`) and statically validated (`modules/plugin_validator.py`, AST-based) before an explicit `sift.py plugins approve` can move them into the trusted, auto-loaded directory. The previously divergent generation implementations in `plugin_manager.py` and `ai_prompts.py` are consolidated into one (`ai_prompts.generate_plugin_code`, backed by the new provider-neutral `AIClient`).
- **#18** Test suite expanded from 13 to 59 tests, covering config loading, artifacts, models, adaptive planning, CVE matching (mocked NVD responses + cache-hit verification), cross-host correlation, plugin validation, and the quarantine lifecycle.
- **#19** README rewritten to match the current CLI surface, module breakdown, and plugin review workflow.
- **#21** Reporting quality improved: a ranked "Top Findings" section (deterministic cross-host correlation, optional AI narrative) now leads the report, ahead of per-host detail; CVE matches are rendered as a factual table separate from AI recommendations; preflight-vs-active-scan discrepancies are called out only when they occur.
- **#22** SMB upload confirmation logic carried through unchanged into the new `ProjectContext`-based `PreFlight`.

Not yet addressed (tracked, out of scope for this pass): #20 (no dedicated `--dry-run` flag), #23 (no additional structured logging beyond the per-project `sift.log` now produced via `setup_logging`).

## Implemented in the 2026-07-04 Pass (Webhooks + Active Web Probing)

- **Priority 6 (Webhooks)** — Added an opt-in, local-only `WebhookConfig` (`utils/config.py`) and `WebhookNotifier` (`utils/webhooks.py`), configured via a new `<Webhook>` block in `settings.example.xml`. Events wired into the real run so far: `run_start`, `run_complete`, `high_severity_finding` (critical/high correlation findings), and `scan_failure` (per failed host from `ScanCompleteness.failed_hosts`). `confirmed_finding` and `approval_required` are deliberately not implemented yet — there is no Nessus-style confirmation workflow or runtime auto-plugin-generation call site to hang them off; adding those events now would have no real trigger.
- **#12 (Web scope)** — `web_scope.txt` is no longer preflight/report-only. `PreFlight.get_web_targets()` reads it, and `Scanner.scan_web_targets()` parses each URL's scheme/host/port and runs `http_scan`/`tls_scan` directly against it (no nmap discovery needed since the scheme is already explicit). Results merge into the same `ScanRun.hosts` dict as network targets, so they get CVE matching skip (no version data), correlation, CSV export, and markdown rendering for free. A new deterministic correlation detector, `detect_missing_security_headers`, promotes the plugins' `missing_security_headers` evidence into a `low`-severity finding when a response was actually observed (errors are excluded).
- `sift.py`'s Step 3 now treats network recon and web probing as independent: missing scan dependencies or a "no" to the recon prompt only skips the network portion, it no longer short-circuits web probing (or vice versa).
- Reporter's "Host Artifacts" section used to guess a `Scan-Data/<host>/nmap.csv` link whenever a host had no recorded artifacts (a leftover pre-artifact-refactor fallback); this broke for web-only hosts, which never save that file. Fixed to only render real, saved artifacts.

## Verified Against a Real Run (PR00004, 2026-07-05)

A full `--auto` run against real devices on the local network (two Dropbear-based routers plus `example.com` from `web_scope.txt`) surfaced two pre-existing bugs, now fixed:

- **Duplicate artifacts on escalated hosts** — `Scanner._merge_host_result` used `list.extend()` for both host- and port-level artifacts, so a host that got quick-scanned then adaptively escalated had every artifact (nmap CSV, plugin output, banners) listed twice in the report and `open_services.csv`. Fixed via a new `Scanner._merge_artifacts` helper that dedupes by `Artifact.path` before appending.
- **Raw SSH KEX data leaking into text fields** — `ssh_scan`'s `recv(1024)` after connecting often also captured the start of the binary KEXINIT packet that follows the identification line, and that garbled binary blob then flowed into `escalate_reason`, the report's host heading, and CSV cells. Fixed by keeping only the first line of the response (the actual RFC 4253 identification string).

Also observed, not a code bug: nmap's unprivileged `-sn` host discovery reported 256/256 addresses "up" on a `/24` where the project's own lightweight preflight sweep found only 1/254 truly responsive — a known limitation of ICMP/ARP-less discovery without root. Running nmap with root or `setcap cap_net_raw` would fix discovery accuracy and avoid burning AI-analysis time on phantom hosts.

A re-run (PR00005) confirmed both fixes above, but surfaced a third, related bug: `Scanner.scan_host`/`scan_web_targets` saved every port's plugin output to `{plugin.name}_output.json`/`{plugin.name}_banner.txt` with no port in the filename, so a host with the same plugin running on multiple ports (e.g. `http_scan` on 80 and 8080) had each port silently overwrite the previous port's evidence file on disk, while the report still linked to it from every port as if it were preserved. Fixed by including the port number in the filename (`http_scan_80_output.json`, `http_scan_8080_output.json`, etc.), verified against the same real routers.

## P0 - Correctness and Run-Stopping Issues

### 1. Fix prompt automation return types

Evidence:

- `prompt_yes_no` returns the string `'y'` in auto mode, otherwise raw user input: `utils/common.py:56`.
- Some callers compare to `'y'`, but others use truthiness directly. For example `flockit.py:112` and `flockit.py:133` treat any non-empty string, including `'n'`, as true.

Impact:

- If the operator answers `n` to active testing or AI analysis, the pipeline can still continue because `'n'` is truthy.

Recommendation:

- Change `prompt_yes_no` to return `bool`.
- Update callers to use boolean semantics consistently.
- Keep a separate helper only if raw prompt text is required.

### 2. Make settings keys consistent

Evidence:

- The XML loader returns `OllamaHost` and `OllamaModel`: `utils/common.py:204`.
- `check_ollama` and `ollama_chat` read `ollama_host` and `ollama_model`: `utils/common.py:215` and `utils/common.py:244`.
- `validate_environment` checks `default_ai_provider` and `openai_api_key`, but those keys are not loaded by `load_settings_xml`: `flockit.py:22` and `utils/common.py:195`.

Impact:

- Custom Ollama host/model settings may be ignored.
- AI provider validation may silently not run.
- OpenAI configuration appears partially implemented but not end-to-end.

Recommendation:

- Define a canonical settings schema with lowercase snake_case keys.
- Normalize XML input into that schema once.
- Add defaults for `default_ai_provider`, `ollama_host`, `ollama_model`, `openai_api_key`, and `openai_model`.
- Add a sample `settings.xml` or `settings.example.xml`.

### 3. Preserve selected scan mode

Evidence:

- `scan_network` derives `scan_arguments` from `self.mode`: `modules/raven.py:56`.
- `scan_host` ignores the passed context and always uses `arguments = "-F"`: `modules/raven.py:76` and `modules/raven.py:81`.

Impact:

- `--mode full` does not affect per-host scanning as expected.

Recommendation:

- Rename the `context` parameter to `scan_arguments`.
- Use it in `scanner.scan(host, arguments=scan_arguments)`.
- Add a test or dry-run scanner seam to verify quick/full behavior.

### 4. Remove unconditional Ollama dependency from Raven startup

Evidence:

- `Raven.__init__` calls `check_ollama()` and exits if unavailable: `modules/raven.py:33`.
- AI analysis is optional later: `flockit.py:133`.

Impact:

- Active scanning cannot run without Ollama, even when AI analysis is disabled or OpenAI is configured.

Recommendation:

- Move provider validation to the AI analysis phase.
- Only require Ollama when the selected provider is Ollama and the user opted into AI/plugin generation.

### 5. Fix report viewing behavior

Evidence:

- `Owl.generate_report` asks "Do you want to see the report?": `modules/owl.py:121`.
- If the answer is `y`, it prints the report.
- If the answer is not `y`, it tries to open the report via `xdg-open`/`open`/`os.startfile`: `modules/owl.py:125`.

Impact:

- Saying no to viewing the report still attempts to open it.

Recommendation:

- If answer is yes, open or print based on a separate explicit mode.
- If answer is no, do nothing.
- In automation, make `--auto-view-report` map to the intended behavior.

## P1 - Reliability and Data Integrity

### 6. Avoid duplicate plugin loading

Evidence:

- `Magpie.__init__` calls `self.load_plugins()`: `modules/magpie.py:14`.
- `Raven.__init__` constructs `Magpie()` and then calls `self.plugin_manager.load_plugins()` again: `modules/raven.py:26` and `modules/raven.py:37`.

Impact:

- Plugins are registered twice and can run twice per matching port.

Recommendation:

- Remove the second `load_plugins` call from `Raven.__init__`.
- Add de-duplication by plugin name in `Magpie`.

### 7. Align generated artifact links with saved filenames

Evidence:

- Plugin JSON is saved as `{plugin.name}_output.json`: `modules/raven.py:115`.
- Report artifact links for plugin-like keys point to `{key}_output.txt`: `modules/owl.py:103`.
- Plugin outputs are attached under `port_data[plugin.name]`, so keys often do not end with `_output`.

Impact:

- Report links for plugin outputs can be missing or wrong.

Recommendation:

- Store artifact paths in the result model when saving files.
- Have `Owl` render saved paths instead of reconstructing filenames heuristically.

### 8. Fix markdown details block generation for AI summaries

Evidence:

- `format_ai_summary` opens a fenced code block but does not close it before `</details>` in markdown mode: `modules/kea.py:39`.

Impact:

- AI sections may render incorrectly in markdown and PDF conversion.

Recommendation:

- Close the fenced block explicitly.
- Add snapshot tests for generated report fragments.

### 9. Make external IP checks robust and non-duplicated

Evidence:

- `validate_environment` fetches and validates external IP: `flockit.py:35`.
- `PreFlight.setup` calls `check_external_ip_validity`, which fetches and validates external IP again: `modules/preflight.py:29` and `modules/preflight.py:124`.
- Several external IP calls have no timeout or exception handling: `flockit.py:35` and `modules/preflight.py:125`.

Impact:

- Startup can hang or fail on transient network issues.
- The user can be prompted twice for the same VPN/range decision.

Recommendation:

- Centralize external IP validation in one component.
- Use a timeout and catch `requests.RequestException`.
- Cache the observed external IP in the project context.

### 10. Use project-local scope as the source of truth

Evidence:

- `split_scope_file` reads root `scope.txt` from the current working directory: `modules/preflight.py:33`.
- It writes split files into the project folder: `modules/preflight.py:34`.

Impact:

- Multiple projects in the same working directory can accidentally share or overwrite scope input.

Recommendation:

- Accept `--scope` as an explicit input path.
- Copy the source scope into the project folder.
- Treat project-local scope files as generated artifacts.

### 11. Correct scope range parsing

Evidence:

- Any entry containing `-` is treated as an IP range candidate: `modules/preflight.py:66`.

Impact:

- Hostnames or URLs containing hyphens can be incorrectly treated as ranges and skipped.

Recommendation:

- Only treat entries as ranges when they match the exact supported IPv4 range pattern.
- Handle CIDR expansion deliberately or pass CIDRs directly to tools that support them.

### 12. Clarify web scope support

Evidence:

- Web scope files are generated: `modules/preflight.py:35`.
- Main active recon targets only include `int_scope.txt` and `ext_scope.txt`: `modules/preflight.py:227`.

Impact:

- README claims web recon support, but the main active scan path does not process web targets.

Recommendation:

- Either implement a web testing phase or document web scope as preflight/report-only for now.
- Consider separate HTTP probing plugins for web URLs.

## P2 - Architecture and Maintainability

### 13. Replace mutable globals with explicit context objects

Evidence:

- `AUTO`, `CUSTOM_SETTINGS`, and `SCAN_RESULTS` are mutable module-level values spread across files: `utils/common.py:29`, `utils/common.py:36`, `modules/preflight.py:19`, and `flockit.py:15`.

Impact:

- Behavior is hard to test and reason about.
- Import order matters; `CUSTOM_SETTINGS = load_settings_xml()` runs at import time: `utils/common.py:212`.

Recommendation:

- Introduce `Config` and `ProjectContext` dataclasses.
- Pass context into `PreFlight`, `Raven`, `Magpie`, and `Owl`.
- Remove settings loading side effects from module import.

### 14. Separate scanning from file writing

Evidence:

- `Raven.scan_host` saves nmap, banner, and plugin artifacts directly while building result data: `modules/raven.py:86`, `modules/raven.py:103`, and `modules/raven.py:115`.

Impact:

- Scan logic is hard to unit test.
- Report paths are inferred from output path conventions.

Recommendation:

- Add an `ArtifactStore` abstraction with methods like `save_nmap_csv`, `save_banner`, and `save_plugin_output`.
- Return artifact paths in scan results.

### 15. Harden plugin loading

Evidence:

- `Magpie` imports every Python file in `modules/plugins`: `modules/magpie.py:22`.
- Importing a plugin executes import-time code.
- AI-generated plugins are written into the same directory: `modules/magpie.py:154`.

Impact:

- A malicious or broken plugin can run arbitrary code during load.
- AI-generated code becomes part of the trusted runtime path.

Recommendation:

- Keep generated plugins in a separate quarantine directory.
- Require explicit approval before enabling generated plugins.
- Add plugin metadata and compatibility validation.
- Catch and isolate plugin execution errors per host/port, which is already partially done.

### 16. Consolidate AI plugin generation paths

Evidence:

- `Magpie.generate_plugin_for` contains one plugin generation implementation: `modules/magpie.py:67`.
- `kea.generate_plugin_code` contains another: `modules/kea.py:95`.

Impact:

- Prompt behavior, validation, provider support, and sanitization can drift.

Recommendation:

- Keep one provider-neutral plugin generation service.
- Reuse one validator.
- Add unit tests for extraction/sanitization/validation.

### 17. Normalize result schema before reporting

Evidence:

- `flockit.py` filters malformed Raven results twice: `flockit.py:126` and `flockit.py:143`.
- `Owl` assumes required port keys exist: `modules/owl.py:67`.

Impact:

- Invalid plugin or scan data can break report generation.

Recommendation:

- Define dataclasses or typed dictionaries for host, port, plugin, and artifact data.
- Validate once after scanning.
- Make report generation tolerant of missing optional fields.

### 18. Add a test suite

High-value initial tests:

- Scope splitting: IPs, CIDRs, domains, URLs, hyphenated domains, invalid entries.
- Prompt automation: yes/no behavior and auto flags.
- Settings loader: default values and XML key normalization.
- Raven scan mode: quick vs full arguments.
- Magpie plugin loading: no duplicates and bad plugin isolation.
- Owl report generation: artifact links, markdown details blocks, missing fields.

Suggested tooling:

- `pytest`
- `responses` or `requests-mock` for external IP and AI HTTP calls.
- Test doubles for `nmap.PortScanner`.

## P3 - Product and UX Improvements

### 19. Update README accuracy

Evidence:

- Usage references `python3 flockit_dev_0.6.py`, but the current entrypoint is `flockit.py`: `README.md:110`.
- Dependency install command says `requirementst.txt`, but the file is `requirements.txt`: `README.md:157`.
- README lists `--int`, `--ext`, and `--web`, but those CLI flags are not defined in `flockit.py`: `README.md:128` and `flockit.py:50`.

Recommendation:

- Update usage examples and supported flags.
- Add a minimal first-run guide with `scope.txt` and `settings.xml` examples.
- Document when Ollama is required.

### 20. Add dry-run and no-network modes

Recommendation:

- `--dry-run`: parse settings/scope and show planned actions without scanning.
- `--no-ai`: force-disable AI paths.
- `--no-upload`: force-disable packaging/upload.
- `--scope`: explicit scope file path.

### 21. Improve reporting quality

Recommendation:

- Add severity labels only when backed by deterministic evidence or explicit AI caveat.
- Split "observed facts" from "AI recommendations".
- Add an appendix of raw artifacts.
- Include command metadata: scan mode, nmap arguments, timestamps, tool versions.

### 22. Make SMB upload explicit and safer

Evidence:

- `compress_and_upload` currently skips upload in auto mode regardless of `--auto-upload`: `modules/preflight.py:165`.
- If not in auto mode, it compresses and attempts upload without calling `prompt_smb_upload`: `modules/preflight.py:163`.

Recommendation:

- Only upload when `--auto-upload` is set or the user explicitly answers yes.
- Validate SMB config before attempting login.
- Keep zip creation separate from upload.

### 23. Add structured logging

Recommendation:

- Initialize logging once per run under the project folder.
- Log scan commands, plugin names, artifact paths, exceptions, and phase timings.
- Keep terminal output concise; put diagnostics in logs.

## Suggested Implementation Order

1. Fix `prompt_yes_no` boolean behavior and update callers.
2. Normalize settings keys and remove import-time settings loading.
3. Fix scan mode propagation and duplicate plugin loading.
4. Move AI provider checks to AI-specific paths.
5. Fix report opening logic, AI markdown blocks, and artifact links.
6. Add focused tests around scope parsing, prompts, settings, Raven scan arguments, and Owl rendering.
7. Refactor toward explicit `Config`, `ProjectContext`, and `ArtifactStore`.
