# Sift Improvement Suggestions (formerly Flock-It)

Last reviewed: 2026-07-02
Reviewed from: current working tree, static review plus localhost flow run

This backlog is ordered by risk and practical impact. Line references point to the reviewed working tree — `flockit.py`/`modules/raven.py`/`modules/owl.py`/`modules/magpie.py`/`modules/kea.py` in the citations below refer to files that have since been renamed to `sift.py`/`modules/scanner.py`/`modules/reporter.py`/`modules/plugin_manager.py`/`modules/ai_prompts.py` respectively (see `docs/DESIGN.md`); the citations are left as-is since they're historical evidence, not current paths.

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

Not yet addressed (tracked, out of scope for this pass): #12 (web scope is still preflight/report-only, no active HTTP probing phase), #20 (no dedicated `--dry-run` flag), #23 (no additional structured logging beyond the per-project `sift.log` now produced via `setup_logging`).

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
