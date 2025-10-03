# Repository Guidelines

## Project Structure & Module Organization
The CLI entry point is `vcpkg-cyclonedx-cpe-purl.py`; it consumes `mapping.json` and emits `sbom.cyclonedx.json` and `.xml`, surfacing missing mapping details inline (errors by default, warnings with `--ignore-missing`). `cpedict/` provides the authoritative CPE vendor/product dictionary, refreshed via `cpedict/update-cpedict.sh` and bundled with SPDX licensing notices. Keep large generated outputs and experimental notebooks out of version control; store only curated mapping updates and scripts.

### Reference Script Policy
- Treat `sample-script.py` as the canonical reference implementation for contributor workflows.
- Never modify `sample-script.py` in this repository; create local copies if experimentation is required.

## Build, Test, and Development Commands
- `python3 -m pip install cyclonedx-python-lib`: installs the only runtime dependency used by the CLI.
- `python3 vcpkg-cyclonedx-cpe-purl.py build <path-to-vcpkg/installed> --mapping mapping.json`: generates CycloneDX SBOM files and fails fast when mappings are missing; point to the vcpkg `installed/` tree for your triplet.
- `python3 vcpkg-cyclonedx-cpe-purl.py build <path-to-vcpkg/installed> --mapping mapping.json --ignore-missing`: produces SBOM outputs while keeping unmapped ports (marked with warning logs and fallback metadata) so you can review gaps without aborting the run.
- `bash cpedict/update-cpedict.sh`: pulls the latest upstream CPE dictionary; re-run before large mapping refreshes.

## Coding Style & Naming Conventions
Follow PEP 8 with 4-space indentation and descriptive snake_case names. Keep functions single-purpose, prefer early returns for validation, and document new CLI options in `--help`. Maintain the existing `[ERROR]`/`[OK]` logging pattern and ensure mapping keys stay lowercase to match vcpkg port folders.

## Testing Guidelines
There is no test suite yet; add `tests/` with `pytest` when expanding logic or parsing. Structure fixtures under `tests/data/` and mirror vcpkg layouts using minimal SPDX samples. Validate new behavior with targeted unit tests and, when touching mapping rules, capture representative failing inputs in regression cases.

## Commit & Pull Request Guidelines
Write commits in imperative mood with concise scope (e.g., "Add openssl CPE mapping"). Reference updated files in the body rather than generic summaries. Pull requests should describe the scenario exercised, list commands run (e.g., `build` with or without `--ignore-missing`), attach relevant snippets of generated SBOM or CLI log output highlighting remaining mapping gaps, and link any tracking issues. Screenshots are optional; include them when demonstrating downstream tooling consumption.

## Data & Security Notes
Treat `mapping.json` as authoritative: verify new entries against upstream CPE and PURL specifications before merging. Do not commit raw NVD dumps; only include distilled vendor/product rows. When sharing SBOMs, scrub paths containing internal infrastructure details and confirm the CycloneDX library version in use is noted in the PR.
