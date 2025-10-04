## vcpkg CycloneDX CPE/PURL helper

This repository provides a thin wrapper around `vcpkg` SPDX metadata so that you can emit CycloneDX SBOMs enriched with CPEs and Package URLs. It is inspired and based on https://github.com/microsoft/vcpkg/discussions/40700. This is temporary solution, until vcpkg will have native CycloneDX/CPE/PURL integration.

### Prerequisites
- Python 3.9 or newer
- `cyclonedx-python-lib` installed in the active environment (`python3 -m pip install cyclonedx-python-lib`)
- A populated `vcpkg` installation tree that includes `share/<port>/vcpkg.spdx.json` files

### Basic usage
1. Populate or update `mapping.json` with the CPE and PURL templates you want to use.
2. Run the CLI in build mode:
   ```bash
   python3 vcpkg-cyclonedx.py build /path/to/vcpkg/installed --mapping mapping.json
   ```
3. On success the script writes `sbom.cyclonedx.json` and `sbom.cyclonedx.xml` to the current directory. If any port lacks a mapping you will receive an error list with suggested CPE candidates sourced from `cpedict/data/cpes.csv`. Status prefixes such as `[OK]`, `[WARN]`, and `[ERROR]` are colorized when the output stream supports ANSI colors.

### Ignore missing mode
Set `--ignore-missing` to generate an SBOM even when some ports do not yet have mappings. Unmapped ports stay in the output with fallback Package URLs and component properties noting that CPE data is unavailable, and a warning lists everything that needs follow-up. The legacy `--skip-missing` flag still works as an alias.
```bash
python3 vcpkg-cyclonedx.py build /path/to/vcpkg/installed \
  --mapping mapping.json --ignore-missing
```

### Interactive edit mode
The `--edit-mapping` flag lets you curate `mapping.json` during the build. Whenever the script encounters an unmapped port it:
- Shows up to three vendor/product suggestions from the bundled CPE dictionary
- Lets you pick a suggestion, enter a custom vendor/product, skip, or quit
- Saves the updated `mapping.json` (preserving indentation) before continuing

Example session:
```bash
python3 vcpkg-cyclonedx.py build /path/to/vcpkg/installed --mapping mapping.json --edit-mapping
...
[EDIT] Port libzip (1.11.3) missing in mapping.json.
[EDIT] Suggested CPE vendor/product pairs:
  1) libzip/libzip
  2) nih/libzip
  3) libzip2/libzip2
Select option number or enter command ([s]kip, [c]ustom, [q]uit): 1
[OK] Selected mapping libzip/libzip for libzip.
[OK] Updated mapping file: mapping.json
```

If there are no suggested suitable suggested variants, use https://nvd.nist.gov/products/cpe/search for search port name and select and fill 'custom' option, like in example below:

```
python3 vcpkg-cyclonedx.py build ../qclauncher/vcpkg/installed --mapping mapping.json --edit-mapping
[EDIT] Port msgpack (7.0.0) missing in mapping.json.
[EDIT] Suggested CPE vendor/product pairs:
  1) gpac/gpac
  2) gpac_project/gpac
  3) kriszyp/msgpackr
Select option number or enter command ([s]kip, [c]ustom, [q]uit): c
  Vendor (CPE party): msgpack
  Product (CPE component): msgpack
  PURL template [pkg:generic/{port}@{version}]: 
[OK] Added custom mapping msgpack/msgpack for msgpack.
[OK] Updated mapping file: mapping.json
```

### Mapping format
Each entry in `mapping.json` uses simple string templates:
- `{port}` is replaced with the vcpkg port name
- `{version}` is replaced with the port version extracted from the SPDX document

For example:
```json
"brotli": {
  "cpe": "cpe:2.3:a:google:{port}:{version}:*:*:*:*:*:*:*",
  "purl": "pkg:generic/{port}@{version}"
}
```

### Updating the CPE dictionary
Just update submodule. This is usually no need to do, as it is service level.
