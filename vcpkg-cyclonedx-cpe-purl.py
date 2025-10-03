#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from collections import defaultdict
from fnmatch import fnmatch
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output import OutputFormat, make_outputter
from cyclonedx.schema import SchemaVersion
from packageurl import PackageURL


CPEDICT_CSV_PATH = Path(__file__).resolve().parent / "cpedict" / "data" / "cpes.csv"


def load_mapping(path: Path) -> dict:
    if not path.exists():
        print(f"[ERROR] Mapping file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def collect_spdx_files(installed_root: Path):
    return list(installed_root.glob("**/share/*/vcpkg.spdx.json"))


def find_mapping_entry(mapping: dict, pkg_name: str) -> Tuple[Optional[dict], Optional[str]]:
    if pkg_name in mapping:
        return mapping[pkg_name], pkg_name
    for pattern, entry in mapping.items():
        if pattern == pkg_name:
            return entry, pattern
        if any(ch in pattern for ch in "*?[") and fnmatch(pkg_name, pattern):
            return entry, pattern
    return None, None


def render_template(template: str, pkg_name: str, pkg_version: str) -> str:
    return (
        template
        .replace("{version}", pkg_version)
        .replace("{port}", pkg_name)
    )


def pattern_has_wildcard(pattern: Optional[str]) -> bool:
    if not pattern:
        return False
    return any(ch in pattern for ch in "*?[")


def extract_wildcard_prefix(pattern: str) -> str:
    if not pattern:
        return ""
    prefix_chars: List[str] = []
    for ch in pattern:
        if ch in "*?[":
            break
        prefix_chars.append(ch)
    if not prefix_chars:
        return ""
    prefix = "".join(prefix_chars).rstrip("-_ .")
    return prefix.lower()


def choose_cpe_product(
    port_name: str,
    vendor_value: str,
    matched_pattern: Optional[str],
    cpedict_by_vendor: Dict[str, Dict[str, str]],
) -> str:
    if not vendor_value:
        return port_name

    vendor_products = cpedict_by_vendor.get(vendor_value.lower())
    if not vendor_products:
        return port_name

    port_lower = port_name.lower()
    if port_lower in vendor_products:
        return vendor_products[port_lower]

    normalized = port_lower.replace("-", "_")
    if normalized in vendor_products:
        return vendor_products[normalized]

    candidates: List[str] = []

    if pattern_has_wildcard(matched_pattern):
        prefix = extract_wildcard_prefix(matched_pattern or "")
        if prefix:
            candidates.append(prefix)

    candidates.append(vendor_value.lower())

    for candidate in candidates:
        if candidate in vendor_products:
            return vendor_products[candidate]

    return port_name


def render_cpe_value(
    template: str,
    pkg_name: str,
    pkg_version: str,
    matched_pattern: Optional[str],
    cpedict_by_vendor: Dict[str, Dict[str, str]],
) -> str:
    if not template:
        return ""

    parts = template.split(":")
    if len(parts) != 13:
        return render_template(template, pkg_name, pkg_version)

    vendor_template = parts[3]
    product_template = parts[4]

    vendor_value = render_template(vendor_template, pkg_name, pkg_version).strip()
    adjusted_product_template = product_template

    if "{port}" in product_template:
        canonical_product = choose_cpe_product(
            pkg_name,
            vendor_value,
            matched_pattern,
            cpedict_by_vendor,
        )
        adjusted_product_template = product_template.replace("{port}", canonical_product)

    parts[3] = vendor_value
    parts[4] = render_template(adjusted_product_template, pkg_name, pkg_version).strip()

    for idx, value in enumerate(parts):
        if idx in (3, 4):
            continue
        parts[idx] = render_template(value, pkg_name, pkg_version).strip()

    return ":".join(parts)


def load_cpedict_index(
    csv_path: Path,
) -> Tuple[
    List[Tuple[str, str]],
    Dict[str, List[Tuple[str, str]]],
    Dict[str, Dict[str, str]],
]:
    entries: List[Tuple[str, str]] = []
    by_product: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    by_vendor: Dict[str, Dict[str, str]] = defaultdict(dict)

    if not csv_path.exists():
        return entries, by_product, by_vendor

    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            vendor = (row.get("vendor") or "").strip()
            product = (row.get("product") or "").strip()
            if not vendor or not product:
                continue
            entry = (vendor, product)
            entries.append(entry)
            product_lower = product.lower()
            vendor_lower = vendor.lower()
            by_product[product_lower].append(entry)
            # Track canonical case for quick vendor/product lookups
            by_vendor[vendor_lower][product_lower] = product

    return entries, by_product, by_vendor


def suggest_cpe_candidates(
    port_name: str,
    entries: List[Tuple[str, str]],
    by_product: Dict[str, List[Tuple[str, str]]],
    limit: int = 3,
) -> List[Tuple[str, str]]:
    if not port_name:
        return []

    port_lower = port_name.lower()
    normalized = port_lower.replace("-", "_")

    suggestions: List[Tuple[str, str]] = []
    seen = set()

    def add_candidates(items: List[Tuple[str, str]]):
        for candidate in items:
            if candidate in seen:
                continue
            seen.add(candidate)
            suggestions.append(candidate)
            if len(suggestions) >= limit:
                return True
        return False

    exact = by_product.get(port_lower, [])
    if add_candidates(exact):
        return suggestions

    alt = by_product.get(normalized, [])
    if add_candidates(alt):
        return suggestions

    partial_matches: List[Tuple[str, str]] = []
    for vendor, product in entries:
        product_lower = product.lower()
        if port_lower in product_lower:
            partial_matches.append((vendor, product))
            continue
        if product_lower in port_lower and len(product_lower) >= 4:
            partial_matches.append((vendor, product))

    add_candidates(partial_matches)
    return suggestions


def create_mapping_entry(vendor: str, product: str, purl_template: str = "pkg:generic/{port}@{version}") -> dict:
    vendor_clean = vendor.strip().lower()
    product_clean = product.strip().lower()
    if not vendor_clean or not product_clean:
        raise ValueError("Vendor and product must be provided for mapping entry")

    cpe_template = f"cpe:2.3:a:{vendor_clean}:{product_clean}:{{version}}:*:*:*:*:*:*:*"
    return {
        "cpe": cpe_template,
        "purl": purl_template.strip() or "pkg:generic/{port}@{version}"
    }


def interactive_add_mapping(
    pkg_name: str,
    pkg_version: str,
    suggestions: List[Tuple[str, str]],
) -> Optional[dict]:
    print(f"[EDIT] Port {pkg_name} ({pkg_version}) missing in mapping.json.")

    if suggestions:
        print("[EDIT] Suggested CPE vendor/product pairs:")
        for idx, (vendor, product) in enumerate(suggestions, start=1):
            print(f"  {idx}) {vendor}/{product}")
    else:
        print("[EDIT] No suggestions found in cpedict.")

    default_purl = "pkg:generic/{port}@{version}"
    prompt = "Select option number or enter command ([s]kip, [c]ustom, [q]uit): "

    while True:
        try:
            choice = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[ERROR] Aborting by user request.")
            sys.exit(1)

        if choice in {"", "s", "skip"}:
            print(f"[INFO] Skipping mapping for {pkg_name}.")
            return None

        if choice in {"q", "quit", "exit"}:
            print("[ERROR] Aborting by user request.")
            sys.exit(1)

        if choice in {"c", "custom"}:
            vendor = input("  Vendor (CPE party): ").strip()
            product = input("  Product (CPE component): ").strip()
            if not vendor or not product:
                print("[WARN] Vendor and product cannot be empty. Try again.")
                continue
            purl_template = input(f"  PURL template [{default_purl}]: ").strip() or default_purl
            try:
                entry = create_mapping_entry(vendor, product, purl_template)
            except ValueError as exc:
                print(f"[WARN] {exc}. Try again.")
                continue
            print(f"[OK] Added custom mapping {vendor}/{product} for {pkg_name}.")
            return entry

        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(suggestions):
                vendor, product = suggestions[index - 1]
                entry = create_mapping_entry(vendor, product)
                print(f"[OK] Selected mapping {vendor}/{product} for {pkg_name}.")
                return entry
            print("[WARN] Invalid option number. Try again.")
            continue

        print("[WARN] Unrecognized input. Provide a number, 'c' for custom, 's' to skip, or 'q' to quit.")


def save_mapping(path: Path, mapping: dict):
    with path.open("w", encoding="utf-8") as handle:
        json.dump(mapping, handle, indent=2)
        handle.write("\n")


def extract_port_package(spdx_doc: dict) -> Optional[dict]:
    packages = spdx_doc.get("packages")
    if not isinstance(packages, list):
        return None

    for package in packages:
        spdx_id = package.get("SPDXID") or package.get("spdxId")
        if isinstance(spdx_id, str) and spdx_id.lower() == "spdxref-port":
            return package

    return None


def build_sbom(
    installed_root: Path,
    mapping_file: Path,
    edit_mapping: bool = False,
    skip_missing: bool = False,
):
    mapping = load_mapping(mapping_file)
    spdx_files = collect_spdx_files(installed_root)

    if not spdx_files:
        print(f"[ERROR] No vcpkg.spdx.json files found under {installed_root}", file=sys.stderr)
        sys.exit(1)

    bom = Bom()
    errors = []
    skipped = []
    cpedict_entries, cpedict_by_product, cpedict_by_vendor = load_cpedict_index(CPEDICT_CSV_PATH)
    mapping_dirty = False

    for spdx_file in spdx_files:
        with spdx_file.open("r", encoding="utf-8") as f:
            spdx = json.load(f)

        port_package = extract_port_package(spdx)
        if not port_package:
            errors.append(f"{spdx_file}: missing port package definition")
            continue

        pkg_name_raw = port_package.get("name")
        pkg_version = port_package.get("versionInfo")

        if isinstance(pkg_name_raw, str):
            pkg_name = pkg_name_raw.strip()
            lookup_name = pkg_name.lower()
        else:
            pkg_name = None
            lookup_name = None

        if not pkg_name:
            errors.append(f"{spdx_file}: missing port name (SPDXRef-port)")
            continue

        if not pkg_version and isinstance(spdx.get("name"), str):
            doc_name = spdx["name"].split("@", 1)
            if len(doc_name) == 2:
                pkg_version = doc_name[1].split()[0]

        if not pkg_version:
            errors.append(f"{spdx_file}: missing version (SPDXRef-port)")
            continue

        mapping_key = pkg_name.lower()
        mapping_name = lookup_name or pkg_name
        m, matched_pattern = find_mapping_entry(mapping, mapping_name)
        if not m:
            suggestions = suggest_cpe_candidates(pkg_name, cpedict_entries, cpedict_by_product)
            if edit_mapping:
                entry = interactive_add_mapping(pkg_name, pkg_version, suggestions)
                if entry:
                    mapping[mapping_key] = entry
                    m = entry
                    matched_pattern = mapping_key
                    mapping_dirty = True
            if not m:
                if skip_missing:
                    skipped.append(pkg_name)
                    continue
                if suggestions:
                    formatted = ", ".join(f"{vendor}/{product}" for vendor, product in suggestions)
                    errors.append(
                        f"Port {pkg_name} ({pkg_version}) missing in mapping.json (suggest: {formatted})"
                    )
                else:
                    errors.append(f"Port {pkg_name} ({pkg_version}) missing in mapping.json")
                continue

        cpe_value = render_cpe_value(
            m.get("cpe", ""),
            pkg_name,
            pkg_version,
            matched_pattern,
            cpedict_by_vendor,
        ).strip()
        purl_value = render_template(m.get("purl", ""), pkg_name, pkg_version).strip()

        if not cpe_value or not purl_value:
            errors.append(f"Port {pkg_name} has incomplete mapping")
            continue

        try:
            purl_obj = PackageURL.from_string(purl_value)
        except ValueError:
            errors.append(f"{spdx_file}: invalid purl '{purl_value}'")
            continue

        comp = Component(
            name=pkg_name,
            version=pkg_version,
            type=ComponentType.LIBRARY,
            purl=purl_obj,
            cpe=cpe_value
        )

        bom.components.add(comp)

    if edit_mapping and mapping_dirty:
        try:
            save_mapping(mapping_file, mapping)
            print(f"[OK] Updated mapping file: {mapping_file}")
        except OSError as exc:
            print(f"[ERROR] Failed to update mapping file {mapping_file}: {exc}")
            sys.exit(1)

    if skipped:
        skipped_list = ", ".join(sorted(skipped))
        print(f"[WARN] Skipped ports without mappings: {skipped_list}")

    if errors:
        print("[ERROR] Missing mappings or invalid data:")
        for e in errors:
            print("  - " + e)
        sys.exit(1)

    # Write JSON
    json_writer = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_4)
    with open("sbom.cyclonedx.json", "w", encoding="utf-8") as f:
        f.write(json_writer.output_as_string())

    # Write XML
    xml_writer = make_outputter(bom, OutputFormat.XML, SchemaVersion.V1_4)
    with open("sbom.cyclonedx.xml", "w", encoding="utf-8") as f:
        f.write(xml_writer.output_as_string())

    print("[OK] SBOM written: sbom.cyclonedx.json and sbom.cyclonedx.xml")


def main():
    parser = argparse.ArgumentParser(prog="vcpkg-cyclonedx-cpe-purl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_p = subparsers.add_parser("build", help="Generate CycloneDX SBOM")
    build_p.add_argument("installed_root", type=Path)
    build_p.add_argument("--mapping", type=Path, default=Path("mapping.json"))
    build_p.add_argument(
        "--edit-mapping",
        action="store_true",
        help="Interactively add missing mapping entries during the build run",
    )
    build_p.add_argument(
        "--skip-missing",
        action="store_true",
        help="Do not fail when mappings are missing; omit unmatched ports instead",
    )

    args = parser.parse_args()

    if args.command == "build":
        build_sbom(
            args.installed_root,
            args.mapping,
            edit_mapping=args.edit_mapping,
            skip_missing=args.skip_missing,
        )


if __name__ == "__main__":
    main()
