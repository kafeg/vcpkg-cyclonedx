#!/usr/bin/env python3
import argparse
import json
import sys
from fnmatch import fnmatch
from pathlib import Path

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model import ExternalReference, ExternalReferenceType
from cyclonedx.output import OutputFormat, make_outputter
from cyclonedx.schema import SchemaVersion


def load_mapping(path: Path) -> dict:
    if not path.exists():
        print(f"[ERROR] Mapping file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def collect_spdx_files(installed_root: Path):
    return list(installed_root.glob("**/share/*/vcpkg.spdx.json"))


def find_mapping_entry(mapping: dict, pkg_name: str):
    if pkg_name in mapping:
        return mapping[pkg_name]
    for pattern, entry in mapping.items():
        if pattern == pkg_name:
            return entry
        if any(ch in pattern for ch in "*?[") and fnmatch(pkg_name, pattern):
            return entry
    return None


def render_template(template: str, pkg_name: str, pkg_version: str) -> str:
    return (
        template
        .replace("{version}", pkg_version)
        .replace("{port}", pkg_name)
    )


def build_sbom(installed_root: Path, mapping_file: Path):
    mapping = load_mapping(mapping_file)
    spdx_files = collect_spdx_files(installed_root)

    if not spdx_files:
        print(f"[ERROR] No vcpkg.spdx.json files found under {installed_root}", file=sys.stderr)
        sys.exit(1)

    bom = Bom()
    errors = []

    for spdx_file in spdx_files:
        with spdx_file.open("r", encoding="utf-8") as f:
            spdx = json.load(f)

        pkg_name = spdx.get("name")
        pkg_version = spdx.get("versionInfo")

        if not pkg_name or not pkg_version:
            errors.append(f"{spdx_file}: missing name/version")
            continue

        m = find_mapping_entry(mapping, pkg_name)
        if not m:
            errors.append(f"Port {pkg_name} missing in mapping.json")
            continue

        cpe = render_template(m.get("cpe", ""), pkg_name, pkg_version)
        purl = render_template(m.get("purl", ""), pkg_name, pkg_version)

        if not cpe or not purl:
            errors.append(f"Port {pkg_name} has incomplete mapping")
            continue

        comp = Component(
            name=pkg_name,
            version=pkg_version,
            type=ComponentType.LIBRARY,
            purl=purl
        )
        comp.external_references.add(
            ExternalReference(
                reference_type=ExternalReferenceType.SECURITY,
                url=cpe  # CycloneDX lib требует url, но можно указать CPE строкой
            )
        )

        bom.components.add(comp)

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


def audit_ports(vcpkg_root: Path, mapping_file: Path):
    mapping = load_mapping(mapping_file)
    ports_dir = vcpkg_root / "ports"

    if not ports_dir.exists():
        print(f"[ERROR] Ports directory not found: {ports_dir}", file=sys.stderr)
        sys.exit(1)

    report = []
    for port_dir in sorted(ports_dir.iterdir()):
        if not port_dir.is_dir():
            continue
        name = port_dir.name
        has_mapping = find_mapping_entry(mapping, name) is not None
        report.append({"port": name, "mapped": has_mapping})

    with open("mapping_audit.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[OK] Audit complete: mapping_audit.json (total {len(report)} ports)")


def main():
    parser = argparse.ArgumentParser(prog="vcpkg-cyclonedx-cpe-purl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_p = subparsers.add_parser("build", help="Generate CycloneDX SBOM")
    build_p.add_argument("installed_root", type=Path)
    build_p.add_argument("--mapping", type=Path, default=Path("mapping.json"))

    audit_p = subparsers.add_parser("audit", help="Audit ports mapping coverage")
    audit_p.add_argument("vcpkg_root", type=Path)
    audit_p.add_argument("--mapping", type=Path, default=Path("mapping.json"))

    args = parser.parse_args()

    if args.command == "build":
        build_sbom(args.installed_root, args.mapping)
    elif args.command == "audit":
        audit_ports(args.vcpkg_root, args.mapping)


if __name__ == "__main__":
    main()
