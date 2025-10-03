#!/usr/bin/python

# https://github.com/microsoft/vcpkg/discussions/40700
# Here is a temporary script that I created to put together a CycloneDX SBOM. Note that it requires a manual package-name-to-CPE mapping, at least to get the vendor name right. Notice that there are no dependencies between the components yet, so you can only see that some component was pulled in, not by whom it was pulled in.

import glob
import argparse
import json
import datetime
import re

parser = argparse.ArgumentParser(
    prog='Create vcpkg dependencies CycloneDX SBOM',
    description='Creates CycloneDX SBOM from vcpkg dependencies, based on vcpkg SPDX files',
    epilog='''
    Example:
        create-vcpkg-dependencies-sbom.py ./vcpkg/packages -o ./vcpkg-dependencies-cdx.json

                    ''')
parser.add_argument('vcpkg_installed_triplet_dir',
                    help='Path to vcpkg_install/<triplet> directory, e.g. ./build/vcpkg_installed/x64-linux-el9')
parser.add_argument('-o', '--output-filename',
                    help='Output filename to produce the CycloneDX json, e.g. vcpkg-dependencies-cdx.json')
args = parser.parse_args()

# Manually created by searching https://nvd.nist.gov/products/cpe/
# For example:
#   curl -O https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
#   gzip -d official-cpe-dictionary_v2.3.xml.gz
#   grep :dcmtk: official-cpe-dictionary_v2.3.xml.gz
cpe_map = {
    "dcmtk": "offis",
    "openjpeg": "uclouvain",
    "protobuf": "google",
    "boost-*": "boost",
    "qt*": "qt",
    "libxfixes": "x.org",
    "xproto": "x.org",  # not found in NVD
    "icu": {"vendor": "icu-project", "product": "international_components_for_unicode"},
    "libiconv": "gnu",  # not found in NVD
    "getopt": "gnu",  # not found in NVD
    "libcap": "libcap_project",
    "vcpkg-*": "microsoft",  # not found in NVD
    "harfbuzz": "harfbuzz_project",
    "gettext": "gnu",
    "gettext-libintl": "gnu",  # not found in NVD
    "utf8-range": "golang",
    "ffmpeg": "ffmpeg",
    "bzip2": "bzip",
    "libxv": "x.org",
    "libpng": "libpng",
    "zstd": {"vendor": "facebook", "product": "zstandard"},
    "xorg-macros": "x.org",  # not found in NVD
    "libxml2": "xmlsoft",
    "liblzma": "tukaani",  # not found in NVD
    "tiff": {"vendor": "libtiff", "product": "libtiff"},
    "zlib": "zlib",
    "libxdmcp": "x.org",
    "minizip": "minizip_project",
    "libuuid": "libuuid",  # not found in NVD
    "libxslt": "xmlsoft",
    "openssl": "openssl",
    "egl-registry": "khronos",  # not found in NVD
    "opengl": "khronos",  # not found in NVD
    "charls": "charls",  # not found in NVD
    "libffi": "libffi_project",
    "virtualgl": "virtualgl",  # not found in NVD
    "libxcrypt": "libxcrypt",
    "pthread-stubs": "x.org",  # not found in NVD
    "pthread": "x.org",  # not found in NVD
    "fontconfig": "fontconfig_project",
    "libvpx": "webmproject",
    "libx11": "x.org",
    "freetype": "freetype",
    "libsystemd": {"vendor": "systemd_project", "product": "systemd"},
    "dirent": "dirent_project",  # not found in NVD
    "xcb": {"vendor": "x", "product": "libxcb"},
    "re2": "google",  # not found in NVD
    "opus": "opus_codec",  # not found in NVD
    "libpq": "supabase",  # not found in NVD
    "libxext": "x",
    "glew": "glew_project",  # not found in NVD
    "libwebp": "webmproject",
    "egl": "khronos",  # not found in NVD
    "libxtst": "x",
    "lz4": "lz4_project",
    "freeglut": "freeglut",  # not found in NVD
    "libb2": "libb2",  # not found in NVD
    "abseil": "abseil",  # not found in NVD
    "libjpeg-turbo": "libjpeg-turbo",
    "libmount": "libmount",
    "lcms": "lcms_project",  # not found in NVD
    "expat": {"vendor": "libexpat_project", "product": "libexpat"},
    "pkgconf": "pkgconf",
    "brotli": "google",
    "libxi": "x.org",
    "pcre2": "pcre2",
    "libxau": "x",  # not found in NVD
    "xtrans": "x",  # not found in NVD
    "double-conversion": "google",  # not found in NVD
    "catch2": "catch",  # not found in NVD
    "jasper": "jasper_project",
    "dbus": "freedesktop",
    "sqlite3": {"vendor": "sqlite", "product": "sqlite"},
    "glib": "gnome",
    "replxx": "replxx",  # not found in NVD
    "gperf": "gnu",  # not found in NVD
    "snappy": "google"
}


def getCpeInfo(spdx_package_metadata):
    package_name = spdx_package_metadata["name"]
    if (package_name in cpe_map):
        return cpe_map[package_name]
    for package_match in cpe_map:
        if (re.match(re.escape(package_match).replace("\*", ".*"), package_name)):
            return cpe_map[package_match]
    if ("homepage" in spdx_package_metadata):
        raise NotImplementedError(
            "No CPE mapped for package {} from {}".format(package_name, spdx_package_metadata["homepage"]))

    raise NotImplementedError(
        "No CPE mapped for package {}".format(package_name))


def getCpe(spdx_package_metadata):
    cpe_info = getCpeInfo(spdx_package_metadata)
    if (isinstance(cpe_info, str)):
        vendor = cpe_info
        product = spdx_package_metadata["name"]
    else:
        vendor = cpe_info["vendor"]
        product = cpe_info["product"]
    upstream_version = getUpstreamVersion(package_metadata["versionInfo"])
    return "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*".format(vendor, product, upstream_version)


def getUpstreamVersion(version_with_port_version):
    port_version_index = version_with_port_version.rfind("#")
    if (port_version_index > 0):
        return version_with_port_version[:port_version_index]
    return version_with_port_version


output_cdx = {
    "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "metadata": {
        "timestamp": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    },
    "components": []
}
print("Finding vcpkg.spdx.json files in {}".format(
    args.vcpkg_installed_triplet_dir))
for vcpkg_spdx_file in glob.iglob(args.vcpkg_installed_triplet_dir + '/share/**/vcpkg.spdx.json'):
    print("Processing {}".format(vcpkg_spdx_file))
    with open(vcpkg_spdx_file) as f:
        vcpkg_spdx = json.load(f)
        package_metadata = vcpkg_spdx["packages"][0]
        package_name = package_metadata["name"]
        cpe = getCpe(package_metadata)
        version_with_port_version = package_metadata["versionInfo"]
        component = {
            "type": "library",
            "name": package_name,
            "version": version_with_port_version,
            "cpe": cpe
        }
        if ("description" in package_metadata):
            component["description"] = package_metadata["description"]
        if ("licenseConcluded" in package_metadata):
            component["licenses"] = [{
                "expression": package_metadata["licenseConcluded"]
                # "acknowledgement": "concluded" # CycloneDX 1.6
            }]
        if ("homepage" in package_metadata):
            component["externalReferences"] = [
                {
                    "url": package_metadata["homepage"],
                    "type": "website"
                },
            ]
        output_cdx["components"].append(component)

print("Writing {}".format(args.output_filename))
with open(args.output_filename, 'w') as f:
    json.dump(output_cdx, f, indent=4)