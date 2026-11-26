"""Shared Daymark release format, monotonicity, and APK verification."""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

REPO = "RMAipassa/Daymark-Releases"
INDEX = "Daymark-update.json"
PACKAGE = "nl.rubyruben.daymark"
SIGNER = "4421f8ff5d869b93474b7e732c29e088dc5dbc42502c407b707f9940c472dbec"
VERSION = r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})"
COMMIT = r"[0-9a-f]{40}"
MAX_APK = 95 * 1024 * 1024  # Keep comfortably under GitHub's 100 MiB Git blob limit.


class ReleaseError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def version_check(name, code):
    require(isinstance(name, str) and re.fullmatch(VERSION, name), "Expected versionName MAJOR.MINOR.PATCH.")
    require(type(code) is int and 1 <= code <= 2_100_000_000, "Invalid integer Android versionCode.")


def asset_names(name):
    apk = f"Daymark-{name}.apk"
    return (apk, f"{apk}.sha256", INDEX)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate key in JSON object.")
        result[key] = value
    return result


def manifest(raw):
    require(len(raw) <= 4096, "Updater manifest is too large.")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (ValueError, RecursionError) as error:
        raise ReleaseError("Malformed UTF-8 updater manifest.") from error
    require(isinstance(value, dict) and set(value) == {"versionName", "versionCode", "apk", "sha256"},
            "Updater manifest must contain exactly versionName, versionCode, apk and sha256.")
    version_check(value["versionName"], value["versionCode"])
    require(value["apk"] == asset_names(value["versionName"])[0], "Manifest APK name does not match its version.")
    require(isinstance(value["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]),
            "Invalid SHA-256 in updater manifest.")
    return value


def update_needed(current, name, code, digest=None):
    if current is None:
        return True
    if name == current["versionName"] and code == current["versionCode"]:
        require(digest is None or digest == current["sha256"], "Same version has a different APK digest.")
        return False
    require(name != current["versionName"], "Cannot reuse a released versionName with a different versionCode.")
    require(code > current["versionCode"], "Refusing a conflicting or lower versionCode.")
    return True


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def checksum_line(apk, digest):
    return f"{digest}  {apk}\n".encode("ascii")


def candidate(directory, version=None):
    index = directory / INDEX
    require(index.is_file() and not index.is_symlink() and index.stat().st_size <= 4096,
            "Missing or invalid candidate manifest.")
    data = manifest(index.read_bytes())
    require(version is None or data["versionName"] == version, "Incoming branch does not match manifest versionName.")
    names = asset_names(data["versionName"])
    require({path.name for path in directory.iterdir()} == set(names), "Unexpected candidate filenames.")
    apk, checksum, _ = (directory / name for name in names)
    require(all(path.is_file() and not path.is_symlink() for path in (apk, checksum)), "Not a regular candidate file.")
    require(0 < apk.stat().st_size <= MAX_APK, "Candidate APK size is out of bounds.")
    require(checksum.stat().st_size <= 256 and checksum.read_bytes() == checksum_line(apk.name, data["sha256"]),
            "Checksum file does not match the manifest.")
    require(sha256(apk) == data["sha256"], "APK SHA-256 does not match the manifest.")
    return data


def tool(command, error_message):
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    require(result.returncode == 0, error_message)
    return result.stdout


def verify_apk(apk, name, code):
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    require(sdk, "Android SDK location is not set.")
    tools = Path(sdk) / "build-tools" / "35.0.0"
    aapt = tools / ("aapt.exe" if os.name == "nt" else "aapt")
    apksigner = tools / ("apksigner.bat" if os.name == "nt" else "apksigner")
    require(aapt.is_file() and apksigner.is_file(), "Install Android SDK build-tools;35.0.0.")
    badging = tool([aapt, "dump", "badging", apk], "Android manifest verification failed (aapt).")
    fields = re.findall(r"^package: name='([^']*)' versionCode='([^']*)' versionName='([^']*)'", badging, re.M)
    require(fields == [(PACKAGE, str(code), name)], "APK package, versionCode, or versionName does not match.")
    require(not re.search(r"^application-debuggable(?:\s|$)", badging, re.M), "Refusing a debuggable APK.")
    certs = tool([apksigner, "verify", "--verbose", "--print-certs", apk], "APK signature verification failed.")
    signers = re.findall(r"^Signer #[0-9]+ certificate SHA-256 digest: (\S+)$", certs, re.M)
    require([signer.lower() for signer in signers] == [SIGNER], "APK does not have the sole expected release signer.")


def git(directory, *args, env=None, data=None):
    result = subprocess.run(["git", "-C", str(directory), *args], env=env, input=data, capture_output=True)
    require(result.returncode == 0, f"Git {args[0]} failed.")
    return result.stdout


def read_index(directory, ref):
    entry = git(directory, "ls-tree", ref, "--", INDEX).decode("ascii")
    if not entry:
        return None
    require(re.fullmatch(rf"100644 blob {COMMIT}\t{re.escape(INDEX)}\n", entry), "Invalid updater file on public main.")
    spec = f"{ref}:{INDEX}"
    require(int(git(directory, "cat-file", "-s", spec)) <= 4096, "Updater file on public main is too large.")
    return manifest(git(directory, "cat-file", "blob", spec))
