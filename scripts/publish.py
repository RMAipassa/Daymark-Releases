#!/usr/bin/env python3
"""Publish a verified Daymark candidate from the trusted default branch."""

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from release_common import (COMMIT, INDEX, MAX_APK, REPO, VERSION, ReleaseError, asset_names, candidate, git,
                            read_index, require, sha256, update_needed, verify_apk)

HTTPS = f"https://github.com/{REPO}.git"
MAIN = "refs/heads/main"
RELEASES = f"/repos/{REPO}/releases"
API = "https://api.github.com"
UPLOADS = "https://uploads.github.com"


def ancestor(repo, old, new):
    return subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", old, new],
                          capture_output=True).returncode == 0


def extract(repo, directory, main, commit, version):
    require(not git(repo, "ls-tree", main, "--", "incoming"), "Public main unexpectedly contains incoming/.")
    parents = git(repo, "rev-list", "--parents", "-n", "1", commit).decode("ascii").split()
    require(len(parents) == 2 and ancestor(repo, parents[1], main),
            "Candidate must be one commit on a public main ancestor.")
    parent = parents[1]
    names = asset_names(version)
    changes = git(repo, "diff-tree", "--no-commit-id", "--no-renames", "--name-status", "-r", "-z", parent, commit)
    expected = {f"A\0incoming/{name}".encode("ascii") for name in names}
    entries = changes.rstrip(b"\0").split(b"\0")
    require(len(entries) == 6 and {b"\0".join(entries[i:i + 2]) for i in range(0, 6, 2)} == expected,
            "Candidate may only add the three expected files under incoming/.")
    for name, limit in zip(names, (MAX_APK, 256, 4096)):
        path = f"incoming/{name}"
        entry = git(repo, "ls-tree", commit, "--", path).decode("ascii")
        matched = re.fullmatch(rf"100644 blob ({COMMIT})\t{re.escape(path)}\n", entry)
        require(matched, "Candidate contains a non-regular file.")
        blob = matched[1]
        require(0 < int(git(repo, "cat-file", "-s", blob)) <= limit, "Candidate file size is out of bounds.")
        (directory / name).write_bytes(git(repo, "cat-file", "blob", blob))


def fetch_candidate(repo, directory, version, expected_commit):
    require(re.fullmatch(VERSION, version), "Expected version MAJOR.MINOR.PATCH.")
    require(expected_commit is None or re.fullmatch(COMMIT, expected_commit), "Missing or invalid candidate commit.")
    ref = f"refs/heads/incoming/v{version}"
    git(repo, "init", "--bare", "--quiet")
    try:
        git(repo, "fetch", "--quiet", "--no-tags", HTTPS, f"{MAIN}:{MAIN}", f"{ref}:{ref}")
    except ReleaseError as error:
        raise ReleaseError(f"Could not fetch public main and incoming/v{version}; the pending branch may be gone.") from error
    main = git(repo, "rev-parse", MAIN).decode("ascii").strip()
    commit = git(repo, "rev-parse", ref).decode("ascii").strip()
    require(expected_commit is None or commit == expected_commit, "Incoming branch changed since it was pushed or verified.")
    extract(repo, directory, main, commit, version)
    return (main, commit, ref, candidate(directory, version))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # Never forward the credential to a different origin.


class GitHub:
    def __init__(self, token):
        require(token, "Missing public Actions token.")
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, payload=None, *, upload=False, content_type="application/json", absent=False):
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2026-03-10", "Content-Type": content_type, "User-Agent": "daymark-publisher"}
        if payload is not None and not isinstance(payload, bytes):
            payload = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request((UPLOADS if upload else API) + path, data=payload, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=120) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if absent and error.code == 404:
                return None
            # Do not log response bodies; they can contain untrusted content.
            raise ReleaseError(f"GitHub {method} {path} failed (HTTP {error.code}).") from error

    def releases_with_tag(self, tag):
        # The REST by-tag endpoint is only guaranteed to return published releases.
        found = []
        for page in range(1, 101):
            releases = self.request("GET", f"{RELEASES}?per_page=100&page={page}")
            found.extend(release for release in releases if release["tag_name"] == tag)
            if len(releases) < 100:
                require(len(found) <= 1, "Multiple releases use this tag; repair manually.")
                return found[0] if found else None
        raise ReleaseError("Could not enumerate all release tags.")

    def tag_object(self, tag):
        tag_ref = self.request("GET", f"/repos/{REPO}/git/ref/tags/{tag}", absent=True)
        if tag_ref is None:
            return None
        require(tag_ref["ref"] == f"refs/tags/{tag}", "Unexpected release tag reference.")
        target = tag_ref["object"]
        for _ in range(4):
            require(re.fullmatch(COMMIT, target["sha"]), "Unexpected release tag SHA.")
            if target["type"] == "commit":
                return target["sha"]
            require(target["type"] == "tag", "Release tag does not point to a commit.")
            target = self.request("GET", f"/repos/{REPO}/git/tags/{target['sha']}")["object"]
        raise ReleaseError("Unexpected nested release tag.")

    def asset_status(self, release, paths, *, complete):
        asset_names_seen = set()
        for asset in release["assets"]:
            name = asset["name"]
            require(name in paths and name not in asset_names_seen, "Unexpected or duplicate GitHub release asset.")
            path = paths[name]
            require(asset["state"] == "uploaded" and asset["size"] == path.stat().st_size and
                    asset.get("digest") == f"sha256:{sha256(path)}", f"GitHub asset verification failed for {name}; refusing replacement.")
            asset_names_seen.add(name)
        require(not complete or asset_names_seen == set(paths), "GitHub release is missing expected assets.")
        return asset_names_seen

    def upsert_release(self, repo, main, tag, paths, *, advance):
        release = self.releases_with_tag(tag)
        # An already advertised or already published tag is never recreated or edited.
        if release is not None and release["draft"] is False:
            self.check_published(repo, main, tag, release, paths)
            return
        require(advance, "Updater already references this version, but its immutable release is missing.")
        require(self.tag_object(tag) is None, "Release tag already exists without a matching immutable release.")
        require(os.environ.get("IMMUTABLE_SETTING_CONFIRMED") == "true",
                "Enable immutable releases and set public variable DAYMARK_IMMUTABLE_RELEASES_ENABLED=true first.")
        marker = f"<!-- daymark-manifest-sha256: {sha256(paths[INDEX])} -->"
        if release is None:
            release = self.request("POST", RELEASES, {"tag_name": tag, "target_commitish": "main",
                                                       "name": f"Daymark {tag}", "body": marker, "draft": True})
        require(release["draft"] is True and release["tag_name"] == tag and release["target_commitish"] == "main"
                and release["body"] == marker, "Existing draft belongs to a different candidate; refusing to change it.")
        release_id = release["id"]
        require(type(release_id) is int and release_id > 0, "Invalid GitHub release ID.")
        uploaded = self.asset_status(release, paths, complete=False)
        for name, path in paths.items():
            if name not in uploaded:
                query = urllib.parse.urlencode({"name": name})
                self.request("POST", f"{RELEASES}/{release_id}/assets?{query}", path.read_bytes(), upload=True,
                             content_type="application/vnd.android.package-archive" if name.endswith(".apk") else
                             ("application/json" if name == INDEX else "text/plain"))
        endpoint = f"{RELEASES}/{release_id}"
        draft = self.request("GET", endpoint)
        require(draft["draft"] is True and draft["tag_name"] == tag and draft["body"] == marker and
                draft["target_commitish"] == "main", "Draft release changed during upload.")
        self.asset_status(draft, paths, complete=True)
        self.request("PATCH", endpoint, {"draft": False, "make_latest": "true"})
        self.check_published(repo, main, tag, self.request("GET", endpoint), paths)

    def check_published(self, repo, main, tag, release, paths):
        require(release["tag_name"] == tag and release["draft"] is False and release["prerelease"] is False,
                "GitHub release is not a published stable release for the expected tag.")
        require(release.get("immutable") is True,
                "GitHub release is not immutable. The updater was not changed; inspect release settings and repair manually.")
        self.asset_status(release, paths, complete=True)
        target = self.tag_object(tag)
        # If main advanced editorially during publication, this run will fail its CAS
        # anyway; the next run fetches the new main and verifies the immutable tag.
        require(target is not None and ancestor(repo, target, main), "Release tag does not point to trusted public main history.")

    def advance_index(self, main, version, raw):
        query = """mutation Update($input: CreateCommitOnBranchInput!) {
          createCommitOnBranch(input: $input) { commit { oid } }
        }"""
        result = self.request("POST", "/graphql", {"query": query, "variables": {"input": {
            "branch": {"repositoryNameWithOwner": REPO, "branchName": "main"},
            "expectedHeadOid": main,
            "message": {"headline": f"Publish Daymark {version} update metadata"},
            "fileChanges": {"additions": [{"path": INDEX, "contents": base64.b64encode(raw).decode("ascii")}]},
        }}})
        require(not result.get("errors") and (result.get("data") or {}).get("createCommitOnBranch"),
                "Could not atomically update main (branch advanced or rules denied the write). Dispatch the publisher again after review.")

    def cleanup(self, repo, ref, commit):
        header = base64.b64encode(f"x-access-token:{self.token}".encode("ascii")).decode("ascii")
        env = {**os.environ, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
               "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {header}", "GIT_TERMINAL_PROMPT": "0"}
        try:
            git(repo, "-c", "http.followRedirects=false", "push", "--quiet", f"--force-with-lease={ref}:{commit}", HTTPS, f":{ref}", env=env)
        except ReleaseError:
            print("::warning::Release verified, but the pending branch was not deleted (changed branch or branch rules).")


def verify(repo, directory):
    if os.environ["GITHUB_EVENT_NAME"] == "workflow_dispatch":
        version, expected_commit = os.environ["REQUESTED_VERSION"], None
    else:
        branch = re.fullmatch(rf"incoming/v({VERSION})", os.environ["INCOMING_BRANCH"])
        require(branch, "Unexpected incoming branch.")
        version, expected_commit = branch[1], os.environ["INCOMING_SHA"]
    _, commit, _, data = fetch_candidate(repo, directory, version, expected_commit)
    verify_apk(directory / data["apk"], version, data["versionCode"])
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"version={version}\ncommit={commit}\ndigest={data['sha256']}\n")
    print(f"Verified Daymark {version} ({data['versionCode']}), candidate {commit}.")


def publish(repo, directory):
    token = os.environ.pop("GH_TOKEN", "")
    version = os.environ["VERIFIED_VERSION"]
    main, commit, ref, data = fetch_candidate(repo, directory, version, os.environ["VERIFIED_COMMIT"])
    require(data["sha256"] == os.environ["VERIFIED_DIGEST"], "Candidate differs from read-only APK verification.")
    advance = update_needed(read_index(repo, main), version, data["versionCode"], data["sha256"])
    paths = {name: directory / name for name in asset_names(version)}
    github = GitHub(token)
    github.upsert_release(repo, main, f"v{version}", paths, advance=advance)
    if advance:
        github.advance_index(main, version, paths[INDEX].read_bytes())
        print(f"Published or recovered immutable Daymark {version}; updater advanced to {data['versionCode']}.")
    else:
        print(f"Daymark {version} already matches the immutable release; nothing republished.")
    github.cleanup(repo, ref, commit)


def main():
    require(sys.argv[1:] in (["verify"], ["publish"]), "Expected verify or publish.")
    require(os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_REF") == MAIN,
            "The publisher must run from main in the public release repository.")
    with tempfile.TemporaryDirectory(prefix="daymark-publish-") as temp:
        repo, directory = (Path(temp) / name for name in ("public", "assets"))
        repo.mkdir()
        directory.mkdir()
        (verify if sys.argv[1] == "verify" else publish)(repo, directory)


if __name__ == "__main__":
    try:
        main()
    except ReleaseError as error:
        sys.exit(str(error))
    except (KeyError, ValueError, OSError):
        sys.exit("Publisher could not read expected files, GitHub response, or workflow environment.")
