#!/usr/bin/env python3
"""Mirror CloakBrowser releases (Pro + free) into this repository's releases.

Runs in GitHub Actions (.github/workflows/sync.yml: cron + manual dispatch) and
locally.

    export CLOAKBROWSER_LICENSE_KEY=cb_xxx      # omit -> Pro mirroring skipped
    python3 scripts/sync_releases.py --dry-run
    python3 scripts/sync_releases.py --platforms linux-x64 --limit 1 --publish

Behaviour
---------
* Enumerates upstream releases (github.com/CloakHQ/CloakBrowser/releases).
    - `chromium-v<ver>-pro`  -> Pro binaries (key required, cloakbrowser.dev)
    - `chromium-v<ver>`      -> free binaries (plain GitHub assets, no key)
* Skips anything already recorded in the state file (unless --force).
* Verifies every archive before publishing:
    - Pro : detached Ed25519 signature over SHA256SUMS (pinned upstream key)
            + archive SHA-256 from the signed manifest.
    - Free: SHA-256 from the release's SHA256SUMS asset, when present.
* Free-tier license keys are force-served the platform's *latest* build; a
  pinned/older version is detected from the signed redirect and skipped (recorded
  in state.skipped) instead of being mirrored under the wrong version.
* Publishes each archive as a release asset in this repository (tag = the
  upstream tag) using the `gh` CLI; the local file is deleted after upload.
* The license key is read from the environment and never written to the repo.

Exit codes: 0 ok, 2 configuration/verification error.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

UPSTREAM = "CloakHQ/CloakBrowser"
API = "https://api.github.com"
SITE = "https://cloakbrowser.dev"
PINNED_PUBKEYS = ["MKFKwIhUcKWq5xTuNA0Ovg99njcDEcEJvmWYYhApvaU="]
PLATFORMS = ["darwin-arm64", "darwin-x64", "linux-x64", "linux-arm64", "windows-x64"]
UA = "cloakbrowser-mirror/1.0"


# --------------------------------------------------------------------------- utils

def eprint(*a) -> None:
    print(*a, file=sys.stderr, flush=True)


def ext_for(platform: str) -> str:
    return ".zip" if platform == "windows-x64" else ".tar.gz"


def archive_name(platform: str) -> str:
    return f"cloakbrowser-{platform}{ext_for(platform)}"


def verify_signature(manifest: bytes, sig_b64: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
    except Exception:
        return False
    for key_b64 in PINNED_PUBKEYS:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key_b64)).verify(sig, manifest)
            return True
        except Exception:
            continue
    return False


def parse_checksums(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and len(parts[0]) == 64 and all(c in "0123456789abcdef" for c in parts[0].lower()):
            out[parts[1].lstrip("*")] = parts[0].lower()
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- upstream

def github_headers(token: str | None) -> dict:
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def list_upstream_releases(token: str | None) -> list[dict]:
    out, page = [], 1
    while True:
        r = httpx.get(f"{API}/repos/{UPSTREAM}/releases",
                      headers=github_headers(token),
                      params={"per_page": 100, "page": page}, timeout=30)
        r.raise_for_status()
        batch = r.json()
        out.extend(batch)
        if len(batch) < 100:
            return out
        page += 1


def parse_targets(releases: list[dict], kinds: set[str]) -> list[dict]:
    targets = []
    for rel in releases:
        if rel.get("draft"):
            continue
        tag = rel.get("tag_name", "")
        assets = {a["name"]: a for a in rel.get("assets", [])}
        if tag.endswith("-pro"):
            if "pro" in kinds:
                targets.append({"kind": "pro", "version": tag[len("chromium-v"):-len("-pro")],
                                "tag": tag, "assets": assets})
        elif tag.startswith("chromium-v"):
            if "free" in kinds:
                targets.append({"kind": "free", "version": tag[len("chromium-v"):],
                                "tag": tag, "assets": assets})
    return targets


# --------------------------------------------------------------------------- pro

def pro_manifest(version: str) -> dict[str, str]:
    base = f"{SITE}/releases/pro/chromium-v{version}"
    man = httpx.get(f"{base}/SHA256SUMS", follow_redirects=True, timeout=20)
    sig = httpx.get(f"{base}/SHA256SUMS.sig", follow_redirects=True, timeout=20)
    man.raise_for_status()
    sig.raise_for_status()
    if not verify_signature(man.content, sig.content):
        raise SystemExit(f"SHA256SUMS signature verification FAILED for {version}")
    return parse_checksums(man.text)


def served_version(version: str, platform: str, key: str) -> str | None:
    """Version the server will actually serve (free keys are pinned to latest)."""
    r = httpx.get(f"{SITE}/api/download/{version}",
                  headers={"Authorization": f"Bearer {key}", "X-Platform": platform, "User-Agent": UA},
                  follow_redirects=False, timeout=30)
    if r.status_code == 401:
        raise SystemExit("license key missing or invalid (HTTP 401)")
    if r.status_code in (301, 302, 303, 307, 308):
        m = re.search(r"/chromium-v([^/]+)/", r.headers.get("location", ""))
        return m.group(1) if m else None
    raise SystemExit(f"unexpected HTTP {r.status_code} for {version}/{platform}")


# --------------------------------------------------------------------------- io/publish

def download(url: str, dest: Path, headers: dict | None = None) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", url, headers=headers or {}, follow_redirects=True, timeout=120) as r:
        r.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in r.iter_bytes(1 << 20):
                fh.write(chunk)
    eprint(f"    downloaded {dest.name} ({dest.stat().st_size >> 20} MiB)")


def ensure_release(repo: str, tag: str, title: str, notes: str) -> None:
    r = subprocess.run(["gh", "release", "view", tag, "-R", repo], capture_output=True, text=True)
    if r.returncode != 0:
        subprocess.run(["gh", "release", "create", tag, "-R", repo,
                        "--title", title, "--notes", notes], check=True)


def publish(repo: str, tag: str, path: Path, title: str, notes: str) -> None:
    ensure_release(repo, tag, title, notes)
    subprocess.run(["gh", "release", "upload", tag, str(path), "-R", repo, "--clobber"], check=True)
    eprint(f"    published {path.name} -> {repo} release {tag}")


# --------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default="state/downloaded.json")
    ap.add_argument("--workdir", default="work")
    ap.add_argument("--platforms", default="", help="comma list, default all")
    ap.add_argument("--kinds", default="pro,free", help="pro,free")
    ap.add_argument("--versions", default="", help="comma list to restrict versions")
    ap.add_argument("--limit", type=int, default=6, help="max downloads this run")
    ap.add_argument("--force", action="store_true", help="re-download mirrored items")
    ap.add_argument("--dry-run", action="store_true", help="plan only, no downloads/publish")
    ap.add_argument("--no-platform-latest", action="store_true",
                    help="skip the per-platform latest reconciliation in --check")
    ap.add_argument("--seed", action="store_true",
                    help="baseline: mark all current upstream versions as seen (no downloads)")
    ap.add_argument("--check", action="store_true",
                    help="cheap monitor mode: list pending versions, no key needed, writes "
                         "$GITHUB_OUTPUT (has_new/versions) when present")
    ap.add_argument("--publish", action="store_true",
                    help="publish mirrored archives as release assets (default when --repo is set)")
    ap.add_argument("--no-publish", action="store_true", help="download+verify, do not publish")
    ap.add_argument("--repo", default=os.environ.get("REPO") or os.environ.get("GITHUB_REPOSITORY", ""),
                    help="target repo for publishing (owner/name)")
    a = ap.parse_args()

    platforms = [p.strip() for p in a.platforms.split(",") if p.strip()] or PLATFORMS
    kinds = {k.strip() for k in a.kinds.split(",") if k.strip()}
    versions = {v.strip() for v in a.versions.split(",") if v.strip()} or None
    key = os.environ.get("CLOAKBROWSER_LICENSE_KEY", "").strip()
    gh_token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

    if "pro" in kinds and not key and not a.check:
        eprint("WARNING: CLOAKBROWSER_LICENSE_KEY not set — Pro mirroring skipped (free only).")

    state_path = Path(a.state)
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    state.setdefault("pro", {})
    state.setdefault("free", {})
    state.setdefault("skipped", [])
    state.setdefault("seen", [])            # "kind:version" already handled at least once
    seen = set(state["seen"])

    eprint(f"upstream: {UPSTREAM}  platforms: {','.join(platforms)}  kinds: {','.join(sorted(kinds))}")
    releases = list_upstream_releases(gh_token)
    targets = parse_targets(releases, kinds)
    if versions:
        targets = [t for t in targets if t["version"] in versions]
    eprint(f"upstream releases: {len(releases)}, candidate targets: {len(targets)}")

    if a.seed:
        for t in targets:
            seen.add(f'{t["kind"]}:{t["version"]}')
        state["seen"] = sorted(seen)
        _finalize(state, state_path)
        eprint(f"seeded baseline: {len(state['seen'])} upstream version(s) marked as seen")
        return 0

    if a.check:
        pending = []
        for t in targets:
            if f'{t["kind"]}:{t["version"]}' in seen:
                continue                    # already handled at least once
            for platform in platforms:
                if not state[t["kind"]].get(t["version"], {}).get(platform):
                    pending.append(f'{t["kind"]}:{t["version"]}:{platform}')
        if "pro" in kinds and not a.no_platform_latest:
            for platform in platforms:
                try:
                    r = httpx.get(f"{SITE}/api/download/version",
                                  headers={"X-Platform": platform, "User-Agent": UA},
                                  timeout=20)
                    r.raise_for_status()
                    plat_latest = (r.json() or {}).get("version")
                except Exception as exc:  # noqa: BLE001
                    eprint(f"  platform-latest lookup failed for {platform}: {exc}")
                    continue
                if not plat_latest:
                    continue
                if not state["pro"].get(plat_latest, {}).get(platform):
                    entry = f"pro:{plat_latest}:{platform}"
                    if entry not in pending:
                        pending.append(entry)
                        eprint(f"  platform latest: {platform} -> {plat_latest} (not mirrored)")

        versions = sorted({p.split(":")[1] for p in pending})
        has_new = bool(pending)
        eprint(f"pending platform targets: {len(pending)}")
        for p in pending[:40]:
            eprint(f"  {p}")
        if len(pending) > 40:
            eprint(f"  ... (+{len(pending) - 40} more)")
        print(json.dumps({"has_new": has_new, "pending": len(pending), "versions": versions}))
        out = os.environ.get("GITHUB_OUTPUT")
        if out:
            with open(out, "a") as fh:
                fh.write(f"has_new={'true' if has_new else 'false'}\n")
                fh.write(f"versions={','.join(versions)}\n")
                fh.write(f"kinds={','.join(sorted(kinds))}\n")
        return 0

    downloads = 0
    published = 0
    handled: set[str] = set()

    for t in targets:
        kind, version, tag = t["kind"], t["version"], t["tag"]
        if kind == "pro" and not key:
            continue
        manifest = None
        if kind == "pro":
            try:
                manifest = pro_manifest(version)
            except SystemExit as exc:
                eprint(f"  skip pro {version}: {exc}")
                continue
            except httpx.HTTPStatusError as exc:
                eprint(f"  skip pro {version}: manifest unavailable ({exc.response.status_code})")
                continue

        for platform in platforms:
            already = state[kind].get(version, {}).get(platform)
            if already and not a.force:
                continue
            if downloads >= a.limit:
                eprint("limit reached; remaining targets deferred to the next run")
                _finalize(state, state_path, write=not a.dry_run)
                return 0
            name = archive_name(platform)

            # ---- Pro (key required; free keys only get the platform latest)
            if kind == "pro":
                if name not in (manifest or {}):
                    _skip(state, kind, version, platform, "not_in_manifest", dry=a.dry_run)
                    continue
                try:
                    srv = served_version(version, platform, key)
                except SystemExit as exc:
                    eprint(f"  {version}/{platform}: {exc}")
                    _skip(state, kind, version, platform, "auth_error", dry=a.dry_run)
                    continue
                if srv != version:
                    eprint(f"  skip pro {version}/{platform}: key serves {srv} (pinned needs paid key)")
                    _skip(state, kind, version, platform, "pinned_requires_paid_key", dry=a.dry_run, served=srv)
                    continue
                dest = Path(a.workdir) / f"{kind}-{version}" / name
                eprint(f"  fetch pro {version}/{platform}")
                if a.dry_run:
                    downloads += 1
                    continue
                download(f"{SITE}/api/download/{version}", dest,
                         {"Authorization": f"Bearer {key}", "X-Platform": platform, "User-Agent": UA})
                digest = sha256_file(dest)
                if digest != manifest[name]:
                    dest.unlink(missing_ok=True)
                    raise SystemExit(f"checksum mismatch for {name}: {digest} != {manifest[name]}")
                if not a.no_publish and a.repo:
                    publish(a.repo, tag, dest, f"CloakBrowser Pro {version}",
                            f"Mirror of upstream `{tag}` (verified: Ed25519 manifest + SHA-256).")
                    published += 1
                state[kind].setdefault(version, {})[platform] = {
                    "asset": name, "sha256": digest, "size": dest.stat().st_size,
                    "tag": tag, "mirrored_at": int(time.time()),
                }
                _unskip(state, kind, version, platform)
                dest.unlink(missing_ok=True)
                downloads += 1
                continue

            # ---- free (plain GitHub asset, no key)
            asset = t["assets"].get(name)
            if not asset:
                _skip(state, kind, version, platform, "asset_missing", dry=a.dry_run)
                continue
            manifest_asset = t["assets"].get("SHA256SUMS")
            expected = None
            if manifest_asset:
                try:
                    txt = httpx.get(manifest_asset["browser_download_url"],
                                    headers={"User-Agent": UA}, follow_redirects=True, timeout=30).text
                    expected = parse_checksums(txt).get(name)
                except Exception:
                    expected = None
            dest = Path(a.workdir) / f"{kind}-{version}" / name
            eprint(f"  fetch free {version}/{platform}")
            if a.dry_run:
                downloads += 1
                continue
            download(asset["browser_download_url"], dest)
            digest = sha256_file(dest)
            if expected and digest != expected:
                dest.unlink(missing_ok=True)
                raise SystemExit(f"checksum mismatch for {name}: {digest} != {expected}")
            if not a.no_publish and a.repo:
                publish(a.repo, tag, dest, f"CloakBrowser free {version}",
                        f"Mirror of upstream `{tag}` (SHA-256 verified).")
                published += 1
            state[kind].setdefault(version, {})[platform] = {
                "asset": name, "sha256": digest, "size": dest.stat().st_size,
                "tag": tag, "mirrored_at": int(time.time()),
            }
            _unskip(state, kind, version, platform)
            dest.unlink(missing_ok=True)
            downloads += 1
            handled.add(f"{kind}:{version}")

        if not a.dry_run:
            handled.add(f"{kind}:{version}")

    state["seen"] = sorted(seen | handled)
    _finalize(state, state_path, write=not a.dry_run)
    eprint(f"done: {downloads} download(s), {published} published"
           + (" (dry run)" if a.dry_run else ""))
    return 0


def _unskip(state: dict, kind: str, version: str, platform: str) -> None:
    state["skipped"] = [s for s in state.get("skipped", [])
                        if not (s.get("kind") == kind and s.get("version") == version
                                and s.get("platform") == platform)]


def _skip(state: dict, kind: str, version: str, platform: str, reason: str,
          dry: bool = False, **extra) -> None:
    rec = {"kind": kind, "version": version, "platform": platform, "reason": reason, **extra}
    if dry:
        eprint(f"    would skip: {rec}")
        return
    state["skipped"] = [s for s in state["skipped"]
                        if not (s.get("kind") == kind and s.get("version") == version
                                and s.get("platform") == platform)]
    state["skipped"].append(rec)
    eprint(f"    skipped: {rec}")


def _finalize(state: dict, path: Path, write: bool = True) -> None:
    if not write:
        return
    state["updated_at"] = int(time.time())
    state["skipped"] = state["skipped"][-200:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    sys.exit(main())
