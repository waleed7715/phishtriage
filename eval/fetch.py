"""Fetch phishing_pot at a pinned commit (outside the repo) and write a SHA-256 manifest."""

from __future__ import annotations

import argparse
import csv
import hashlib
import shutil
import subprocess
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG = REPO_ROOT / "eval" / "dataset.toml"


def git(*args: str, cwd: Path | None = None) -> str:
    exe = shutil.which("git")
    if exe is None:
        raise SystemExit("git not found on PATH")
    # Arguments come from this script and the pinned config, never from user input.
    result = subprocess.run(  # noqa: S603
        [exe, *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", type=Path, default=Path.home() / "data" / "phishing_pot")
    args = parser.parse_args()

    cfg = tomllib.loads(CONFIG.read_text())["phishing_pot"]
    url, commit = cfg["url"], cfg["commit"]
    dest: Path = args.dest.expanduser().resolve()

    if dest == REPO_ROOT or REPO_ROOT in dest.parents:
        raise SystemExit(f"refusing to place samples inside the repo: {dest}")

    if not (dest / ".git").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        git("clone", "--filter=blob:none", "--no-checkout", url, str(dest))
        (dest / ".git" / "info").mkdir(parents=True, exist_ok=True)
        (dest / ".git" / "info" / "attributes").write_text("* -text\n")
    git("fetch", "--quiet", "origin", commit, cwd=dest)
    git("checkout", "--quiet", "--detach", commit, cwd=dest)
    if (head := git("rev-parse", "HEAD", cwd=dest)) != commit:
        raise SystemExit(f"checked out {head}, expected {commit}")
    dest.chmod(0o700)
    manifest = dest.parent / f"{dest.name}-manifest.csv"

    files = sorted((dest / "email").glob("*.eml"))
    with manifest.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "sha256", "label", "source", "commit"])
        for p in files:
            rel = p.relative_to(dest).as_posix()
            # Provisional label: the dataset also contains spam/fraud; test split gets hand-labeled.
            writer.writerow([rel, sha256(p), "phishing", "phishing_pot", commit])
    print(f"wrote {len(files)} rows to {manifest} at commit {commit[:12]}")


if __name__ == "__main__":
    main()
