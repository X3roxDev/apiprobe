from __future__ import annotations

import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any, Iterable


LOG_FORMAT = "%(levelname)s %(name)s: %(message)s"


def setup_logging(verbose: bool = False) -> None:
    """Configure process-wide logging for CLI use."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=LOG_FORMAT,
    )


def human_size(num_bytes: int | float) -> str:
    """Return a compact human-readable byte count."""
    value = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def write_json(path: str | Path, data: Any) -> None:
    """Write JSON with stable formatting."""
    with Path(path).open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True, default=str)
        handle.write("\n")


def write_csv(path: str | Path, rows: Iterable[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    """Write dictionaries to CSV."""
    materialized = list(rows)
    if not materialized and not fieldnames:
        fieldnames = []
    if fieldnames is None:
        keys: set[str] = set()
        for row in materialized:
            keys.update(row.keys())
        fieldnames = sorted(keys)
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(materialized)


def exit_for_error(message: str, code: int = 1) -> int:
    """Print a user-focused error message and return an exit code."""
    print(f"error: {message}", file=sys.stderr)
    return code


import csv
import fnmatch
import hashlib
import json
import math
import os
import platform
import re
import shutil
import socket
import ssl
import statistics
import subprocess
import time
import tracemalloc
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Any


def iter_files(root: str | Path, ignores: Iterable[str] = ()) -> Iterable[Path]:
    """Yield files under root while applying shell-style ignore patterns."""
    root_path = Path(root)
    patterns = tuple(ignores)
    for path in root_path.rglob("*"):
        rel = path.relative_to(root_path).as_posix()
        if any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in patterns):
            continue
        if path.is_file():
            yield path


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """Hash a file incrementally with SHA-256."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fileguard_baseline(paths: Iterable[str | Path], ignores: Iterable[str] = ()) -> dict[str, dict[str, object]]:
    baseline: dict[str, dict[str, object]] = {}
    for root in paths:
        root_path = Path(root).resolve()
        for path in iter_files(root_path, ignores):
            stat = path.stat()
            baseline[str(path)] = {"sha256": sha256_file(path), "size": stat.st_size, "modified": stat.st_mtime}
    return baseline


def fileguard_compare(old: dict[str, dict[str, object]], new: dict[str, dict[str, object]]) -> dict[str, list[str]]:
    old_keys, new_keys = set(old), set(new)
    modified = sorted(path for path in old_keys & new_keys if old[path].get("sha256") != new[path].get("sha256"))
    return {"created": sorted(new_keys - old_keys), "modified": modified, "deleted": sorted(old_keys - new_keys)}


SECRET_PATTERNS = {
    "api-key": re.compile(r"(?i)(api[_-]?key|token|secret)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_-]{16,})"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "db-url": re.compile(r"(?i)(postgres|mysql|mongodb)://[^\s'\\\"]+"),
    "password": re.compile(r"(?i)password\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def scan_secrets(root: str | Path, ignores: Iterable[str] = (".git/*",), entropy_threshold: float = 4.5) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for path in iter_files(root, ignores):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            for name, pattern in SECRET_PATTERNS.items():
                match = pattern.search(line)
                if match:
                    findings.append({"path": str(path), "line": number, "rule": name, "severity": "high", "evidence": "[redacted]"})
            for token in re.findall(r"[A-Za-z0-9_-]{24,}", line):
                if shannon_entropy(token) >= entropy_threshold:
                    findings.append({"path": str(path), "line": number, "rule": "high-entropy-token", "severity": "medium", "evidence": "[redacted]"})
    return findings


def inspect_tls(host: str, port: int = 443, timeout: float = 3.0) -> dict[str, object]:
    context = ssl.create_default_context()
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            expires_raw = cert.get("notAfter", "")
            expires = datetime.strptime(expires_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if expires_raw else None
            san = [value for key, value in cert.get("subjectAltName", []) if key == "DNS"]
            return {"host": host, "port": port, "protocol": tls.version(), "cipher": tls.cipher()[0] if tls.cipher() else None, "issuer": cert.get("issuer"), "subject": cert.get("subject"), "sans": san, "expires": expires.isoformat() if expires else None, "days_until_expiry": (expires - datetime.now(timezone.utc)).days if expires else None, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}


def dns_query(domain: str, record_type: str = "A") -> dict[str, object]:
    started = time.perf_counter()
    records: list[str] = []
    if record_type in {"A", "AAAA"}:
        family = socket.AF_INET if record_type == "A" else socket.AF_INET6
        try:
            records = sorted({item[4][0] for item in socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)})
        except socket.gaierror:
            records = []
    else:
        try:
            output = subprocess.check_output(["nslookup", f"-type={record_type}", domain], text=True, stderr=subprocess.STDOUT, timeout=5)
            records = [line.strip() for line in output.splitlines() if line.strip() and "server" not in line.lower()]
        except (OSError, subprocess.SubprocessError):
            records = []
    return {"domain": domain, "type": record_type, "records": records, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}


def reverse_dns(address: str) -> dict[str, object]:
    try:
        host, aliases, _ = socket.gethostbyaddr(address)
        return {"address": address, "hostname": host, "aliases": aliases}
    except OSError as exc:
        return {"address": address, "error": str(exc)}


def list_processes() -> list[dict[str, object]]:
    system = platform.system()
    cmd = ["tasklist", "/FO", "CSV", "/NH"] if system == "Windows" else ["ps", "-eo", "pid,user,comm,args", "--no-headers"]
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return []
    rows: list[dict[str, object]] = []
    for line in output.splitlines():
        if system == "Windows":
            parts = [item.strip('"') for item in line.split('","')]
            if len(parts) >= 2:
                rows.append({"pid": int(parts[1]), "name": parts[0], "username": None, "cmdline": "", "executable": parts[0]})
        else:
            parts = line.split(None, 3)
            if len(parts) >= 4:
                rows.append({"pid": int(parts[0]), "username": parts[1], "name": parts[2], "cmdline": parts[3], "executable": parts[2]})
    return rows


def process_changes(previous: list[dict[str, object]], current: list[dict[str, object]]) -> dict[str, list[int]]:
    old, new = {int(row["pid"]) for row in previous}, {int(row["pid"]) for row in current}
    return {"started": sorted(new - old), "terminated": sorted(old - new)}


def suspicious_processes(processes: list[dict[str, object]], rules: Iterable[str]) -> list[dict[str, object]]:
    patterns = tuple(rules)
    return [proc for proc in processes if any(fnmatch.fnmatch(str(proc.get("cmdline", "")), pattern) or fnmatch.fnmatch(str(proc.get("executable", "")), pattern) for pattern in patterns)]


def analyze_disk(root: str | Path, min_duplicate_size: int = 1) -> dict[str, object]:
    root_path = Path(root)
    files: list[tuple[Path, int]] = []
    ext = Counter()
    empty_dirs: list[str] = []
    dir_sizes = Counter()
    for current, dirs, names in os.walk(root_path):
        current_path = Path(current)
        if not dirs and not names:
            empty_dirs.append(str(current_path))
        for name in names:
            path = current_path / name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            files.append((path, size))
            ext[path.suffix.lower() or "[none]"] += 1
            for parent in [path.parent, *path.parents]:
                if root_path in parent.parents or parent == root_path:
                    dir_sizes[str(parent)] += size
    hash_groups: dict[str, list[str]] = {}
    for path, size in files:
        if size >= min_duplicate_size:
            hash_groups.setdefault(sha256_file(path), []).append(str(path))
    duplicates = [group for group in hash_groups.values() if len(group) > 1]
    return {"total_size": sum(size for _, size in files), "file_count": len(files), "largest_files": [(str(p), s) for p, s in sorted(files, key=lambda item: item[1], reverse=True)[:20]], "largest_directories": dir_sizes.most_common(20), "extensions": dict(ext), "duplicates": duplicates, "empty_directories": empty_dirs}


def create_backup(source: str | Path, destination: str | Path, excludes: Iterable[str] = (), dry_run: bool = False) -> dict[str, object]:
    source_path = Path(source).resolve()
    dest_path = Path(destination)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    archive = dest_path / f"{source_path.name}-{stamp}.zip"
    files = list(iter_files(source_path, excludes))
    manifest = {str(path.relative_to(source_path)): sha256_file(path) for path in files}
    if dry_run:
        return {"archive": str(archive), "files": len(files), "dry_run": True}
    dest_path.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            zf.write(path, path.relative_to(source_path))
        zf.writestr("backup-manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
    return {"archive": str(archive), "files": len(files), "sha256": sha256_file(archive), "dry_run": False}


def parse_netstat(output: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].lower().startswith(("tcp", "udp")):
            local = next((part for part in parts[1:] if ":" in part and not part.startswith("0:")), parts[1])
            pid = parts[-1] if parts[-1].isdigit() else ""
            port = local.rsplit(":", 1)[-1]
            if port.isdigit():
                rows.append({"protocol": parts[0], "local_address": local, "port": int(port), "pid": int(pid) if pid else None})
    return rows


def listening_ports() -> list[dict[str, object]]:
    args = ["netstat", "-ano"] if platform.system() == "Windows" else ["netstat", "-tuln"]
    try:
        return parse_netstat(subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL))
    except (OSError, subprocess.CalledProcessError):
        return []


def build_request(method: str, url: str, params: dict[str, str] | None = None, headers: dict[str, str] | None = None, body: str | bytes | None = None) -> urllib.request.Request:
    if params:
        separator = "&" if urllib.parse.urlparse(url).query else "?"
        url = url + separator + urllib.parse.urlencode(params)
    data = body.encode("utf-8") if isinstance(body, str) else body
    return urllib.request.Request(url, data=data, headers=headers or {}, method=method.upper())


def send_request(request: urllib.request.Request, timeout: float = 10.0) -> dict[str, object]:
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
        return {"status": response.status, "headers": dict(response.headers.items()), "body": body.decode("utf-8", "replace"), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}


def hash_text(text: str, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def hash_file(path: str | Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_manifest(root: str | Path, algorithm: str = "sha256") -> dict[str, str]:
    root_path = Path(root)
    return {str(path.relative_to(root_path)): hash_file(path, algorithm) for path in iter_files(root_path)}


def verify_manifest(root: str | Path, manifest: dict[str, str], algorithm: str = "sha256") -> dict[str, list[str]]:
    root_path = Path(root)
    missing, changed, ok = [], [], []
    for rel, expected in manifest.items():
        path = root_path / rel
        if not path.exists():
            missing.append(rel)
        elif hash_file(path, algorithm) != expected:
            changed.append(rel)
        else:
            ok.append(rel)
    return {"ok": ok, "missing": missing, "changed": changed}


def read_network_counters() -> dict[str, dict[str, int]]:
    proc = Path("/proc/net/dev")
    counters: dict[str, dict[str, int]] = {}
    if proc.exists():
        for line in proc.read_text(encoding="utf-8").splitlines()[2:]:
            name, raw = line.split(":", 1)
            parts = raw.split()
            counters[name.strip()] = {"bytes_recv": int(parts[0]), "packets_recv": int(parts[1]), "bytes_sent": int(parts[8]), "packets_sent": int(parts[9])}
    return counters


def network_rate(before: dict[str, dict[str, int]], after: dict[str, dict[str, int]], seconds: float) -> dict[str, dict[str, float]]:
    rates: dict[str, dict[str, float]] = {}
    for name, later in after.items():
        earlier = before.get(name)
        if earlier and seconds > 0:
            rates[name] = {"download_bps": (later["bytes_recv"] - earlier["bytes_recv"]) / seconds, "upload_bps": (later["bytes_sent"] - earlier["bytes_sent"]) / seconds}
    return rates


def detect_json_duplicates(text: str) -> list[str]:
    duplicates: list[str] = []
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen:
                duplicates.append(key)
            seen.add(key)
        return dict(pairs)
    json.loads(text, object_pairs_hook=hook)
    return duplicates


def validate_config(path: str | Path, required_keys: Iterable[str] = ()) -> dict[str, object]:
    path_obj = Path(path)
    text = path_obj.read_text(encoding="utf-8")
    suffix = path_obj.suffix.lower()
    errors: list[str] = []
    data: Any = {}
    try:
        if suffix == ".json":
            duplicates = detect_json_duplicates(text)
            data = json.loads(text)
            errors.extend(f"duplicate key: {key}" for key in duplicates)
        elif suffix == ".toml":
            import tomllib
            data = tomllib.loads(text)
        elif suffix in {".env", ""}:
            data = {}
            seen: set[str] = set()
            for number, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "=" not in stripped:
                    errors.append(f"line {number}: missing '='")
                    continue
                key, value = stripped.split("=", 1)
                if key in seen:
                    errors.append(f"duplicate key: {key}")
                seen.add(key)
                data[key] = value
        elif suffix in {".yaml", ".yml"}:
            data = {}
            for number, line in enumerate(text.splitlines(), 1):
                if ":" in line and not line.lstrip().startswith("#"):
                    key, value = line.split(":", 1)
                    data[key.strip()] = value.strip()
                elif line.strip() and not line.lstrip().startswith("#"):
                    errors.append(f"line {number}: unsupported YAML shape")
        else:
            errors.append(f"unsupported config extension: {suffix}")
    except Exception as exc:
        errors.append(str(exc))
    missing = [key for key in required_keys if isinstance(data, dict) and key not in data]
    errors.extend(f"missing required key: {key}" for key in missing)
    return {"valid": not errors, "errors": errors, "data": data}


def analyze_repo(root: str | Path) -> dict[str, object]:
    root_path = Path(root)
    files = [path for path in iter_files(root_path, [".git/*"])]
    sizes = [(str(path.relative_to(root_path)), path.stat().st_size) for path in files]
    text_findings = []
    for path in files:
        try:
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if "TODO" in line or "FIXME" in line:
                    text_findings.append({"path": str(path.relative_to(root_path)), "line": number, "text": line.strip()[:120]})
        except OSError:
            continue
    missing = [name for name in ["README.md", "LICENSE", ".gitignore"] if not (root_path / name).exists()]
    return {"file_count": len(files), "total_size": sum(size for _, size in sizes), "extensions": dict(Counter(Path(name).suffix.lower() or "[none]" for name, _ in sizes)), "large_files": sorted(sizes, key=lambda item: item[1], reverse=True)[:20], "empty_files": [name for name, size in sizes if size == 0], "todo_comments": text_findings, "potential_secrets": scan_secrets(root_path), "missing_standard_files": missing}


def collision_safe_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    counter = 1
    while True:
        candidate = path.with_name(f"{stem} ({counter}){suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def organize_plan(root: str | Path, mode: str = "extension") -> list[dict[str, str]]:
    root_path = Path(root)
    moves: list[dict[str, str]] = []
    for path in root_path.iterdir():
        if not path.is_file():
            continue
        if mode == "date":
            folder = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m")
        else:
            folder = (path.suffix.lower().lstrip(".") or "no-extension")
        destination = collision_safe_path(root_path / folder / path.name)
        moves.append({"source": str(path), "destination": str(destination)})
    return moves


def execute_moves(moves: list[dict[str, str]], dry_run: bool = True) -> dict[str, object]:
    completed: list[dict[str, str]] = []
    if dry_run:
        return {"dry_run": True, "moves": moves}
    for move in moves:
        source, destination = Path(move["source"]), Path(move["destination"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
        completed.append(move)
    return {"dry_run": False, "moves": completed}


def benchmark_callable(func: Callable[[], Any], repeats: int = 5, warmups: int = 1) -> dict[str, object]:
    for _ in range(max(0, warmups)):
        func()
    timings: list[float] = []
    tracemalloc.start()
    for _ in range(max(1, repeats)):
        started = time.perf_counter()
        func()
        timings.append(time.perf_counter() - started)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"runs": len(timings), "mean": statistics.mean(timings), "median": statistics.median(timings), "min": min(timings), "max": max(timings), "stdev": statistics.stdev(timings) if len(timings) > 1 else 0.0, "peak_memory_bytes": peak}


def compare_runs(first: dict[str, object], second: dict[str, object]) -> dict[str, float]:
    return {"mean_delta": float(second["mean"]) - float(first["mean"]), "mean_ratio": float(second["mean"]) / float(first["mean"]) if float(first["mean"]) else 0.0}


def parse_systemctl(output: str) -> list[dict[str, str]]:
    services = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4 and parts[0].endswith(".service"):
            services.append({"name": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3], "description": parts[4] if len(parts) > 4 else ""})
    return services


def list_services() -> list[dict[str, str]]:
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(["sc", "query", "state=", "all"], text=True, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.CalledProcessError):
            return []
        services: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("SERVICE_NAME:"):
                if current:
                    services.append(current)
                current = {"name": stripped.split(":", 1)[1].strip()}
            elif stripped.startswith("STATE"):
                current["state"] = stripped.split(":", 1)[1].strip()
        if current:
            services.append(current)
        return services
    try:
        output = subprocess.check_output(["systemctl", "list-units", "--type=service", "--all", "--no-legend"], text=True, stderr=subprocess.DEVNULL)
        return parse_systemctl(output)
    except (OSError, subprocess.CalledProcessError):
        return []


def devopsbox_collect() -> dict[str, object]:
    disk = shutil.disk_usage(Path.cwd().anchor or ".")
    docker = shutil.which("docker")
    git = shutil.which("git")
    return {"system": {"platform": platform.platform(), "python": platform.python_version()}, "disk": {"total": disk.total, "used": disk.used, "free": disk.free}, "process_count": len(list_processes()), "ports": listening_ports()[:20], "services": list_services()[:20], "docker": {"installed": bool(docker), "path": docker}, "git": {"installed": bool(git), "path": git}, "environment": {"path_entries": len(os.environ.get("PATH", "").split(os.pathsep))}, "security": {"home_env_set": bool(os.environ.get("HOME") or os.environ.get("USERPROFILE"))}}


import argparse
import json
import time
from pathlib import Path
from pprint import pprint


def _kv(values: list[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            raise ValueError(f"expected KEY=VALUE, got {item}")
        key, value = item.split("=", 1)
        result[key] = value
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="apiprobe", description="Command-line HTTP and API testing client built on Python stdlib.")
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    req = sub.add_parser("request"); req.add_argument("method"); req.add_argument("url"); req.add_argument("--header", action="append"); req.add_argument("--param", action="append"); req.add_argument("--body"); req.add_argument("--timeout", type=float, default=10.0); req.add_argument("--save"); req.add_argument("--json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    try:
        if args.command == "request":
            request = build_request(args.method, args.url, _kv(args.param), _kv(args.header), args.body)
            data = send_request(request, args.timeout)
            if args.save:
                Path(args.save).write_text(str(data["body"]), encoding="utf-8")
            pprint({k: v for k, v in data.items() if k != "body"})
            if args.json:
                write_json(args.json, data)
        return 0
    except KeyboardInterrupt:
        return exit_for_error("interrupted", 130)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return exit_for_error(str(exc), 2)


if __name__ == "__main__":
    raise SystemExit(main())

