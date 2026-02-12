#!/usr/bin/env python
import os
import re
import json
import difflib
import sys
import datetime
import xml.etree.ElementTree as ET
import subprocess
import shutil
import hashlib
import threading
from typing import List, Dict, Any, Optional
from collections import Counter

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("repo-diff-enhanced")

# ====================================================================================
# CONFIG: MODULE AND PACKAGE MAPPING (manual overrides)
# ====================================================================================

# Manual module mapping hints - Quarkus multimodule -> Spring standalone projects
MANUAL_MODULE_MAP = {
    "demo-module-api-1": "demo-module-api-1",
    "demo-module-api-2": "demo-module-api-2",
    "demo-module-api-3": "demo-module-api-3",
    "demo-module-api-4": "demo-module-api-4",
    "demo-module-api-5": None,  # often maps to root module in Spring world
}

# Package mappings (example from your screenshot case)
PACKAGE_MAP = {
    "com.quarkus.project": "com.springboot.project"
}


def log_startup():
    print("")
    print("=" * 80)
    print(f"[MCP] Starting MCP Server: repo-diff-enhanced")
    print(f"[MCP] Timestamp:  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[MCP] Python:     {sys.version.split()[0]}")
    print(f"[MCP] File:       {os.path.abspath(__file__)}")
    print(f"[MCP] CWD:        {os.getcwd()}")
    print("=" * 80)
    print("")


# ====================================================================================
# Helper Functions
# ====================================================================================

_CACHE_LOCK = threading.RLock()
_REPO_CACHE: Dict[str, Dict[str, Any]] = {}
_FILE_TEXT_CACHE: Dict[str, Dict[str, Any]] = {}
_FILE_HASH_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_MAX_TEXT = 512
_CACHE_MAX_HASH = 4096


def _prune_cache(cache: Dict[str, Dict[str, Any]], max_entries: int) -> None:
    if len(cache) <= max_entries:
        return
    # Simple prune: drop oldest entries by last_access
    items = sorted(cache.items(), key=lambda kv: kv[1].get("last_access", 0))
    for k, _ in items[: max(0, len(cache) - max_entries)]:
        cache.pop(k, None)


def _repo_state_signature(repo_root: str, include_untracked: bool = True) -> str:
    try:
        head = _git(repo_root, ["rev-parse", "HEAD"]).strip()
    except Exception:
        head = "no-head"
    status_args = ["status", "--porcelain", "-z"]
    if not include_untracked:
        status_args.append("-uno")
    try:
        status = _git(repo_root, status_args)
    except Exception:
        status = ""
    data = (head + "\0" + status).encode("utf-8", errors="ignore")
    return hashlib.sha1(data).hexdigest()


def _get_java_files_cached(
    repo_root: str,
    use_cache: bool = True,
    refresh_cache: bool = False,
    include_untracked: bool = True,
) -> Dict[str, str]:
    if not use_cache:
        return _collect_java_files(repo_root, use_cache=False)

    sig = _repo_state_signature(repo_root, include_untracked=include_untracked)
    with _CACHE_LOCK:
        entry = _REPO_CACHE.get(repo_root)
        if entry and not refresh_cache and entry.get("state_sig") == sig:
            entry["last_access"] = datetime.datetime.now().timestamp()
            return entry["java_files"]

    files = _collect_java_files(repo_root, use_cache=False)
    with _CACHE_LOCK:
        _REPO_CACHE[repo_root] = {
            "state_sig": sig,
            "java_files": files,
            "last_access": datetime.datetime.now().timestamp(),
        }
        _prune_cache(_REPO_CACHE, 64)
    return files

def _normalize_path(path: str) -> str:
    norm = os.path.normpath(path)
    norm = norm.replace(os.sep, "/")
    return norm


def _read_file_text(path: str) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            with open(path, "r", encoding=enc, errors="strict") as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _read_file_text_cached(path: str, use_cache: bool = True) -> str:
    if not use_cache:
        return _read_file_text(path)

    try:
        st = os.stat(path)
    except OSError:
        return _read_file_text(path)

    cache_key = f"{path}|{st.st_mtime_ns}|{st.st_size}"
    with _CACHE_LOCK:
        entry = _FILE_TEXT_CACHE.get(cache_key)
        if entry:
            entry["last_access"] = datetime.datetime.now().timestamp()
            return entry["text"]

    text = _read_file_text(path)
    with _CACHE_LOCK:
        _FILE_TEXT_CACHE[cache_key] = {
            "text": text,
            "last_access": datetime.datetime.now().timestamp(),
        }
        _prune_cache(_FILE_TEXT_CACHE, _CACHE_MAX_TEXT)
    return text


def _file_hash(path: str, use_cache: bool = True) -> str:
    if not use_cache:
        return _file_hash_uncached(path)

    try:
        st = os.stat(path)
    except OSError:
        return _file_hash_uncached(path)

    cache_key = f"{path}|{st.st_mtime_ns}|{st.st_size}"
    with _CACHE_LOCK:
        entry = _FILE_HASH_CACHE.get(cache_key)
        if entry:
            entry["last_access"] = datetime.datetime.now().timestamp()
            return entry["hash"]

    h = _file_hash_uncached(path)
    with _CACHE_LOCK:
        _FILE_HASH_CACHE[cache_key] = {
            "hash": h,
            "last_access": datetime.datetime.now().timestamp(),
        }
        _prune_cache(_FILE_HASH_CACHE, _CACHE_MAX_HASH)
    return h


def _file_hash_uncached(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(repo_root: str, args: List[str]) -> str:
    completed = subprocess.run(
        ["git", "-C", repo_root] + args,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


def _git_diff(repo_root: str, args: List[str]) -> str:
    completed = subprocess.run(
        ["git", "-C", repo_root] + args,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode not in (0, 1):
        err = (completed.stderr or "").strip()
        raise ValueError(f"git diff failed in {repo_root}" + (f": {err}" if err else ""))
    return completed.stdout


def _validate_repo_path(path: str, must_be_git: bool = True) -> str:
    root = os.path.abspath(path)
    if not os.path.isdir(root):
        raise ValueError(f"Repo path is not a directory: {root}")
    if must_be_git:
        try:
            _git(root, ["rev-parse", "--show-toplevel"])
        except subprocess.CalledProcessError as e:
            msg = (e.stderr or "").strip()
            raise ValueError(
                f"Repo path is not a git repo or is inaccessible: {root}"
                + (f" ({msg})" if msg else "")
            )
    return root


def _collect_changed_files(
    repo_root: str,
    commit: str,
    include_staged: bool = True,
    include_untracked: bool = False,
) -> Dict[str, Any]:
    changed = set()

    for line in _git_diff(repo_root, ["diff", "--name-only", commit]).splitlines():
        if line:
            changed.add(_normalize_path(line.strip()))

    if include_staged:
        for line in _git_diff(repo_root, ["diff", "--name-only", "--cached", commit]).splitlines():
            if line:
                changed.add(_normalize_path(line.strip()))

    untracked = set()
    if include_untracked:
        for line in _git(repo_root, ["ls-files", "--others", "--exclude-standard"]).splitlines():
            if line:
                untracked.add(_normalize_path(line.strip()))
        changed |= untracked

    return {
        "changed_files": sorted(changed),
        "untracked_files": sorted(untracked),
    }


def _collect_java_files(
    root: str,
    exclude_dirs=None,
    use_cache: bool = True,
    refresh_cache: bool = False,
    include_untracked: bool = True,
) -> Dict[str, str]:
    # If caller uses custom excludes, skip cache to avoid mismatched results.
    if exclude_dirs:
        use_cache = False

    if use_cache:
        return _get_java_files_cached(
            root,
            use_cache=True,
            refresh_cache=refresh_cache,
            include_untracked=include_untracked,
        )

    exclude_dirs = set(exclude_dirs or [])
    files: Dict[str, str] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in exclude_dirs
            and not d.startswith(".git")
            and d not in ("build", "target", ".idea", ".vscode", "out")
        ]

        for fname in filenames:
            if not fname.endswith(".java"):
                continue
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root)
            rel = _normalize_path(rel)
            files[rel] = full

    return files


def normalize_java_relpath(rel: str) -> str:
    return normalize_java_relpath_with_maps(rel, MANUAL_MODULE_MAP, PACKAGE_MAP)


def normalize_java_relpath_with_maps(
    rel: str,
    module_map: Optional[Dict[str, Optional[str]]] = None,
    package_map: Optional[Dict[str, str]] = None,
) -> str:
    """
    Normalize Java file paths by:
      - stripping or remapping known module prefixes
      - applying package mapping
    This gives a cross-repo comparable key like:
        src/main/java/.../JobIdConverter.java
    """
    module_map = module_map or {}
    package_map = package_map or {}

    parts = rel.split("/")
    if parts and parts[0] in module_map:
        mapped = module_map.get(parts[0])
        if mapped is None:
            parts = parts[1:]
        else:
            parts[0] = mapped
    rel = "/".join(parts)

    for left_pkg, right_pkg in package_map.items():
        rel = rel.replace(left_pkg.replace(".", "/"), right_pkg.replace(".", "/"))

    return rel


def _apply_path_remap(rel_path: str, rules: Optional[List[Dict[str, str]]]) -> str:
    if not rules:
        return rel_path
    for rule in rules:
        src = rule.get("from")
        dst = rule.get("to", "")
        mode = rule.get("mode", "prefix")
        if not src:
            continue
        if mode == "prefix":
            if rel_path.startswith(src):
                return dst + rel_path[len(src):]
        elif mode == "replace":
            if src in rel_path:
                return rel_path.replace(src, dst)
        elif mode == "regex":
            try:
                if re.search(src, rel_path):
                    return re.sub(src, dst, rel_path)
            except re.error:
                continue
    return rel_path


def _rewrite_patch_paths(patch_text: str, old_path: str, new_path: str) -> str:
    if old_path == new_path:
        return patch_text

    lines = []
    for line in patch_text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            parts = line.strip().split()
            if len(parts) >= 4 and parts[2] == old_path and parts[3] == old_path:
                line = line.replace(f"diff --git {old_path} {old_path}",
                                   f"diff --git {new_path} {new_path}")
        elif line.startswith("--- ") or line.startswith("+++ "):
            prefix = line[:4]
            path = line[4:].strip()
            if path == old_path:
                line = prefix + new_path + ("\n" if line.endswith("\n") else "")
        elif line.startswith("rename from "):
            path = line[len("rename from "):].strip()
            if path == old_path:
                line = "rename from " + new_path + ("\n" if line.endswith("\n") else "")
        elif line.startswith("rename to "):
            path = line[len("rename to "):].strip()
            if path == old_path:
                line = "rename to " + new_path + ("\n" if line.endswith("\n") else "")
        lines.append(line)
    return "".join(lines)


def _patch_line_stats(patch_text: str) -> Dict[str, int]:
    added = 0
    removed = 0
    for line in patch_text.splitlines():
        if line.startswith("+++ ") or line.startswith("--- "):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1
    return {"added": added, "removed": removed}


def _filter_paths_by_prefixes(
    paths: List[str],
    include_prefixes: Optional[List[str]] = None,
    exclude_prefixes: Optional[List[str]] = None,
) -> List[str]:
    if not include_prefixes and not exclude_prefixes:
        return paths

    def norm_prefix(p: str) -> str:
        p = _normalize_path(p)
        if p and not p.endswith("/"):
            p += "/"
        return p

    include_norm = [norm_prefix(p) for p in (include_prefixes or []) if p]
    exclude_norm = [norm_prefix(p) for p in (exclude_prefixes or []) if p]

    filtered = []
    for path in paths:
        p = _normalize_path(path)
        if include_norm and not any(p.startswith(pref) for pref in include_norm):
            continue
        if exclude_norm and any(p.startswith(pref) for pref in exclude_norm):
            continue
        filtered.append(path)
    return filtered


# ====================================================================================
# Repo analysis helpers
# ====================================================================================

def _parse_pom(pom_path: str) -> Dict[str, Any]:
    """
    Minimal pom.xml parser to extract:
      - groupId
      - artifactId
      - packaging
      - modules
      - frameworks (quarkus / spring-boot)
    """
    result: Dict[str, Any] = {
        "is_maven": True,
        "packaging": None,
        "groupId": None,
        "artifactId": None,
        "modules": [],
        "frameworks": [],
    }

    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()

        # handle namespaces like {http://maven.apache.org/POM/4.0.0}project
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        def find_text(tag: str) -> Optional[str]:
            """
            Find direct child text under project, and fallback to parent/groupId/... if needed.
            """
            el = root.find(f"{ns}{tag}")
            if el is not None and el.text:
                return el.text.strip()

            # Common Maven pattern: groupId in <parent>
            if tag in ("groupId", "version"):
                parent = root.find(f"{ns}parent")
                if parent is not None:
                    pel = parent.find(f"{ns}{tag}")
                    if pel is not None and pel.text:
                        return pel.text.strip()

            return None

        result["groupId"] = find_text("groupId")
        result["artifactId"] = find_text("artifactId")
        result["packaging"] = find_text("packaging")

        # --- modules ---
        modules_el = root.find(f"{ns}modules")
        if modules_el is not None:
            for mod in modules_el.findall(f"{ns}module"):
                if mod.text:
                    result["modules"].append(mod.text.strip())

        # --- dependencies: detect frameworks ---
        deps_el = root.find(f"{ns}dependencies")
        if deps_el is not None:
            for dep in deps_el.findall(f"{ns}dependency"):
                g = dep.find(f"{ns}groupId")
                a = dep.find(f"{ns}artifactId")
                group = (g.text.strip() if g is not None and g.text else "") if g is not None else ""
                art = (a.text.strip() if a is not None and a.text else "") if a is not None else ""

                # Quarkus
                if "quarkus" in art or group.startswith("io.quarkus"):
                    if "quarkus" not in result["frameworks"]:
                        result["frameworks"].append("quarkus")

                # Spring Boot
                if "spring-boot-starter" in art or group.startswith("org.springframework.boot"):
                    if "spring-boot" not in result["frameworks"]:
                        result["frameworks"].append("spring-boot")

        # --- build plugins: also detect frameworks ---
        build_el = root.find(f"{ns}build")
        if build_el is not None:
            plugins_el = build_el.find(f"{ns}plugins")
            if plugins_el is not None:
                for pl in plugins_el.findall(f"{ns}plugin"):
                    g = pl.find(f"{ns}groupId")
                    a = pl.find(f"{ns}artifactId")
                    group = (g.text.strip() if g is not None and g.text else "") if g is not None else ""
                    art = (a.text.strip() if a is not None and a.text else "") if a is not None else ""

                    # Quarkus Maven plugin
                    if "quarkus-maven-plugin" in art or group == "io.quarkus":
                        if "quarkus" not in result["frameworks"]:
                            result["frameworks"].append("quarkus")

                    # Spring Boot Maven plugin
                    if "spring-boot-maven-plugin" in art or group == "org.springframework.boot":
                        if "spring-boot" not in result["frameworks"]:
                            result["frameworks"].append("spring-boot")

    except Exception as e:
        result["error"] = f"Failed to parse pom.xml: {e}"

    return result

def _analyze_repo_internal(repo_root: str) -> Dict[str, Any]:
    root = os.path.abspath(repo_root)
    result: Dict[str, Any] = {
        "root": root,
        "build_tool": "unknown",
        "frameworks": [],
        "is_multimodule": False,
        "modules": [],
        "details": {},
    }

    pom_path = os.path.join(root, "pom.xml")
    build_gradle = os.path.join(root, "build.gradle")
    build_gradle_kts = os.path.join(root, "build.gradle.kts")
    settings_gradle = os.path.join(root, "settings.gradle")
    settings_gradle_kts = os.path.join(root, "settings.gradle.kts")

    # Maven
    if os.path.isfile(pom_path):
        result["build_tool"] = "maven"
        pom_info = _parse_pom(pom_path)
        result["details"]["pom"] = pom_info
        for fw in pom_info.get("frameworks", []):
            if fw not in result["frameworks"]:
                result["frameworks"].append(fw)

        modules = pom_info.get("modules", [])
        if modules:
            result["is_multimodule"] = True
            result["modules"] = modules

        submodule_dirs = []
        for entry in os.listdir(root):
            subdir = os.path.join(root, entry)
            if os.path.isdir(subdir) and os.path.isfile(os.path.join(subdir, "pom.xml")):
                submodule_dirs.append(entry)
        for m in submodule_dirs:
            if m not in result["modules"]:
                result["modules"].append(m)
        if len(result["modules"]) > 1:
            result["is_multimodule"] = True

    # Gradle
    elif os.path.isfile(build_gradle) or os.path.isfile(build_gradle_kts):
        result["build_tool"] = "gradle"
        build_file = build_gradle if os.path.isfile(build_gradle) else build_gradle_kts
        text = _read_file_text(build_file)

        if "io.quarkus" in text or "quarkus-bom" in text:
            if "quarkus" not in result["frameworks"]:
                result["frameworks"].append("quarkus")

        if "org.springframework.boot" in text or "spring-boot-starter" in text:
            if "spring-boot" not in result["frameworks"]:
                result["frameworks"].append("spring-boot")

        settings_file = None
        if os.path.isfile(settings_gradle):
            settings_file = settings_gradle
        elif os.path.isfile(settings_gradle_kts):
            settings_file = settings_gradle_kts

        if settings_file:
            settings_text = _read_file_text(settings_file)
            modules = []
            for line in settings_text.splitlines():
                line = line.strip()
                if line.startswith("include("):
                    parts = line.split("include", 1)[1]
                    parts = parts.replace("(", "").replace(")", "")
                    for piece in parts.split(","):
                        piece = piece.strip().strip("\"' ")
                        if not piece:
                            continue
                        if piece.startswith(":"):
                            piece = piece[1:]
                        if piece and piece not in modules:
                            modules.append(piece)
            if modules:
                result["is_multimodule"] = True
                result["modules"] = modules

    # Config-based extra detection
    config_candidates = [
        os.path.join(root, "src", "main", "resources", "application.properties"),
        os.path.join(root, "src", "main", "resources", "application.yml"),
        os.path.join(root, "src", "main", "resources", "application.yaml"),
    ]
    for cfg in config_candidates:
        if os.path.isfile(cfg):
            cfg_text = _read_file_text(cfg)
            if "quarkus." in cfg_text and "quarkus" not in result["frameworks"]:
                result["frameworks"].append("quarkus")
            if "spring." in cfg_text and "spring-boot" not in result["frameworks"]:
                result["frameworks"].append("spring-boot")

    return result


# ====================================================================================
# Package root detection
# ====================================================================================

PACKAGE_RE = re.compile(r'^\s*package\s+([a-zA-Z0-9_.]+)\s*;')


def _detect_package_roots_internal(
    repo_root: str,
    max_files: int = 5000,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, Any]:
    root = os.path.abspath(repo_root)
    java_files = _collect_java_files(root, use_cache=use_cache, refresh_cache=refresh_cache)
    pkg_counts: Counter[str] = Counter()

    for i, (_, path) in enumerate(java_files.items()):
        if i >= max_files:
            break
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in range(12):
                    line = f.readline()
                    if not line:
                        break
                    m = PACKAGE_RE.match(line)
                    if m:
                        pkg_counts[m.group(1)] += 1
                        break
        except OSError:
            continue

    root_counts: Counter[str] = Counter()
    for pkg, c in pkg_counts.items():
        parts = pkg.split(".")
        for k in range(1, len(parts) + 1):
            root_candidate = ".".join(parts[:k])
            root_counts[root_candidate] += c

    root_candidates = root_counts.most_common(20)
    dominant = root_candidates[0][0] if root_candidates else None

    return {
        "repo_root": root,
        "file_count_scanned": min(len(java_files), max_files),
        "unique_packages_found": len(pkg_counts),
        "package_counts_top20": pkg_counts.most_common(20),
        "root_candidates_top20": root_candidates,
        "dominant_root_package_guess": dominant,
    }


@mcp.tool(title="Detect dominant package roots in a repo")
def detect_package_roots(
    repo_path: str,
    max_files: int = 5000,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, Any]:
    root = _validate_repo_path(repo_path)
    return _detect_package_roots_internal(
        root,
        max_files=max_files,
        use_cache=use_cache,
        refresh_cache=refresh_cache,
    )


# ====================================================================================
# Module similarity detection
# ====================================================================================

def _discover_modules_for_similarity(root: str) -> Dict[str, str]:
    info = _analyze_repo_internal(root)
    modules: Dict[str, str] = {}

    for m in info.get("modules") or []:
        m_root = os.path.join(root, m)
        if os.path.isdir(m_root):
            modules[m] = m_root

    for entry in os.listdir(root):
        sub = os.path.join(root, entry)
        if not os.path.isdir(sub):
            continue
        if os.path.isdir(os.path.join(sub, "src", "main", "java")):
            modules.setdefault(entry, sub)

    modules.setdefault("(root)", root)
    return modules


def _module_fingerprint(
    module_root: str,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, Any]:
    java_files = _collect_java_files(
        module_root, use_cache=use_cache, refresh_cache=refresh_cache
    )
    keys = set()
    for rel in java_files.keys():
        p = rel
        for marker in (
            "src/main/java/",
            "src/test/java/",
            "src/main/kotlin/",
            "src/test/kotlin/",
            "src/",
        ):
            idx = p.find(marker)
            if idx != -1:
                p = p[idx + len(marker):]
                break
        keys.add(p)
    return {
        "file_count": len(java_files),
        "signature_keys": keys,
    }


@mcp.tool(title="Detect similarity between modules of two repos")
def detect_module_similarity(
    repo_a_path: str,
    repo_b_path: str,
    top_n: int = 3,
    min_score: float = 0.1,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, Any]:
    root_a = _validate_repo_path(repo_a_path)
    root_b = _validate_repo_path(repo_b_path)

    modules_a = _discover_modules_for_similarity(root_a)
    modules_b = _discover_modules_for_similarity(root_b)

    fingerprints_a = {
        name: _module_fingerprint(path, use_cache=use_cache, refresh_cache=refresh_cache)
        for name, path in modules_a.items()
    }
    fingerprints_b = {
        name: _module_fingerprint(path, use_cache=use_cache, refresh_cache=refresh_cache)
        for name, path in modules_b.items()
    }

    results = {}

    for name_a, fp_a in fingerprints_a.items():
        sig_a = fp_a["signature_keys"]
        if not sig_a:
            continue

        candidates = []
        for name_b, fp_b in fingerprints_b.items():
            sig_b = fp_b["signature_keys"]
            if not sig_b:
                continue
            inter = len(sig_a & sig_b)
            union = len(sig_a | sig_b)
            score = inter / union if union > 0 else 0.0
            if score >= min_score:
                candidates.append({
                    "module_b": name_b,
                    "score": score,
                    "common_files_estimate": inter,
                    "files_in_a": len(sig_a),
                    "files_in_b": len(sig_b),
                })

        candidates.sort(key=lambda x: x["score"], reverse=True)
        if candidates:
            results[name_a] = candidates[:top_n]

    return {
        "repo_a_root": root_a,
        "repo_b_root": root_b,
        "module_similarity": results,
    }


# ====================================================================================
# API analysis: Quarkus REST vs Spring OpenAPI
# ====================================================================================

HTTP_ANNOTS = {
    "@GET": "GET",
    "@POST": "POST",
    "@PUT": "PUT",
    "@DELETE": "DELETE",
    "@PATCH": "PATCH",
    "@OPTIONS": "OPTIONS",
    "@HEAD": "HEAD",
}
PATH_ANNOT_RE = re.compile(r'@Path\s*\(\s*"([^"]+)"\s*\)')


def _collect_quarkus_endpoints(
    quarkus_root: str,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, Any]:
    root = os.path.abspath(quarkus_root)
    java_files = _collect_java_files(root, use_cache=use_cache, refresh_cache=refresh_cache)
    endpoints = []

    for rel, abs_path in java_files.items():
        try:
            lines = _read_file_text_cached(abs_path, use_cache=use_cache).splitlines()
        except OSError:
            continue

        for idx, line in enumerate(lines):
            http_method = None
            for ann, verb in HTTP_ANNOTS.items():
                if ann in line:
                    http_method = verb
                    break
            if not http_method:
                continue

            path = None
            for back in range(idx, max(idx - 15, -1), -1):
                m = PATH_ANNOT_RE.search(lines[back])
                if m:
                    path = m.group(1)
                    break

            if not path:
                path = "(no-path-found)"

            endpoints.append(
                {
                    "method": http_method,
                    "path": path,
                    "file": _normalize_path(rel),
                    "line": idx + 1,
                }
            )

    return {
        "root": root,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
    }


def _collect_openapi_from_json(spec_path: str) -> List[Dict[str, Any]]:
    with open(spec_path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    paths = data.get("paths", {}) or {}
    ops = []
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for m, info in methods.items():
            http = m.upper()
            if http not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
                continue
            op = {
                "method": http,
                "path": path,
                "operationId": info.get("operationId"),
                "summary": info.get("summary"),
            }
            ops.append(op)
    return ops


def _collect_openapi_from_yaml(spec_path: str) -> List[Dict[str, Any]]:
    with open(spec_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    ops = []
    in_paths = False
    current_path = None

    for line in lines:
        stripped = line.rstrip("\n")

        if not in_paths and stripped.strip() == "paths:":
            in_paths = True
            continue

        if not in_paths:
            continue

        m_path = re.match(r'^\s{2}(/[^:]+):\s*$', stripped)
        if m_path:
            current_path = m_path.group(1)
            continue

        m_method = re.match(r'^\s{4}([a-zA-Z]+):\s*$', stripped)
        if m_method and current_path:
            http = m_method.group(1).upper()
            if http in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
                ops.append(
                    {
                        "method": http,
                        "path": current_path,
                        "operationId": None,
                        "summary": None,
                    }
                )

    return ops


def _discover_openapi_specs(root: str) -> List[str]:
    specs = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".git") and d not in ("build", "target")]
        for fname in filenames:
            lower = fname.lower()
            if not (lower.endswith(".json") or lower.endswith(".yaml") or lower.endswith(".yml")):
                continue
            if "openapi" in lower or "swagger" in lower or "api" in lower:
                specs.append(os.path.join(dirpath, fname))
    return specs


def _collect_openapi_operations(root: str, spec_relative_paths: Optional[List[str]] = None) -> Dict[str, Any]:
    root = os.path.abspath(root)

    spec_files = []
    if spec_relative_paths:
        for rel in spec_relative_paths:
            abs_path = os.path.join(root, rel)
            if os.path.isfile(abs_path):
                spec_files.append(abs_path)
    else:
        spec_files = _discover_openapi_specs(root)

    operations = []

    for spec in spec_files:
        lower = spec.lower()
        try:
            if lower.endswith(".json"):
                ops = _collect_openapi_from_json(spec)
            elif lower.endswith(".yaml") or lower.endswith(".yml"):
                ops = _collect_openapi_from_yaml(spec)
            else:
                continue
            for op in ops:
                op_copy = dict(op)
                op_copy["spec_file"] = spec
                operations.append(op_copy)
        except Exception:
            continue

    return {
        "root": root,
        "spec_files": spec_files,
        "operation_count": len(operations),
        "operations": operations,
    }


@mcp.tool(title="Analyze API differences (Quarkus REST vs Spring OpenAPI)")
def analyze_api_differences(
    quarkus_repo_path: str,
    spring_repo_path: str,
    spring_openapi_relative_paths: Optional[List[str]] = None,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, Any]:
    quarkus_repo_path = _validate_repo_path(quarkus_repo_path)
    spring_repo_path = _validate_repo_path(spring_repo_path)

    quarkus_info = _collect_quarkus_endpoints(
        quarkus_repo_path, use_cache=use_cache, refresh_cache=refresh_cache
    )
    openapi_info = _collect_openapi_operations(spring_repo_path, spec_relative_paths=spring_openapi_relative_paths)

    q_map = {}
    for ep in quarkus_info["endpoints"]:
        key = f'{ep["method"]} {ep["path"]}'
        q_map.setdefault(key, []).append(ep)

    o_map = {}
    for op in openapi_info["operations"]:
        key = f'{op["method"]} {op["path"]}'
        o_map.setdefault(key, []).append(op)

    q_keys = set(q_map.keys())
    o_keys = set(o_map.keys())

    only_q = sorted(q_keys - o_keys)
    only_o = sorted(o_keys - q_keys)
    intersect = sorted(q_keys & o_keys)

    return {
        "quarkus_summary": {
            "root": quarkus_info["root"],
            "endpoint_count": quarkus_info["endpoint_count"],
        },
        "openapi_summary": {
            "root": openapi_info["root"],
            "spec_files": openapi_info["spec_files"],
            "operation_count": openapi_info["operation_count"],
        },
        "only_in_quarkus": [
            {"key": key, "examples": q_map[key][:3]} for key in only_q
        ],
        "only_in_openapi": [
            {"key": key, "examples": o_map[key][:3]} for key in only_o
        ],
        "intersect_count": len(intersect),
    }


# ====================================================================================
# Core MCP tools: analyze, classify, scan, diff, module-to-project compare
# ====================================================================================

@mcp.tool(title="Analyze a Java repo (framework & multimodule detection)")
def analyze_repo(repo_path: str) -> Dict[str, Any]:
    root = _validate_repo_path(repo_path)
    return _analyze_repo_internal(root)


@mcp.tool(title="Classify two repos as Quarkus vs Spring and multimodule")
def classify_two_repos(repo_a_path: str, repo_b_path: str) -> Dict[str, Any]:
    repo_a_path = _validate_repo_path(repo_a_path)
    repo_b_path = _validate_repo_path(repo_b_path)

    a_info = _analyze_repo_internal(repo_a_path)
    b_info = _analyze_repo_internal(repo_b_path)

    def has_fw(info: Dict[str, Any], name: str) -> bool:
        return name in info.get("frameworks", [])

    guessed_quarkus = None
    guessed_spring = None

    if has_fw(a_info, "quarkus") and not has_fw(b_info, "quarkus"):
        guessed_quarkus = "repo_a"
    elif has_fw(b_info, "quarkus") and not has_fw(a_info, "quarkus"):
        guessed_quarkus = "repo_b"

    if has_fw(a_info, "spring-boot") and not has_fw(b_info, "spring-boot"):
        guessed_spring = "repo_a"
    elif has_fw(b_info, "spring-boot") and not has_fw(a_info, "spring-boot"):
        guessed_spring = "repo_b"

    return {
        "repo_a": a_info,
        "repo_b": b_info,
        "module_map_used": MANUAL_MODULE_MAP,
        "package_map_used": PACKAGE_MAP,
        "guessed_quarkus": guessed_quarkus,
        "guessed_spring": guessed_spring,
    }


@mcp.tool(title="Compare two Java repos using module and package mapping")
def scan_repos(
    left_repo_path: str,
    right_repo_path: str,
    left_commit: Optional[str] = None,
    include_staged: bool = True,
    include_untracked: bool = False,
    module_map_override: Optional[Dict[str, Optional[str]]] = None,
    package_map_override: Optional[Dict[str, str]] = None,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, Any]:
    left_root = _validate_repo_path(left_repo_path)
    right_root = _validate_repo_path(right_repo_path)

    module_map = MANUAL_MODULE_MAP if module_map_override is None else module_map_override
    package_map = PACKAGE_MAP if package_map_override is None else package_map_override

    left_files = _collect_java_files(
        left_root, use_cache=use_cache, refresh_cache=refresh_cache, include_untracked=include_untracked
    )
    right_files = _collect_java_files(
        right_root, use_cache=use_cache, refresh_cache=refresh_cache, include_untracked=include_untracked
    )

    left_norm = {normalize_java_relpath_with_maps(k, module_map, package_map): v for k, v in left_files.items()}
    right_norm = {normalize_java_relpath_with_maps(k, module_map, package_map): v for k, v in right_files.items()}

    left_keys = set(left_norm.keys())
    right_keys = set(right_norm.keys())

    filtered_changed = None
    if left_commit:
        changed = set()
        result = _collect_changed_files(
            left_root,
            left_commit,
            include_staged=include_staged,
            include_untracked=include_untracked,
        )
        for rel in result["changed_files"]:
            if not rel.endswith(".java"):
                continue
            changed.add(normalize_java_relpath_with_maps(rel, module_map, package_map))
        filtered_changed = sorted(changed)
        left_keys = left_keys & changed

    only_left = sorted(left_keys - right_keys)
    only_right = sorted(right_keys - left_keys)
    common = sorted(left_keys & right_keys)

    different = []
    identical = 0

    for key in common:
        if not package_map:
            left_hash = _file_hash(left_norm[key], use_cache=use_cache)
            right_hash = _file_hash(right_norm[key], use_cache=use_cache)
            if left_hash == right_hash:
                identical += 1
                continue

        left_text = _read_file_text_cached(left_norm[key], use_cache=use_cache)
        right_text = _read_file_text_cached(right_norm[key], use_cache=use_cache)

        for lpkg, rpkg in package_map.items():
            left_text = left_text.replace(f"package {lpkg}", f"package {rpkg}")

        if left_text == right_text:
            identical += 1
        else:
            different.append(key)

    return {
        "left_root": left_root,
        "right_root": right_root,
        "left_commit": left_commit,
        "include_staged": include_staged,
        "include_untracked": include_untracked,
        "module_map_used": module_map,
        "package_map_used": package_map,
        "filtered_changed_files": filtered_changed,
        "only_in_left": only_left,
        "only_in_right": only_right,
        "different_files": different,
        "identical": identical,
        "total_common": len(common),
    }


def _line_diff_stats(left_text: str, right_text: str) -> Dict[str, int]:
    left_lines = left_text.splitlines()
    right_lines = right_text.splitlines()
    sm = difflib.SequenceMatcher(a=left_lines, b=right_lines)
    added = 0
    removed = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "delete"):
            removed += (i2 - i1)
        if tag in ("replace", "insert"):
            added += (j2 - j1)
    return {"added": added, "removed": removed}


@mcp.tool(title="Get diff stats between two Java repos")
def get_diff_stats(
    left_repo_path: str,
    right_repo_path: str,
    left_commit: Optional[str] = None,
    include_staged: bool = True,
    include_untracked: bool = False,
    module_map_override: Optional[Dict[str, Optional[str]]] = None,
    package_map_override: Optional[Dict[str, str]] = None,
    max_files: int = 500,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, Any]:
    scan = scan_repos(
        left_repo_path=left_repo_path,
        right_repo_path=right_repo_path,
        left_commit=left_commit,
        include_staged=include_staged,
        include_untracked=include_untracked,
        module_map_override=module_map_override,
        package_map_override=package_map_override,
        use_cache=use_cache,
        refresh_cache=refresh_cache,
    )

    left_root = scan["left_root"]
    right_root = scan["right_root"]
    module_map = scan.get("module_map_used", MANUAL_MODULE_MAP)
    package_map = scan.get("package_map_used", PACKAGE_MAP)

    left_files = _collect_java_files(
        left_root, use_cache=use_cache, refresh_cache=refresh_cache, include_untracked=include_untracked
    )
    right_files = _collect_java_files(
        right_root, use_cache=use_cache, refresh_cache=refresh_cache, include_untracked=include_untracked
    )
    left_norm = {normalize_java_relpath_with_maps(k, module_map, package_map): v for k, v in left_files.items()}
    right_norm = {normalize_java_relpath_with_maps(k, module_map, package_map): v for k, v in right_files.items()}

    per_file = []
    total_added = 0
    total_removed = 0

    for idx, key in enumerate(scan["different_files"]):
        if idx >= max_files:
            break
        left_path = left_norm.get(key)
        right_path = right_norm.get(key)
        if not left_path or not right_path:
            continue
        left_text = _read_file_text_cached(left_path, use_cache=use_cache)
        right_text = _read_file_text_cached(right_path, use_cache=use_cache)
        for lpkg, rpkg in package_map.items():
            left_text = left_text.replace(f"package {lpkg}", f"package {rpkg}")
        stats = _line_diff_stats(left_text, right_text)
        total_added += stats["added"]
        total_removed += stats["removed"]
        per_file.append({
            "file": key,
            "added": stats["added"],
            "removed": stats["removed"],
        })

    return {
        "left_root": left_root,
        "right_root": right_root,
        "left_commit": left_commit,
        "include_staged": include_staged,
        "include_untracked": include_untracked,
        "module_map_used": module_map,
        "package_map_used": package_map,
        "counts": {
            "only_in_left": len(scan["only_in_left"]),
            "only_in_right": len(scan["only_in_right"]),
            "different": len(scan["different_files"]),
            "identical": scan["identical"],
            "total_common": scan["total_common"],
        },
        "line_stats": {
            "total_added": total_added,
            "total_removed": total_removed,
            "files_considered": len(per_file),
            "max_files": max_files,
            "truncated": len(scan["different_files"]) > max_files,
        },
        "per_file": per_file,
    }


@mcp.tool(title="Generate a migration plan between two repos")
def generate_migration_plan(
    source_repo_path: str,
    target_repo_path: str,
    source_commit: Optional[str] = None,
    include_staged: bool = True,
    include_untracked: bool = False,
    module_map_override: Optional[Dict[str, Optional[str]]] = None,
    package_map_override: Optional[Dict[str, str]] = None,
    path_remap_rules: Optional[List[Dict[str, str]]] = None,
    include_prefixes: Optional[List[str]] = None,
    exclude_prefixes: Optional[List[str]] = None,
    top_n: int = 3,
    min_score: float = 0.1,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, Any]:
    source_root = _validate_repo_path(source_repo_path)
    target_root = _validate_repo_path(target_repo_path)

    module_map = MANUAL_MODULE_MAP if module_map_override is None else module_map_override
    package_map = PACKAGE_MAP if package_map_override is None else package_map_override

    classification = classify_two_repos(source_root, target_root)
    pkg_source = _detect_package_roots_internal(
        source_root, use_cache=use_cache, refresh_cache=refresh_cache
    )
    pkg_target = _detect_package_roots_internal(
        target_root, use_cache=use_cache, refresh_cache=refresh_cache
    )
    module_similarity = detect_module_similarity(
        repo_a_path=source_root,
        repo_b_path=target_root,
        top_n=top_n,
        min_score=min_score,
        use_cache=use_cache,
        refresh_cache=refresh_cache,
    )

    scan = scan_repos(
        left_repo_path=source_root,
        right_repo_path=target_root,
        left_commit=source_commit,
        include_staged=include_staged,
        include_untracked=include_untracked,
        module_map_override=module_map,
        package_map_override=package_map,
        use_cache=use_cache,
        refresh_cache=refresh_cache,
    )

    diff_stats = get_diff_stats(
        left_repo_path=source_root,
        right_repo_path=target_root,
        left_commit=source_commit,
        include_staged=include_staged,
        include_untracked=include_untracked,
        module_map_override=module_map,
        package_map_override=package_map,
        use_cache=use_cache,
        refresh_cache=refresh_cache,
        max_files=200,
    )

    preview = None
    if source_commit:
        preview = merge_changes_tool(
            source_repo_path=source_root,
            target_repo_path=target_root,
            source_commit=source_commit,
            mode="preview",
            include_staged=include_staged,
            include_untracked=include_untracked,
            path_remap_rules=path_remap_rules,
        )

    if include_prefixes or exclude_prefixes:
        scan["only_in_left"] = _filter_paths_by_prefixes(
            scan["only_in_left"], include_prefixes, exclude_prefixes
        )
        scan["only_in_right"] = _filter_paths_by_prefixes(
            scan["only_in_right"], include_prefixes, exclude_prefixes
        )
        scan["different_files"] = _filter_paths_by_prefixes(
            scan["different_files"], include_prefixes, exclude_prefixes
        )
        if preview and preview.get("preview"):
            filtered_preview = []
            for item in preview["preview"]:
                src = item.get("source_path", "")
                if not _filter_paths_by_prefixes([src], include_prefixes, exclude_prefixes):
                    continue
                filtered_preview.append(item)
            preview["preview"] = filtered_preview
            preview["changed_files"] = _filter_paths_by_prefixes(
                preview.get("changed_files", []), include_prefixes, exclude_prefixes
            )
            preview["changed_files_count"] = len(preview["changed_files"])

    suggested_module_map = {}
    for module, candidates in module_similarity.get("module_similarity", {}).items():
        if not candidates:
            continue
        best = candidates[0]
        if best["score"] >= min_score:
            suggested_module_map[module] = best["module_b"]

    return {
        "source_root": source_root,
        "target_root": target_root,
        "module_map_used": module_map,
        "package_map_used": package_map,
        "path_remap_rules": path_remap_rules or [],
        "include_prefixes": include_prefixes or [],
        "exclude_prefixes": exclude_prefixes or [],
        "classification": classification,
        "package_roots": {
            "source": pkg_source,
            "target": pkg_target,
        },
        "module_similarity": module_similarity,
        "suggested_module_map": suggested_module_map,
        "scan_summary": {
            "only_in_source": scan["only_in_left"],
            "only_in_target": scan["only_in_right"],
            "different_files": scan["different_files"],
            "identical": scan["identical"],
            "total_common": scan["total_common"],
        },
        "diff_stats": diff_stats,
        "merge_preview": preview,
    }


@mcp.tool(title="Get unified diff for a specific normalized file key")
def get_file_diff(
    left_repo_path: str,
    right_repo_path: str,
    relative_path: str,
    context_lines: int = 4,
    module_map_override: Optional[Dict[str, Optional[str]]] = None,
    package_map_override: Optional[Dict[str, str]] = None,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, str]:
    left_root = _validate_repo_path(left_repo_path)
    right_root = _validate_repo_path(right_repo_path)
    norm_key = relative_path
    module_map = MANUAL_MODULE_MAP if module_map_override is None else module_map_override
    package_map = PACKAGE_MAP if package_map_override is None else package_map_override

    def find_actual(repo_root: str, key: str) -> Optional[str]:
        all_files = _collect_java_files(repo_root, use_cache=use_cache, refresh_cache=refresh_cache)
        for orig_rel, abs_path in all_files.items():
            if normalize_java_relpath_with_maps(orig_rel, module_map, package_map) == key:
                return abs_path
        return None

    left_file = find_actual(left_root, norm_key)
    right_file = find_actual(right_root, norm_key)

    if not left_file:
        raise ValueError(f"File not found in left repo for key: {norm_key}")
    if not right_file:
        raise ValueError(f"File not found in right repo for key: {norm_key}")

    left = _read_file_text_cached(left_file, use_cache=use_cache)
    right = _read_file_text_cached(right_file, use_cache=use_cache)

    for lpkg, rpkg in package_map.items():
        left = left.replace(f"package {lpkg}", f"package {rpkg}")

    diff_lines = difflib.unified_diff(
        left.splitlines(keepends=True),
        right.splitlines(keepends=True),
        fromfile=f"left/{norm_key}",
        tofile=f"right/{norm_key}",
        n=context_lines,
    )
    diff_text = "".join(diff_lines)
    if not diff_text:
        diff_text = "(files are identical after normalization)"

    return {
        "relative_path": norm_key,
        "left_file": left_file,
        "right_file": right_file,
        "diff": diff_text,
    }


@mcp.tool(title="Compare a Quarkus multi-module repo against multiple Spring projects")
def scan_quarkus_modules_vs_spring_projects(
    quarkus_repo_path: str,
    module_mappings: List[Dict[str, str]],
    module_map_override: Optional[Dict[str, Optional[str]]] = None,
    package_map_override: Optional[Dict[str, str]] = None,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> Dict[str, Any]:
    quarkus_root = _validate_repo_path(quarkus_repo_path)

    results = []
    module_map = MANUAL_MODULE_MAP if module_map_override is None else module_map_override
    package_map = PACKAGE_MAP if package_map_override is None else package_map_override

    for mapping in module_mappings:
        module_name = mapping.get("module")
        spring_repo = mapping.get("spring_repo_path")

        if not module_name or not spring_repo:
            results.append({
                "module": module_name or "(missing)",
                "spring_repo_path": spring_repo or "(missing)",
                "error": "Both 'module' and 'spring_repo_path' must be provided.",
            })
            continue

        quarkus_module_root = os.path.join(quarkus_root, module_name)
        spring_root = _validate_repo_path(spring_repo)

        if not os.path.isdir(quarkus_module_root):
            results.append({
                "module": module_name,
                "spring_repo_path": spring_root,
                "error": f"Quarkus module directory does not exist: {quarkus_module_root}",
            })
            continue

        left_files = _collect_java_files(
            quarkus_module_root, use_cache=use_cache, refresh_cache=refresh_cache
        )
        right_files = _collect_java_files(
            spring_root, use_cache=use_cache, refresh_cache=refresh_cache
        )

        left_norm = {
            normalize_java_relpath_with_maps(rel, module_map, package_map): path
            for rel, path in left_files.items()
        }
        right_norm = {
            normalize_java_relpath_with_maps(rel, module_map, package_map): path
            for rel, path in right_files.items()
        }

        left_keys = set(left_norm.keys())
        right_keys = set(right_norm.keys())

        only_left = sorted(left_keys - right_keys)
        only_right = sorted(right_keys - left_keys)
        common = sorted(left_keys & right_keys)

        different = []
        identical = 0

        for key in common:
            if not package_map:
                left_hash = _file_hash(left_norm[key], use_cache=use_cache)
                right_hash = _file_hash(right_norm[key], use_cache=use_cache)
                if left_hash == right_hash:
                    identical += 1
                    continue

            left_text = _read_file_text_cached(left_norm[key], use_cache=use_cache)
            right_text = _read_file_text_cached(right_norm[key], use_cache=use_cache)

            for lpkg, rpkg in package_map.items():
                left_text = left_text.replace(f"package {lpkg}", f"package {rpkg}")

            if left_text == right_text:
                identical += 1
            else:
                different.append(key)

        results.append({
            "module": module_name,
            "spring_repo_path": spring_root,
            "module_map_used": module_map,
            "package_map_used": package_map,
            "only_in_quarkus": only_left,
            "only_in_spring": only_right,
            "different_files": different,
            "identical": identical,
            "total_common": len(common),
        })

    return {
        "quarkus_root": quarkus_root,
        "module_results": results,
    }


# ====================================================================================
# Utility tool: write to README
# ====================================================================================

@mcp.tool(title="Write content to README.md")
def write_to_readme(
    output_path: str,
    content: str,
    mode: str = "append"
) -> Dict[str, Any]:
    """
    Writes tool output to a README.md (or any markdown) file.
    Arguments:
      - output_path: full path to README.md
      - content: the text to write
      - mode: "append" or "overwrite"
    """
    path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    if mode == "overwrite":
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n\n" + content)

    return {
        "status": "ok",
        "path": path,
        "mode": mode,
        "bytes_written": len(content)
    }


@mcp.tool(title="List Java file names matching multiple regex patterns")
def list_files_matching_multi(
    root_path: str,
    patterns: List[str],
    match_mode: str = "any",   # "any" or "all"
    include_dirs: bool = False,
    ignore_case: bool = True,
    group_results: bool = False
) -> Dict[str, Any]:
    """
    Recursively list Java *file names only* that match multiple regex patterns.
    Does not return directory structure like src/main/java/... - only the final filename.

    Args:
        root_path (str): Folder or repo root to search.
        patterns (List[str]): Regex patterns for matching filenames or paths.
        match_mode (str): "any" = match one pattern, "all" = must match all patterns.
        include_dirs (bool): If true, directories can be matched too.
        ignore_case (bool): Case-insensitive regex.
        group_results (bool): If true, group results per pattern.

    Returns:
        {
            "root": "...",
            "patterns": [...],
            "matched": N,
            "results": [
                {"file_name": "...", "absolute": "..."}
            ],
            "groups": { ... } or {}
        }
    """
    if not os.path.isdir(root_path):
        raise ValueError(f"root_path is not a directory: {root_path}")

    flags = re.IGNORECASE if ignore_case else 0
    regex_list = [(pat, re.compile(pat, flags)) for pat in patterns]

    root = os.path.abspath(root_path)
    results = []
    grouped = {pat: [] for pat in patterns}

    for dirpath, dirnames, filenames in os.walk(root):
        # remove unwanted dirs
        dirnames[:] = [
            d for d in dirnames
            if d not in (".git", "target", "build", ".idea", ".vscode", "out")
        ]

        # -------------------------
        # Match Java files
        # -------------------------
        for fname in filenames:
            if not fname.endswith(".java"):
                continue

            abs_path = os.path.join(dirpath, fname)

            # we match regex against the *full relative path* for flexibility
            rel_full = os.path.relpath(abs_path, root).replace("\\", "/")

            matches = []
            for pat, regex in regex_list:
                if regex.search(rel_full) or regex.search(fname):
                    matches.append(pat)

            # any vs all
            if (match_mode == "any" and matches) or \
               (match_mode == "all" and len(matches) == len(patterns)):

                results.append({
                    "file_name": fname,
                    "absolute": abs_path
                })

                if group_results:
                    for m in matches:
                        grouped[m].append({
                            "file_name": fname,
                            "absolute": abs_path
                        })

        # -------------------------
        # Optionally match directories
        # -------------------------
        if include_dirs:
            for d in dirnames:
                abs_path = os.path.join(dirpath, d)
                rel_full = os.path.relpath(abs_path, root).replace("\\", "/")

                matches = []
                for pat, regex in regex_list:
                    if regex.search(rel_full) or regex.search(d):
                        matches.append(pat)

                if (match_mode == "any" and matches) or \
                   (match_mode == "all" and len(matches) == len(patterns)):

                    results.append({
                        "file_name": d,
                        "absolute": abs_path
                    })

                    if group_results:
                        for m in matches:
                            grouped[m].append({
                                "file_name": d,
                                "absolute": abs_path
                            })

    return {
        "root": root,
        "patterns": patterns,
        "match_mode": match_mode,
        "matched": len(results),
        "results": results[:5000],
        "groups": grouped if group_results else {}
    }


@mcp.tool(title="Merge changes from source repo into target repo")
def merge_changes_tool(
    source_repo_path: str,
    target_repo_path: str,
    source_commit: str,
    mode: str = "preview",  # "preview", "check", or "apply"
    allow_files: Optional[List[str]] = None,
    include_staged: bool = True,
    include_untracked: bool = False,
    context_lines: int = 3,
    path_remap_rules: Optional[List[Dict[str, str]]] = None,
    apply_check: bool = True,
) -> Dict[str, Any]:
    source_root = _validate_repo_path(source_repo_path)
    target_root = _validate_repo_path(target_repo_path)

    if mode not in ("preview", "check", "apply"):
        raise ValueError("mode must be 'preview', 'check', or 'apply'")

    changed_info = _collect_changed_files(
        source_root,
        source_commit,
        include_staged=include_staged,
        include_untracked=include_untracked,
    )
    changed_files = changed_info["changed_files"]
    untracked_set = set(changed_info["untracked_files"])

    preview_items = []
    for rel in changed_files:
        target_rel = _apply_path_remap(rel, path_remap_rules)
        target_abs = os.path.join(target_root, target_rel)
        preview_items.append({
            "source_path": rel,
            "target_path": target_rel,
            "target_exists": os.path.isfile(target_abs),
        })

    if mode == "preview":
        return {
            "source_root": source_root,
            "target_root": target_root,
            "source_commit": source_commit,
            "include_staged": include_staged,
            "include_untracked": include_untracked,
            "path_remap_rules": path_remap_rules or [],
            "changed_files_count": len(changed_files),
            "changed_files": changed_files,
            "preview": preview_items,
        }

    if not allow_files:
        raise ValueError("allow_files must be provided when mode='check' or mode='apply'")

    allow_set = set(_normalize_path(p) for p in allow_files)
    results = []

    for rel in allow_set:
        if rel not in changed_files:
            results.append({
                "source_path": rel,
                "target_path": _apply_path_remap(rel, path_remap_rules),
                "status": "skipped",
                "reason": "not in changed_files",
            })
            continue

        target_rel = _apply_path_remap(rel, path_remap_rules)
        patch_parts = []

        # Untracked files: use no-index diff against /dev/null
        if rel in untracked_set:
            patch = _git_diff(
                source_root,
                ["diff", "--no-prefix", "--binary", "--no-index", "--", "/dev/null", rel],
            )
            if patch:
                patch_parts.append(_rewrite_patch_paths(patch, rel, target_rel))

        # Tracked files: diff against commit (unstaged)
        patch = _git_diff(
            source_root,
            ["diff", "--no-prefix", "--binary", f"-U{context_lines}", source_commit, "--", rel],
        )
        if patch:
            patch_parts.append(_rewrite_patch_paths(patch, rel, target_rel))

        # Staged changes
        if include_staged:
            patch = _git_diff(
                source_root,
                ["diff", "--no-prefix", "--binary", f"-U{context_lines}", "--cached", source_commit, "--", rel],
            )
            if patch:
                patch_parts.append(_rewrite_patch_paths(patch, rel, target_rel))

        patch_text = "".join(patch_parts)
        if not patch_text.strip():
            results.append({
                "source_path": rel,
                "target_path": target_rel,
                "status": "skipped",
                "reason": "no diff for file",
            })
            continue
        patch_meta = {
            "patch_chars": len(patch_text),
            "patch_lines": patch_text.count("\n") + 1,
            "patch_stats": _patch_line_stats(patch_text),
        }

        target_abs = os.path.join(target_root, target_rel)
        backup_path = None

        check_result = None
        if mode == "check" or apply_check:
            check_proc = subprocess.run(
                ["git", "-C", target_root, "apply", "--check", "--binary", "--whitespace=nowarn"],
                input=patch_text,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            check_result = {
                "returncode": check_proc.returncode,
                "stdout": (check_proc.stdout or "").strip(),
                "stderr": (check_proc.stderr or "").strip(),
            }
            if mode == "check" and check_proc.returncode != 0:
                results.append({
                    "source_path": rel,
                    "target_path": target_rel,
                    "status": "check_failed",
                    "error": check_result["stderr"],
                    "backup": backup_path,
                    "patch_meta": patch_meta,
                })
                continue
            if mode == "check" and check_proc.returncode == 0:
                results.append({
                    "source_path": rel,
                    "target_path": target_rel,
                    "status": "check_ok",
                    "backup": backup_path,
                    "patch_meta": patch_meta,
                })
                continue
            if apply_check and check_proc.returncode != 0:
                results.append({
                    "source_path": rel,
                    "target_path": target_rel,
                    "status": "check_failed",
                    "error": check_result["stderr"],
                    "backup": backup_path,
                    "patch_meta": patch_meta,
                })
                continue

        if mode == "apply" and os.path.isfile(target_abs):
            backup_path = target_abs + ".bak"
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            shutil.copy2(target_abs, backup_path)

        apply_proc = subprocess.run(
            ["git", "-C", target_root, "apply", "--binary", "--whitespace=nowarn"],
            input=patch_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if apply_proc.returncode == 0:
            if backup_path and os.path.isfile(backup_path):
                os.remove(backup_path)
            results.append({
                "source_path": rel,
                "target_path": target_rel,
                "status": "applied",
                "patch_meta": patch_meta,
            })
        else:
            results.append({
                "source_path": rel,
                "target_path": target_rel,
                "status": "failed",
                "error": (apply_proc.stderr or "").strip(),
                "backup": backup_path,
                "check": check_result,
                "patch_meta": patch_meta,
            })

    return {
        "source_root": source_root,
        "target_root": target_root,
        "source_commit": source_commit,
        "include_staged": include_staged,
        "include_untracked": include_untracked,
        "mode": mode,
        "path_remap_rules": path_remap_rules or [],
        "apply_check": apply_check,
        "results": results,
    }


@mcp.tool(title="Clear .bak backups in a repo")
def clear_backup(
    repo_path: str,
    dry_run: bool = True,
) -> Dict[str, Any]:
    root = _validate_repo_path(repo_path)
    removed = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "build", ".idea", ".vscode", "out")]
        for fname in filenames:
            if not fname.endswith(".bak"):
                continue
            abs_path = os.path.join(dirpath, fname)
            removed.append(abs_path)
            if not dry_run:
                os.remove(abs_path)

    return {
        "repo_root": root,
        "dry_run": dry_run,
        "count": len(removed),
        "files": removed,
    }


@mcp.tool(title="Restore .bak backups in a repo")
def restore_backup(
    repo_path: str,
    dry_run: bool = True,
    overwrite_existing: bool = False,
) -> Dict[str, Any]:
    root = _validate_repo_path(repo_path)
    restored = []
    skipped = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "build", ".idea", ".vscode", "out")]
        for fname in filenames:
            if not fname.endswith(".bak"):
                continue
            bak_path = os.path.join(dirpath, fname)
            original_path = bak_path[:-4]
            if os.path.exists(original_path) and not overwrite_existing:
                skipped.append({"backup": bak_path, "reason": "original_exists"})
                continue
            restored.append({"backup": bak_path, "restored_to": original_path})
            if not dry_run:
                os.makedirs(os.path.dirname(original_path), exist_ok=True)
                shutil.copy2(bak_path, original_path)

    return {
        "repo_root": root,
        "dry_run": dry_run,
        "overwrite_existing": overwrite_existing,
        "restored": restored,
        "skipped": skipped,
        "restored_count": len(restored),
        "skipped_count": len(skipped),
    }
@mcp.tool(title="List changed files since a commit")
def list_changed_files_since_commit(
    repo_path: str,
    commit: str,
    include_untracked: bool = False,
    include_staged: bool = True,
    include_prefixes: Optional[List[str]] = None,
    exclude_prefixes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    root = _validate_repo_path(repo_path)
    result = _collect_changed_files(
        root,
        commit,
        include_staged=include_staged,
        include_untracked=include_untracked,
    )
    files = _filter_paths_by_prefixes(
        result["changed_files"],
        include_prefixes=include_prefixes,
        exclude_prefixes=exclude_prefixes,
    )
    untracked = _filter_paths_by_prefixes(
        result["untracked_files"],
        include_prefixes=include_prefixes,
        exclude_prefixes=exclude_prefixes,
    )

    return {
        "repo_root": root,
        "commit": commit,
        "include_staged": include_staged,
        "include_untracked": include_untracked,
        "include_prefixes": include_prefixes or [],
        "exclude_prefixes": exclude_prefixes or [],
        "changed_files": files,
        "untracked_files": untracked,
        "count": len(files),
    }


@mcp.tool(title="Get diff for a file since a commit")
def get_diff_since_commit(
    repo_path: str,
    commit: str,
    relative_path: str,
    context_lines: int = 4,
) -> Dict[str, Any]:
    root = _validate_repo_path(repo_path)

    diff = _git_diff(root, ["diff", f"-U{context_lines}", commit, "--", relative_path])
    if not diff:
        diff = "(no diff)"

    return {
        "repo_root": root,
        "commit": commit,
        "relative_path": relative_path,
        "diff": diff,
    }


# ====================================================================================
# Run MCP server
# ====================================================================================

if __name__ == "__main__":
    log_startup()
    mcp.run()
