#!/usr/bin/env python
import os
import re
import json
import difflib
import sys
import datetime
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from collections import Counter

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("repo-diff-enhanced")

# ====================================================================================
# CONFIG: MODULE AND PACKAGE MAPPING (manual overrides)
# ====================================================================================

# Manual module mapping hints – Quarkus multimodule -> Spring standalone projects
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


def _collect_java_files(root: str, exclude_dirs=None) -> Dict[str, str]:
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
    """
    Normalize Java file paths by:
      - stripping known module prefixes
      - applying package mapping
    This gives a cross-repo comparable key like:
        src/main/java/.../JobIdConverter.java
    """
    parts = rel.split("/")
    if parts and parts[0] in MANUAL_MODULE_MAP:
        parts = parts[1:]
    rel = "/".join(parts)

    for left_pkg, right_pkg in PACKAGE_MAP.items():
        rel = rel.replace(left_pkg.replace(".", "/"), right_pkg.replace(".", "/"))

    return rel


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
            Find direct child text under project, and fallback to parent/groupId/… if needed.
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


def _detect_package_roots_internal(repo_root: str, max_files: int = 5000) -> Dict[str, Any]:
    root = os.path.abspath(repo_root)
    java_files = _collect_java_files(root)
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
def detect_package_roots(repo_path: str, max_files: int = 5000) -> Dict[str, Any]:
    if not os.path.isdir(repo_path):
        raise ValueError(f"Repo path is not a directory: {repo_path}")
    return _detect_package_roots_internal(repo_path, max_files=max_files)


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


def _module_fingerprint(module_root: str) -> Dict[str, Any]:
    java_files = _collect_java_files(module_root)
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
) -> Dict[str, Any]:
    root_a = os.path.abspath(repo_a_path)
    root_b = os.path.abspath(repo_b_path)

    if not os.path.isdir(root_a):
        raise ValueError(f"repo_a_path is not a directory: {root_a}")
    if not os.path.isdir(root_b):
        raise ValueError(f"repo_b_path is not a directory: {root_b}")

    modules_a = _discover_modules_for_similarity(root_a)
    modules_b = _discover_modules_for_similarity(root_b)

    fingerprints_a = {name: _module_fingerprint(path) for name, path in modules_a.items()}
    fingerprints_b = {name: _module_fingerprint(path) for name, path in modules_b.items()}

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


def _collect_quarkus_endpoints(quarkus_root: str) -> Dict[str, Any]:
    root = os.path.abspath(quarkus_root)
    java_files = _collect_java_files(root)
    endpoints = []

    for rel, abs_path in java_files.items():
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
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
) -> Dict[str, Any]:
    if not os.path.isdir(quarkus_repo_path):
        raise ValueError(f"quarkus_repo_path is not a directory: {quarkus_repo_path}")
    if not os.path.isdir(spring_repo_path):
        raise ValueError(f"spring_repo_path is not a directory: {spring_repo_path}")

    quarkus_info = _collect_quarkus_endpoints(quarkus_repo_path)
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
    if not os.path.isdir(repo_path):
        raise ValueError(f"Repo path is not a directory: {repo_path}")
    return _analyze_repo_internal(repo_path)


@mcp.tool(title="Classify two repos as Quarkus vs Spring and multimodule")
def classify_two_repos(repo_a_path: str, repo_b_path: str) -> Dict[str, Any]:
    if not os.path.isdir(repo_a_path):
        raise ValueError(f"repo_a_path is not a directory: {repo_a_path}")
    if not os.path.isdir(repo_b_path):
        raise ValueError(f"repo_b_path is not a directory: {repo_b_path}")

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
def scan_repos(left_repo_path: str, right_repo_path: str) -> Dict[str, Any]:
    left_root = os.path.abspath(left_repo_path)
    right_root = os.path.abspath(right_repo_path)

    if not os.path.isdir(left_root):
        raise ValueError(f"Left repo path is not a directory: {left_root}")
    if not os.path.isdir(right_root):
        raise ValueError(f"Right repo path is not a directory: {right_root}")

    left_files = _collect_java_files(left_root)
    right_files = _collect_java_files(right_root)

    left_norm = {normalize_java_relpath(k): v for k, v in left_files.items()}
    right_norm = {normalize_java_relpath(k): v for k, v in right_files.items()}

    left_keys = set(left_norm.keys())
    right_keys = set(right_norm.keys())

    only_left = sorted(left_keys - right_keys)
    only_right = sorted(right_keys - left_keys)
    common = sorted(left_keys & right_keys)

    different = []
    identical = 0

    for key in common:
        left_text = _read_file_text(left_norm[key])
        right_text = _read_file_text(right_norm[key])

        for lpkg, rpkg in PACKAGE_MAP.items():
            left_text = left_text.replace(f"package {lpkg}", f"package {rpkg}")

        if left_text == right_text:
            identical += 1
        else:
            different.append(key)

    return {
        "left_root": left_root,
        "right_root": right_root,
        "only_in_left": only_left,
        "only_in_right": only_right,
        "different_files": different,
        "identical": identical,
        "total_common": len(common),
    }


@mcp.tool(title="Get unified diff for a specific normalized file key")
def get_file_diff(
    left_repo_path: str,
    right_repo_path: str,
    relative_path: str,
    context_lines: int = 4,
) -> Dict[str, str]:
    left_root = os.path.abspath(left_repo_path)
    right_root = os.path.abspath(right_repo_path)
    norm_key = relative_path

    def find_actual(repo_root: str, key: str) -> Optional[str]:
        all_files = _collect_java_files(repo_root)
        for orig_rel, abs_path in all_files.items():
            if normalize_java_relpath(orig_rel) == key:
                return abs_path
        return None

    left_file = find_actual(left_root, norm_key)
    right_file = find_actual(right_root, norm_key)

    if not left_file:
        raise ValueError(f"File not found in left repo for key: {norm_key}")
    if not right_file:
        raise ValueError(f"File not found in right repo for key: {norm_key}")

    left = _read_file_text(left_file)
    right = _read_file_text(right_file)

    for lpkg, rpkg in PACKAGE_MAP.items():
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
) -> Dict[str, Any]:
    quarkus_root = os.path.abspath(quarkus_repo_path)
    if not os.path.isdir(quarkus_root):
        raise ValueError(f"quarkus_repo_path is not a directory: {quarkus_root}")

    results = []

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
        spring_root = os.path.abspath(spring_repo)

        if not os.path.isdir(quarkus_module_root):
            results.append({
                "module": module_name,
                "spring_repo_path": spring_root,
                "error": f"Quarkus module directory does not exist: {quarkus_module_root}",
            })
            continue

        if not os.path.isdir(spring_root):
            results.append({
                "module": module_name,
                "spring_repo_path": spring_root,
                "error": f"Spring repo directory does not exist: {spring_root}",
            })
            continue

        left_files = _collect_java_files(quarkus_module_root)
        right_files = _collect_java_files(spring_root)

        left_norm = {normalize_java_relpath(rel): path for rel, path in left_files.items()}
        right_norm = {normalize_java_relpath(rel): path for rel, path in right_files.items()}

        left_keys = set(left_norm.keys())
        right_keys = set(right_norm.keys())

        only_left = sorted(left_keys - right_keys)
        only_right = sorted(right_keys - left_keys)
        common = sorted(left_keys & right_keys)

        different = []
        identical = 0

        for key in common:
            left_text = _read_file_text(left_norm[key])
            right_text = _read_file_text(right_norm[key])

            for lpkg, rpkg in PACKAGE_MAP.items():
                left_text = left_text.replace(f"package {lpkg}", f"package {rpkg}")

            if left_text == right_text:
                identical += 1
            else:
                different.append(key)

        results.append({
            "module": module_name,
            "spring_repo_path": spring_root,
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


# ====================================================================================
# Run MCP server
# ====================================================================================

if __name__ == "__main__":
    log_startup()
    mcp.run()
