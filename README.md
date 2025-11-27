# Repo Diff MCP Server – Copilot Usage Guide

This project exposes a local **MCP server** (`repo-diff-enhanced`) that helps compare:

- Quarkus multi-module repo ↔ Spring Boot repos
- Code structure & file content
- Modules & packages
- REST APIs vs OpenAPI specs
- And writes reports into Markdown **README files**

GitHub Copilot (in VS Code / JetBrains) can call these tools directly via chat.

---

## 1. MCP Server Overview

Server name (as configured in Copilot): `repo-diff-enhanced`  
Main script: `diff_check_mcp.py` (run via `python diff_check_mcp.py`)

Core tools:

- `analyze_repo`
- `classify_two_repos`
- `detect_package_roots`
- `detect_module_similarity`
- `scan_repos`
- `get_file_diff`
- `scan_quarkus_modules_vs_spring_projects`
- `analyze_api_differences`
- `write_to_readme`

> Throughout this guide, replace the example paths (`C:/tmp/...`) with your real local repo paths.

---

## 2. Useful Path Placeholders

In prompts below, assume:

- **Quarkus multi-module repo**:  
  `C:/tmp/quarkus-project`

- **Spring mono/child repo (or parent)**:  
  `C:/tmp/spring-project`

- **Standalone Spring module repos**:
  - `C:/tmp/demo-module-api-1`
  - `C:/tmp/demo-module-api-2`
  - `C:/tmp/demo-module-api-3`
  - `C:/tmp/demo-module-api-4`

- **Main diff report README**:  
  `C:/tmp/diff-report/README.md`

Feel free to adjust them in your prompts.

---

## 3. Check MCP Server is Available

**Prompt:**

> List all available MCP servers and confirm that `repo-diff-enhanced` is available.

If it shows up, the config is good.

---

## 4. Analyze Individual Repos → README

### 4.1 Analyze Quarkus repo

**Prompt:**

> Use the `repo-diff-enhanced` MCP server.  
> Call `analyze_repo` with:  
> `repo_path = "C:/tmp/quarkus-project"`.  
> Take the JSON result and summarize it into markdown under a heading  
> `## Quarkus Repo Analysis`  
> (include build tool, frameworks, modules, and whether it is multi-module).  
> Then call `write_to_readme` with:  
> - `output_path = "C:/tmp/diff-report/README.md"`  
> - `content = "<your markdown summary>"`  
> - `mode = "append"`.

### 4.2 Analyze Spring repo

**Prompt:**

> Call `analyze_repo` with:  
> `repo_path = "C:/tmp/spring-project"`.  
> Summarize the result into markdown under  
> `## Spring Repo Analysis`  
> and append it to the same README using `write_to_readme`.

---

## 5. Classify Repos (Quarkus vs Spring) → README

**Prompt:**

> Call `classify_two_repos` with:  
> `repo_a_path = "C:/tmp/quarkus-project"`  
> `repo_b_path = "C:/tmp/spring-project"`.  
> Convert the result into markdown under  
> `## Repo Classification (Quarkus vs Spring)`  
> describing for each repo: build tool, frameworks, modules, and whether it is multi-module.  
> Then append that section to `C:/tmp/diff-report/README.md` using `write_to_readme`.

---

## 6. Detect Package Roots → README

Use this to discover dominant Java package roots in each repo.

**Prompt:**

> Call `detect_package_roots` with  
> `repo_path = "C:/tmp/quarkus-project"`,  
> then again with  
> `repo_path = "C:/tmp/spring-project"`.  
> Turn the two results into a markdown section  
> `## Package Root Detection (Quarkus vs Spring)`  
> showing the `dominant_root_package_guess` and top 5 `root_candidates_top20` for each repo.  
> Append this section to `C:/tmp/diff-report/README.md` using `write_to_readme`.

---

## 7. Detect Module Similarity → README

This helps map Quarkus modules to Spring modules/projects.

**Prompt:**

> Call `detect_module_similarity` with:  
> `repo_a_path = "C:/tmp/quarkus-project"`  
> `repo_b_path = "C:/tmp/spring-project"`  
> `top_n = 3`  
> `min_score = 0.1`.  
> Generate a markdown table under  
> `## Module Similarity (Quarkus vs Spring)`  
> with columns: `Module A | Best Match in B | Score | Common Files`.  
> For each module in A, list up to the top 3 matches in B by score.  
> Append this table to `C:/tmp/diff-report/README.md` via `write_to_readme`.

---

## 8. Whole Repo Diff (`scan_repos`) → README

This compares all Java files between two repos using module & package normalization.

**Prompt:**

> Call `scan_repos` with:  
> `left_repo_path = "C:/tmp/quarkus-project"`  
> `right_repo_path = "C:/tmp/spring-project"`.  
> Create a markdown section `## Repo Diff Summary` containing:  
> - total counts for `only_in_left`, `only_in_right`, `different_files`, `identical`, `total_common`,  
> - and a small table showing the first 10 `different_files`.  
> Append this section to `C:/tmp/diff-report/README.md` using `write_to_readme`.

---

## 9. Single File Diff (`get_file_diff`) → README

After `scan_repos`, pick one normalized key from `different_files`  
(e.g. `src/main/java/core/JobIdConverter.java`).

**Prompt:**

> From the last `scan_repos` result, pick one representative entry from `different_files`,  
> for example `src/main/java/core/JobIdConverter.java`.  
> Call `get_file_diff` with:  
> `left_repo_path = "C:/tmp/quarkus-project"`  
> `right_repo_path = "C:/tmp/spring-project"`  
> `relative_path = "src/main/java/core/JobIdConverter.java"`.  
> Wrap the `diff` field in a fenced ```diff``` code block under the heading  
> `## Diff: JobIdConverter.java`  
> and append it to `C:/tmp/diff-report/README.md` using `write_to_readme`.

---

## 10. Quarkus Modules vs Spring Projects → README

Use this when the **Quarkus repo is multi-module** and the **Spring side is split into separate repos**.

### 10.1 Module-to-project comparison summary

**Prompt:**

> Call `scan_quarkus_modules_vs_spring_projects` with:  
> `quarkus_repo_path = "C:/tmp/quarkus-project"`  
> `module_mappings = [  
>   {"module": "demo-module-api-1",       "spring_repo_path": "C:/tmp/demo-module-api-1"},  
>   {"module": "demo-module-api-2", "spring_repo_path": "C:/tmp/demo-module-api-2"},  
>   {"module": "demo-module-api-3",        "spring_repo_path": "C:/tmp/demo-module-api-3"},  
>   {"module": "demo-module-api-4",    "spring_repo_path": "C:/tmp/demo-module-api-4"}  
> ]`.  
> For each module result, create a markdown section  
> `### Module: <module-name>` with bullet points:  
> - `only_in_quarkus` count  
> - `only_in_spring` count  
> - `different_files` count  
> - `identical` and `total_common`.  
> Append all module sections to `C:/tmp/diff-report/README.md` using `write_to_readme`.

### 10.2 Per-module READMEs (optional)

**Prompt:**

> Using the same `scan_quarkus_modules_vs_spring_projects` result,  
> for each module create a separate markdown content summary (same bullets as before)  
> and call `write_to_readme` with  
> `output_path = "C:/tmp/module-diff-reports/<module>/README.md"`  
> and `mode = "overwrite"` so each module gets its own report file.

---

## 11. API Differences (Quarkus REST vs Spring OpenAPI) → README

### 11.1 If you know the OpenAPI spec path

**Prompt:**

> Call `analyze_api_differences` with:  
> `quarkus_repo_path = "C:/tmp/quarkus-project"`  
> `spring_repo_path = "C:/tmp/spring-project"`  
> `spring_openapi_relative_paths = ["src/main/resources/openapi.yaml"]`.  
> Create a markdown section `## API Coverage (Quarkus vs OpenAPI)` summarizing:  
> - `endpoint_count` (Quarkus)  
> - `operation_count` (OpenAPI)  
> - counts of `only_in_quarkus`, `only_in_openapi`, and `intersect_count`,  
> - and list the first 10 entries from each of `only_in_quarkus` and `only_in_openapi` (showing method + path).  
> Append this section to `C:/tmp/diff-report/README.md` using `write_to_readme`.

### 11.2 Auto-discover OpenAPI specs

**Prompt:**

> Call `analyze_api_differences` with:  
> `quarkus_repo_path = "C:/tmp/quarkus-project"`  
> `spring_repo_path = "C:/tmp/spring-project"`  
> and leave `spring_openapi_relative_paths` as null so it auto-discovers spec files.  
> Then produce the same `## API Coverage (Quarkus vs OpenAPI)` markdown section,  
> also listing which spec files were used, and append it to `C:/tmp/diff-report/README.md` with `write_to_readme`.

---

## 12. General Pattern for New Reports

Whenever you run any MCP tool and want the result saved:

1. Ask Copilot to:
   - Call the tool.
   - Turn the JSON result into a markdown section with a clear heading.
2. Then call `write_to_readme` with:
   - `output_path` = your target README path
   - `content` = that markdown
   - `mode` = `"append"` (or `"overwrite"` for a fresh file)

**Template Prompt:**

> Call `<TOOL_NAME>` with `<arguments>`.  
> Take the JSON result and convert it into a markdown section titled  
> `## <Section Title>` with a short summary and key tables/lists.  
> Then call `write_to_readme` with:  
> - `output_path = "<FULL_PATH_TO_README>"`  
> - `content = "<the markdown you just generated>"`  
> - `mode = "append"`.

---

## 13. Notes

- Paths like `C:/tmp/...` should be adjusted to your actual repo locations.
- `MANUAL_MODULE_MAP` and `PACKAGE_MAP` are currently defined in Python, but you can extend the server later to pass them as parameters if needed.
- For deeper diffs, combine:
  - `scan_repos` → list changed files  
  - `get_file_diff` → inspect key classes  
  - `analyze_api_differences` → check REST vs OpenAPI coverage  
  - `scan_quarkus_modules_vs_spring_projects` → validate each module migration

This README is meant to be **copied as-is** into your project so future you can just open Copilot Chat and follow the prompts.
