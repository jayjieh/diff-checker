import os
from pathlib import Path
import hashlib
import difflib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


# ---- Configuration hooks ----

# Package path mappings if Quarkus and Spring Boot use different base packages.
# Example:
# PACKAGE_PATH_MAPPINGS = {
#     "com.mycompany.product.quarkus": "com.mycompany.product"
# }
PACKAGE_PATH_MAPPINGS = {}


def normalized_key(src_root: Path, file_path: Path, is_left_side: bool) -> str:
    """
    Build a normalized key for a file, so that logically equivalent files in both
    repos map to the same key.

    - src_root: the "src/main/java" or root directory used as base.
    - file_path: actual file.
    - is_left_side: True if this is the "left" repo (e.g. Quarkus),
                    used to apply package path mappings only on that side.
    """
    rel = file_path.relative_to(src_root).as_posix()

    if is_left_side and PACKAGE_PATH_MAPPINGS:
        # Apply path-based mappings for the left side.
        for from_pkg, to_pkg in PACKAGE_PATH_MAPPINGS.items():
            from_prefix = from_pkg.replace(".", "/") + "/"
            to_prefix = to_pkg.replace(".", "/") + "/"
            if rel.startswith(from_prefix):
                rel = to_prefix + rel[len(from_prefix):]
                break

    return rel


def normalize_content(text: str) -> str:
    """
    Hook to normalize file content before comparison.

    For now:
    - collapse all runs of whitespace to a single space
    - strip leading/trailing whitespace

    You can extend this to:
    - remove license headers
    - map package names, etc.
    """
    return " ".join(text.split())


def file_hash(path: Path, do_normalize: bool = True) -> str:
    """
    Compute a hash of the file content, optionally after normalization.
    """
    data = path.read_text(encoding="utf-8", errors="ignore")
    if do_normalize:
        data = normalize_content(data)
    digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
    return digest


def index_repo(root: Path, is_left_side: bool, exts=(".java",)) -> dict:
    """
    Walk a repo, indexing files by normalized key.

    Returns: dict[key] = Path
    """
    src_root = root / "src" / "main" / "java"
    if not src_root.is_dir():
        # fallback to repo root
        src_root = root

    index = {}
    for dirpath, _, filenames in os.walk(src_root):
        for name in filenames:
            if exts and not name.endswith(exts):
                continue
            full = Path(dirpath) / name
            key = normalized_key(src_root, full, is_left_side=is_left_side)
            if key in index:
                # Just warn in console; last one wins
                print(f"[WARN] Duplicate key {key} in {root}")
            index[key] = full
    return index


def compare_repos(left_root: Path, right_root: Path, ignore_whitespace: bool = True):
    """
    Compare two repos.

    Returns a dict with:
      {
        "only_left": { key: Path },
        "only_right": { key: Path },
        "pairs": {
            key: {
                "left": Path,
                "right": Path,
                "status": "identical" | "modified"
            }
        }
      }
    """
    left_index = index_repo(left_root, is_left_side=True)
    right_index = index_repo(right_root, is_left_side=False)

    all_keys = set(left_index) | set(right_index)

    only_left = {}
    only_right = {}
    pairs = {}

    for key in sorted(all_keys):
        lp = left_index.get(key)
        rp = right_index.get(key)

        if lp is None:
            only_right[key] = rp
        elif rp is None:
            only_left[key] = lp
        else:
            # Both exist: compare
            if ignore_whitespace:
                h_left = file_hash(lp, do_normalize=True)
                h_right = file_hash(rp, do_normalize=True)
            else:
                h_left = file_hash(lp, do_normalize=False)
                h_right = file_hash(rp, do_normalize=False)

            status = "identical" if h_left == h_right else "modified"
            pairs[key] = {"left": lp, "right": rp, "status": status}

    return {
        "only_left": only_left,
        "only_right": only_right,
        "pairs": pairs,
    }


# ---- GUI ----

class DiffCheckerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Quarkus ↔ Spring Boot Repo Diff Checker")

        # Keep data from last comparison
        self.last_result = None
        self.item_metadata = {}  # tree_item_id -> metadata dict

        self._build_ui()

    def _build_ui(self):
        root = self.master

        main_frame = ttk.Frame(root, padding=8)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Top: repo selection
        repo_frame = ttk.LabelFrame(main_frame, text="Repositories")
        repo_frame.pack(fill=tk.X, pady=(0, 8))

        # Left repo
        self.left_path_var = tk.StringVar()
        ttk.Label(repo_frame, text="Left (Quarkus):").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(repo_frame, textvariable=self.left_path_var, width=60).grid(row=0, column=1, sticky="we", padx=4, pady=4)
        ttk.Button(repo_frame, text="Browse...", command=self.browse_left).grid(row=0, column=2, padx=4, pady=4)

        # Right repo
        self.right_path_var = tk.StringVar()
        ttk.Label(repo_frame, text="Right (Spring Boot):").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(repo_frame, textvariable=self.right_path_var, width=60).grid(row=1, column=1, sticky="we", padx=4, pady=4)
        ttk.Button(repo_frame, text="Browse...", command=self.browse_right).grid(row=1, column=2, padx=4, pady=4)

        repo_frame.columnconfigure(1, weight=1)

        # Options + Compare
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=(0, 8))

        self.ignore_ws_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Ignore whitespace differences", variable=self.ignore_ws_var).pack(side=tk.LEFT, padx=4)

        ttk.Button(options_frame, text="Compare", command=self.run_compare).pack(side=tk.RIGHT, padx=4)

        # Summary label
        self.summary_var = tk.StringVar(value="No comparison yet.")
        ttk.Label(main_frame, textvariable=self.summary_var).pack(fill=tk.X, pady=(0, 4))

        # Middle: Notebook with file lists
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        self.notebook = notebook

        self.tree_only_left = self._create_tree(notebook, "Only in Left (Quarkus)")
        self.tree_only_right = self._create_tree(notebook, "Only in Right (Spring Boot)")
        self.tree_modified = self._create_tree(notebook, "Modified Files")

        # Bottom: diff viewer
        diff_frame = ttk.LabelFrame(main_frame, text="File / Diff")
        diff_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        self.diff_text = tk.Text(diff_frame, wrap="none", height=20)
        self.diff_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        y_scroll = ttk.Scrollbar(diff_frame, orient=tk.VERTICAL, command=self.diff_text.yview)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.diff_text.configure(yscrollcommand=y_scroll.set)

        x_scroll = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=self.diff_text.xview)
        x_scroll.pack(fill=tk.X)
        self.diff_text.configure(xscrollcommand=x_scroll.set)

        # Monospaced font
        try:
            self.diff_text.configure(font=("Consolas", 10))
        except tk.TclError:
            # fallback to default
            pass

    def _create_tree(self, notebook, title):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text=title)

        columns = ("key",)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        tree.heading("key", text="File (normalized key)")
        tree.column("key", anchor="w", width=600)

        tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scroll.set)

        tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        return tree

    def browse_left(self):
        path = filedialog.askdirectory(title="Select Quarkus repo")
        if path:
            self.left_path_var.set(path)

    def browse_right(self):
        path = filedialog.askdirectory(title="Select Spring Boot repo")
        if path:
            self.right_path_var.set(path)

    def run_compare(self):
        left = self.left_path_var.get().strip()
        right = self.right_path_var.get().strip()

        if not left or not right:
            messagebox.showerror("Error", "Please select both repositories.")
            return

        left_path = Path(left)
        right_path = Path(right)

        if not left_path.is_dir() or not right_path.is_dir():
            messagebox.showerror("Error", "Both paths must be existing directories.")
            return

        self.summary_var.set("Comparing... please wait.")
        self.master.update_idletasks()

        try:
            result = compare_repos(left_path, right_path, ignore_whitespace=self.ignore_ws_var.get())
        except Exception as e:
            messagebox.showerror("Error", f"Comparison failed:\n{e}")
            self.summary_var.set("Comparison failed.")
            return

        self.last_result = result
        self.populate_trees(result)

    def clear_trees(self):
        for tree in (self.tree_only_left, self.tree_only_right, self.tree_modified):
            for item in tree.get_children():
                tree.delete(item)
        self.item_metadata.clear()

    def populate_trees(self, result):
        self.clear_trees()

        only_left = result["only_left"]
        only_right = result["only_right"]
        pairs = result["pairs"]

        n_identical = sum(1 for p in pairs.values() if p["status"] == "identical")
        n_modified = sum(1 for p in pairs.values() if p["status"] == "modified")

        self.summary_var.set(
            f"Left-only: {len(only_left)} | Right-only: {len(only_right)} | Modified: {n_modified} | Identical: {n_identical}"
        )

        # Populate left-only
        for key, path in only_left.items():
            item_id = self.tree_only_left.insert("", "end", values=(key,))
            self.item_metadata[item_id] = {
                "status": "only_left",
                "left": path,
                "right": None,
            }

        # Populate right-only
        for key, path in only_right.items():
            item_id = self.tree_only_right.insert("", "end", values=(key,))
            self.item_metadata[item_id] = {
                "status": "only_right",
                "left": None,
                "right": path,
            }

        # Populate modified
        for key, info in pairs.items():
            if info["status"] != "modified":
                continue
            item_id = self.tree_modified.insert("", "end", values=(key,))
            self.item_metadata[item_id] = {
                "status": "modified",
                "left": info["left"],
                "right": info["right"],
            }

        # Clear diff view
        self.show_text("Select a file to view its contents / diff.")

    def on_tree_select(self, event):
        tree = event.widget
        selection = tree.selection()
        if not selection:
            return
        item_id = selection[0]
        meta = self.item_metadata.get(item_id)
        if not meta:
            return

        status = meta["status"]
        left = meta["left"]
        right = meta["right"]

        try:
            if status == "only_left" and left is not None:
                text = left.read_text(encoding="utf-8", errors="ignore")
                header = f"--- Only in LEFT (Quarkus)\n{left}\n\n"
                self.show_text(header + text)
            elif status == "only_right" and right is not None:
                text = right.read_text(encoding="utf-8", errors="ignore")
                header = f"+++ Only in RIGHT (Spring Boot)\n{right}\n\n"
                self.show_text(header + text)
            elif status == "modified" and left is not None and right is not None:
                self.show_diff(left, right)
            else:
                self.show_text("No data.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file(s):\n{e}")

    def show_text(self, text: str):
        self.diff_text.config(state=tk.NORMAL)
        self.diff_text.delete("1.0", tk.END)
        self.diff_text.insert("1.0", text)
        self.diff_text.config(state=tk.DISABLED)

    def show_diff(self, left: Path, right: Path):
        left_text = left.read_text(encoding="utf-8", errors="ignore").splitlines()
        right_text = right.read_text(encoding="utf-8", errors="ignore").splitlines()

        diff_lines = list(
            difflib.unified_diff(
                left_text,
                right_text,
                fromfile=str(left),
                tofile=str(right),
                lineterm=""
            )
        )

        if not diff_lines:
            content = f"Files are identical after normalization.\n\nLEFT: {left}\nRIGHT: {right}"
        else:
            content = "\n".join(diff_lines)

        self.show_text(content)


def main():
    root = tk.Tk()
    app = DiffCheckerGUI(root)
    root.geometry("900x700")
    root.mainloop()


if __name__ == "__main__":
    main()
