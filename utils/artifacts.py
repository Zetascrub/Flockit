import json
import os
from dataclasses import dataclass
from typing import Optional

from utils.common import print_status


@dataclass
class Artifact:
    label: str
    path: str  # project-root-relative, forward-slash normalized
    kind: str = "generic"  # "nmap" | "banner" | "plugin" | "cve" | "preflight" | "generic"


class ArtifactStore:
    """Owns all file writes under a project root. Replaces save_scan_output's
    manual path-joining — callers get back an Artifact (label+path+kind)
    instead of reconstructing filenames when rendering the report."""

    def __init__(self, project_root: str):
        self.project_root = os.path.abspath(project_root)

    def _host_dir(self, host: str) -> str:
        path = os.path.join(self.project_root, "Scan-Data", host)
        os.makedirs(path, exist_ok=True)
        return path

    def relative(self, abs_path: str) -> str:
        return os.path.relpath(abs_path, self.project_root).replace(os.sep, "/")

    def save_text(self, host: str, filename: str, content: str,
                   label: Optional[str] = None, kind: str = "generic") -> Optional[Artifact]:
        full_path = os.path.join(self._host_dir(host), filename)
        try:
            with open(full_path, "w") as f:
                f.write(content)
            print_status(f"[+] Saved scan output to {full_path}", "info")
            return Artifact(label=label or filename, path=self.relative(full_path), kind=kind)
        except Exception as e:
            print_status(f"[!] Failed to write {full_path}: {e}", "error")
            return None

    def save_json(self, host: str, filename: str, data, label: Optional[str] = None,
                   kind: str = "generic") -> Optional[Artifact]:
        return self.save_text(host, filename, json.dumps(data, indent=2), label=label, kind=kind)

    def save_project_file(self, filename: str, content: str) -> str:
        full_path = os.path.join(self.project_root, filename)
        with open(full_path, "w") as f:
            f.write(content)
        return full_path
