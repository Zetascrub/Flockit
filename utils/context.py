import os
from dataclasses import dataclass
from typing import Optional

from utils.artifacts import ArtifactStore
from utils.common import setup_logging
from utils.config import Config


@dataclass
class ProjectContext:
    """Explicit, threaded-through state for a single tool run. Replaces the
    mutable module-level globals (AUTO/CUSTOM_SETTINGS/SCAN_RESULTS) that
    settings/results used to live in."""

    project_id: str
    project_folder: str  # absolute path
    scope_source_path: str
    config: Config
    artifacts: ArtifactStore
    external_ip: Optional[str] = None
    log_path: str = ""

    @classmethod
    def create(cls, project_id: str, scope_source_path: str, config: Config) -> "ProjectContext":
        project_folder = os.path.abspath(project_id or "PR00000")
        os.makedirs(project_folder, exist_ok=True)
        for sub in ("Screenshots", "Scan-Data"):
            os.makedirs(os.path.join(project_folder, sub), exist_ok=True)

        artifacts = ArtifactStore(project_folder)
        log_path = os.path.join(project_folder, "sift.log")
        setup_logging(log_path)

        return cls(
            project_id=project_id,
            project_folder=project_folder,
            scope_source_path=scope_source_path,
            config=config,
            artifacts=artifacts,
            log_path=log_path,
        )
