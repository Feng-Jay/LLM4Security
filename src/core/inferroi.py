import os
import yaml
import subprocess
from pathlib import Path
from typing import Optional, Self, List
from pydantic import BaseModel, Field

from .abs_tool import AbsTool
from utils import Config, logger

class Inferroi(BaseModel, AbsTool):
    inferroi_dir: Path = Field(
        default=Path("./dependencies/INFERROI/"),
        description="Directory where INFERROI is located."
    )
    project_path: Path = Field(
        default=Path("./dependencies/iris/data/cwe-bench-java/project-sources"),
        description="Path to the project to be scanned."
    )

    @classmethod
    def from_config(cls, config_file: Path = Path("../inferroi.yaml")) -> Self:
        """Load configuration from a YAML file."""
        
        configs = yaml.safe_load(config_file.read_text())
        
        inferroi_dir = configs.get("inferroi_dir", "./dependencies/INFERROI/")
        if not Path(inferroi_dir).exists():
            logger.error(f"INFERROI directory {inferroi_dir} does not exist.")
            raise FileNotFoundError(f"INFERROI directory {inferroi_dir} does not exist.")
        
        project_path = configs.get("project_path", "./dependencies/iris/data/cwe-bench-java/project-sources")
        if not Path(project_path).exists():
            logger.error(f"Project path {project_path} does not exist.")
            raise FileNotFoundError(f"Project path {project_path} does not exist.")
        
        return cls(
            inferroi_dir=Path(inferroi_dir),
            project_path=Path(project_path)
        )
    
    def run_on_target(self, target_repo, target_commit_id, vulnerability_type, report_file) -> bool:
        cmd = f"python -m script.scan_project -project_path {target_repo}"
        
        logger.info(f"Running INFERROI on {target_repo} with command: {cmd}")
        try:
            subprocess.run(cmd, shell=True, check=True, cwd=self.inferroi_dir)
        except Exception as e:
            logger.error(f"Failed to run INFERROI: {e}")
            return False
        
        return True


        
        