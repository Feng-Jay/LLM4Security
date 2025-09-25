import os
import subprocess
from yaml import safe_load
from pathlib import Path
from typing import Self, List, Optional
from pydantic import BaseModel, Field
from .abs_tool import AbsTool
from utils import Config, logger

class RepoAudit(AbsTool, BaseModel):

    repoaudit_path: Path = Field(
        default=Path("./dependencies/RepoAudit/"),
        description="Path to the RepoAudit tool."
    )
    
    project_path: Path = Field(
        default=Path("./data/projects/linux"),
        description="Path to the projects to be scanned."
    )
    
    vul_type: str = Field(
        default="CWE-401",
        description="Type of vulnerability to audit."
    )

    model_name: str = Field(
        default="claude-3.5",
        description="LLMs to use for auditing."
    )

    @classmethod
    def from_config(cls, config_file: Path = Path("../repoaudit.yaml")) -> Self:
        config = safe_load(config_file.read_text())
        repoaudit_path = config.get("repoaudit_path", "./dependencies/RepoAudit/")
        if not Path(repoaudit_path).exists():
            logger.error(f"RepoAudit path {repoaudit_path} does not exist.")
            raise FileNotFoundError(f"RepoAudit path {repoaudit_path} does not exist.")
        
        project_path = config.get("project_path", "./data/projects/linux")
        logger.info(f"Project path: {project_path}")
        if not Path(project_path).exists():
            logger.error(f"Project path {project_path} does not exist.")
            raise FileNotFoundError(f"Project path {project_path} does not exist.")
        vul_type = config.get("vul_type", "CWE-401")
        candidates = ["MLK", "NPD", "UAF"]
        if vul_type not in candidates:
            logger.error(f"Invalid vulnerability type: {vul_type}. Must be one of {candidates}.")
            raise ValueError(f"Invalid vulnerability type: {vul_type}. Must be one of {candidates}.")

        model_name = config.get("model_name", "claude-3.5")
    
        return cls(
            repoaudit_path=Path(repoaudit_path),
            project_path=Path(project_path),
            vul_type=vul_type,
            model_name=model_name
        )
    
    def set_localization(self, localization: str) -> None:
        if localization.startswith("drivers"):
            if len(localization.split("/")) > 1:
                localization = "drivers/" + localization.split("/")[1]
        else:
            localization = localization.split("/")[0]
        os.environ["VULPATH"] = localization

    def set_src_localization(self, localization: str) -> None:
        os.environ["SRC_VULPATH"] = localization
    
    def set_sink_localization(self, localization: str) -> None:
        os.environ["SINK_VULPATH"] = localization
    
    def set_src_api(self, api: str) -> None:
        os.environ["SRC_API"] = api
    
    def set_sink_api(self, api: str) -> None:
        os.environ["SINK_API"] = api
    
    def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file: Path) -> bool:
        
        logger.info(f"Checkout commint {target_commit_id} in {self.project_path}")
        
        result = subprocess.run(["git", "checkout", "-f", target_commit_id], cwd=self.project_path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            logger.error(f"Failed to checkout commit {target_commit_id}: {result.stderr.decode()}")
            return False
        if os.environ.get("VULPATH").startswith("drivers"):
            target_repo = target_repo / os.environ.get("VULPATH", "src").split("/")[0] / os.environ.get("VULPATH", "src").split("/")[1]
            # self.set_localization(os.environ.get("VULPATH", "src").split("/")[0] + "/" + os.environ.get("VULPATH", "src").split("/")[1])
        else:
            target_repo = target_repo / os.environ.get("VULPATH", "src").split("/")[0]
        
        logger.info(f"Running RepoAudit on {target_repo} for vulnerability type {vulnerability_type}")
        cmd = f"python repoaudit.py \
                --language Cpp \
                --model-name {self.model_name} \
                --project-path {target_repo} \
                --commit_id {target_commit_id[:-1]} \
                --bug-type {self.vul_type} \
                --temperature 0.0 \
                --scan-type dfbscan \
                --call-depth 3 \
                --max-neural-workers 30"
        cmd = f"python3 repoaudit.py \
                --language Cpp \
                --model-name {self.model_name}\
                --project-path {target_repo} \
                --bug-type {self.vul_type} \
                --temperature 0.0 \
                --scan-type dfbscan \
                --commit_id {target_commit_id[:-1]} \
                --call-depth 3 \
                --max-neural-workers 30"
        logger.info(f"Command to run: {cmd}")
        subprocess.run(cmd, shell=True, check=True, cwd=self.repoaudit_path)
        pass

    pass