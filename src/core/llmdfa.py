import os
import subprocess
from typing import Self
from pathlib import Path
from yaml import safe_load
from pydantic import BaseModel, Field, field_validator 

from .abs_tool import AbsTool
from utils import Config, logger


class LLMDFA(AbsTool, BaseModel):

    llmdfa_path: Path = Field(
        default=Path("./dependencies/LLMDFA/"),
        description="Path to the LLMDFA tool."
    )

    llm_model: str = Field(
        default="gpt-4-turbo-preview",
        description="LLM model to use for LLMDFA."
    )

    vul_type: str = Field(
        default="",
        description="Type of vulnerability to audit."
    )

    cwe_mappings: dict = {
        "CWE-078": "osci",
        "CWE-079": "xss",
        "CWE-022": "apt"
    }

    @field_validator("llm_model")
    def validate_llm_model(cls, v: str) -> str:
        candidates = ["gpt-3.5-turbo", "gpt-4-turbo", "gpt-4o-mini"]
        if v not in candidates:
            logger.error(f"Invalid LLM model: {v}. Must be one of {candidates}.")
            raise ValueError(f"Invalid LLM model: {v}. Must be one of {candidates}.")
        return v
    
    @classmethod
    def from_config(cls, config_file: Path = Path("../llmdfa.yaml")) -> Self:
        config = safe_load(config_file.read_text())
        llmdfa_path = config.get("llmdfa_path", "./dependencies/LLMDFA/src")
        if not Path(llmdfa_path).exists():
            logger.error(f"LLMDFA path {llmdfa_path} does not exist.")
            raise FileNotFoundError(f"LLMDFA path {llmdfa_path} does not exist.")
        
        llm_model = config.get("llm_model", "gpt-4-turbo-preview")

        vul_type = config.get("vul_type", "")

        return cls(
            llmdfa_path=Path(llmdfa_path),
            llm_model=llm_model,
            vul_type=vul_type
        )

    def set_fl_files(self, fl_files: list[str]) -> None:
        os.environ["LLMDFAFLFILES"] = "#".join(fl_files)

    def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file: Path) -> bool:
        if self.vul_type == "":
            self.vul_type = vulnerability_type
            logger.info(f"Set vulnerability type to {self.vul_type} for LLMDFA.")
        if target_commit_id != "":
            subprocess.run(" ".join(["git", "checkout", "-f", target_commit_id]), cwd=target_repo, shell=True)
            logger.info(f"Checked out to commit {target_commit_id} of {target_repo}.")
        cmd = f"python run_llmdfa.py --bug-type {self.cwe_mappings[self.vul_type]} --model-name {self.llm_model} \
                -syn-parser -fscot -syn-solver --solving-refine-number 3 --analysis-mode all --project_name {target_repo.name}"
        logger.info(f"Running LLMDFA with command: {cmd}")
        subprocess.run(cmd, shell=True, cwd=self.llmdfa_path)
        return True