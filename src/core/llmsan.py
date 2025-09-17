
import os
import subprocess
from typing import Self 
from pathlib import Path
from yaml import safe_load
from pydantic import BaseModel, Field, field_validator

from .abs_tool import AbsTool
from utils import Config, logger


class LLMSAN(AbsTool, BaseModel):
    llmsan_path : Path = Field(
        default=Path("./dependencies/LLMSAN/"),
        description="Path to the LLMSAN tool."
    )
    llm_model: str = Field(
        default="gpt-4-turbo",
        description="LLM model to use for LLMSAN."
    )
    cwe_mappings: dict = {
        "CWE-022": "apt",
        "CWE-078": "ci",
        "CWE-079": "xss"
    }

    @field_validator("llm_model")
    def validate_llm_model(cls, v: str) -> str:
        candidates = ["gpt-3.5-turbo", "gpt-4-turbo", "gpt-4o-mini"]
        if v not in candidates:
            logger.error(f"Invalid LLM model: {v}. Must be one of {candidates}.")
            raise ValueError(f"Invalid LLM model: {v}. Must be one of {candidates}.")
        return v

    @classmethod
    def from_config(cls, config_file: Path = Path("../llmsan.yaml")) -> Self:
        config = safe_load(config_file.read_text())
        llmsan_path = config.get("llmsan_path", "./dependencies/LLMSAN/src")
        if not Path(llmsan_path).exists():
            logger.error(f"LLMSAN path {llmsan_path} does not exist.")
            raise FileNotFoundError(f"LLMSAN path {llmsan_path} does not exist.")
        
        llm_model = config.get("llm_model", "gpt-4-turbo")
    
        return cls(
            llmsan_path=Path(llmsan_path),
            llm_model=llm_model
        )

    def set_fl_files(self, fl_files: list[str]) -> None:
        os.environ["LLMSANFLFILES"] = "#".join(fl_files)

    def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file: Path) -> bool:
        cmd = f"python batchrun.py --project-name={target_repo} --bug-type={self.cwe_mappings[vulnerability_type]} --detection-model={self.llm_model} \
                --sanitization-model={self.llm_model} --analysis-mode=eager --project-mode=all --engine=llmsan --global-temperature=0.0 \
                -functionality-sanitize -reachability-sanitize --self-consistency-k=1"
        logger.info(f"Running LLMSAN with command: {cmd}")
        subprocess.run(cmd, shell=True, cwd=self.llmsan_path)
        return True