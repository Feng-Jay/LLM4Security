import yaml
import subprocess
from pathlib import Path

from .abs_tool import AbsTool
from pydantic import BaseModel, Field, field_validator
from typing import Self
from utils import logger, Config

CWE_TO_DESC = {
    "CWE-401": "Memory Leak",
    "CWE-416": "Use After Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-022": "Path Traversal",
    "CWE-078": "OS Command Injection",
    "CWE-079": "Cross-site Scripting (XSS)",
    "CWE-094": "Code Injection",
    "CWE-400": "Uncontrolled Resource Consumption (Resource Exhaustion)",
    "CWE-772": "Missing Release of Resource after Effective Lifetime"
}

class Codex(AbsTool, BaseModel):
    
    model_name: str = Field(
        default = "gpt-5.4",
        description = "LLM model name used in Codex."
    )

    project_path: Path = Field(
        default = Path("/data/lifengjie/LLM4Security/data/projects/linux_codex"),
        description = "Path to the project to be analyzed."
    )

    vul_type: str = Field(
        default = "CWE-401",
        description = "Type of vulnerability to audit."
    )

    localization: str = Field(
        default = "",
        description = "Localization of the vulnerability."
    )

    src_localization: str = Field(
        default = "",
        description = "Localization of the source."
    )

    sink_localization: str = Field(
        default = "",
        description = "Localization of the sink."
    )

    @field_validator("project_path")
    def validate_project_path(cls, v: Path) -> Path:
        if not v.exists():
            raise FileNotFoundError(f"Project path {v} does not exist.")
        return v

    @field_validator("model_name")
    def validate_model_name(cls, v: str) -> str:
        candidates = ["gpt-5.4"]
        if v not in candidates:
            raise ValueError(f"Invalid model name: {v}. Must be one of {candidates}.")
        return v
    
    @field_validator("vul_type")
    def validate_vul_type(cls, v: str) -> str:
        candidates = ["CWE-401", "CWE-416", "CWE-476", "CWE-022", "CWE-078", "CWE-079", "CWE-094", "CWE-400", "CWE-772"]
        if v not in candidates:
            raise ValueError(f"Invalid vulnerability type: {v}. Must be one of {candidates}.")
        return v
    
    @classmethod
    def from_config(cls, config_file: Path = Path("../codex.yaml")) -> Self:
        config = yaml.safe_load(config_file.read_text())
        model_name = config.get("model_name", "gpt-5.4")
        vul_type = config.get("vul_type", "CWE-401")
        return cls(model_name=model_name, vul_type=vul_type)
    
    def set_localization(self, localization: str) -> None:
        self.localization = localization

    def set_src_localization(self, src_localization: str) -> None:
        self.src_localization = src_localization
    
    def set_sink_localization(self, sink_localization: str) -> None:
        self.sink_localization = sink_localization
    

    def get_prompt(self) -> str:
        prompt_str_template = f"""You are a security auditor. 
        Your task is to analyze current project and determine whether it contains {self.vul_type} {CWE_TO_DESC[self.vul_type]} vulnerabilities."""
        if self.localization != "" or self.src_localization != "" or self.sink_localization != "":
            prompt_str_template += """For this project, """
            if self.localization != "":
                prompt_str_template += f"""potential vulnerabilities are localized at {self.localization} files. """
            if self.src_localization != "":
                prompt_str_template += f"""the source of potential vulnerabilities is located at {self.src_localization}, """
            if self.sink_localization != "":
                prompt_str_template += f"""and the sink is located at {self.sink_localization}."""
            
            prompt_str_template += """And the dataflows/sources/sinks/propogators are connected through this whole project. """
        else:
            prompt_str_template += """Please analyze the whole project to find potential vulnerabilities."""
        
        prompt_str_template += "Please provide a detialed analysis of this project and find corresponding vulnerabilities if they exist."
        return prompt_str_template
    
    def run_on_target(self, target_repo, target_commit_id, vulnerability_type, report_file):
        logger.info(f"Running Codex on {target_repo} at commit {target_commit_id} for vulnerability type {vulnerability_type}.")
        if self.localization != "":
            report_file = report_file.parent / f"{report_file.stem}-{self.localization.replace('/', '-')}"
        
        if (report_file / "report.txt").exists():
            logger.info(f"Report file {report_file / 'report.txt'} already exists. Skip running Codex.")
            return True
        
        if not report_file.exists():
            report_file.mkdir(parents=True, exist_ok=True)

        if self.vul_type == "":
            self.vul_type = vulnerability_type
            logger.info(f"Set vulnerability type to {self.vul_type} for Codex.")
        # use the unified name, not with the suffix _codex.
        if target_repo.exists():
            self.project_path = target_repo
            # copy the dir to another dir to avoid CVE info leakage in its dir name.
            repo_name = target_repo.stem.split("_")[0]
            # target_dir = self.project_path.parent / f"{repo_name}_codex"
            # subprocess.run(["cp", "-r", str(target_repo), str(target_dir)], check=True)
            # self.project_path = target_dir
            logger.info(f"Set project path to {self.project_path} for Codex.")

        if target_commit_id != "":
            logger.info(f"Checkout commint {target_commit_id} in {self.project_path}")
            result = subprocess.run(["git", "checkout", "-f", target_commit_id], cwd=self.project_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                logger.error(f"Failed to checkout commit {target_commit_id} in {self.project_path}. Error: {result.stderr.decode()}")
                return False
        
        prompt = self.get_prompt()
        logger.info(f"Generated prompt for Codex: {prompt}")
        from datetime import datetime
        now = datetime.now()
        logger.info(f"Running Codex with prompt: {prompt} on project path: {self.project_path}")
        result = subprocess.run(["codex", "exec", prompt, "--skip-git-repo-check"], cwd=self.project_path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # rm the copied repo to avoid disk space issue
        # subprocess.run(["rm", "-rf", str(self.project_path)], check=True)
        # logger.info(f"Removed copied project path {self.project_path} after running Codex.")

        if result.returncode != 0:
            logger.error(f"Failed to run Codex on {self.project_path}. Error: {result.stderr.decode()}")
            return False
        output = result.stdout.decode()

        with open(report_file / "report.txt", "w") as f:
            f.write(output)
        
        # find the chat history and cp it under the report_file dir
        chat_history_path = Path.home() / f".codex_new/sessions/{now.strftime('%Y')}/{now.strftime('%m')}/{now.strftime('%d')}/"
        files = [p for p in chat_history_path.iterdir() if p.suffix == ".jsonl"]
        files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        chat_file = files[0]
        if chat_file.exists():
            subprocess.run(["cp", str(chat_file), str(report_file / "codex_chat.jsonl")], check=True)