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

class ClaudeCode(AbsTool, BaseModel):
    
    model_name: str = Field(
        default = "claude-sonnet-4-6",
        description = "LLM model name used in Claude Code."
    )

    project_path: Path = Field(
        default = Path("/data/lifengjie/LLM4Security/data/projects/linux_cc"),
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
        candidates = ["claude-sonnet-4-6"]
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
    def from_config(cls, config_file: Path = Path("../claudecode.yaml")) -> Self:
        config = yaml.safe_load(config_file.read_text())
        model_name = config.get("model_name", "claude-sonnet-4-6")
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
                prompt_str_template += f"""potential vulnerabilities are localized at {self.localization}. """
            if self.src_localization != "":
                prompt_str_template += f"""the source of the vulnerability is located at {self.src_localization}, """
            if self.sink_localization != "":
                prompt_str_template += f"""and the sink is located at {self.sink_localization}."""
            
            prompt_str_template += """And the dataflows/sources/sinks/propogators are connected through this whole project. """
        else:
            prompt_str_template += """Please analyze the whole project to find potential vulnerabilities."""
        
        prompt_str_template += "Please provide a detialed analysis of this project and find potential vulnerabilities if they exist. BTW, do not use tools about online search to answer this question, since they are not allowed in this scenario."
        return prompt_str_template
    
    def run_on_target(self, target_repo, target_commit_id, vulnerability_type, report_file):
        logger.info(f"Running Claude Code on {target_repo} at commit {target_commit_id} for vulnerability type {vulnerability_type}.")
        
        if self.localization != "":
            report_file = report_file.parent / f"{report_file.stem}-{self.localization.replace('/', '-')}"

        if (report_file / "report.txt").exists():
            logger.info(f"Report file {report_file / 'report.txt'} already exists. Skip running Claude Code.")
            return True

        if not report_file.exists():
            report_file.mkdir(parents=True, exist_ok=True)
        
        if self.vul_type == "":
            self.vul_type = vulnerability_type
            logger.info(f"Set vulnerability type to {self.vul_type} for claudecode.")

        # use the unified name, not with the suffix _codex.
        if target_repo.exists():
            self.project_path = target_repo
            # copy the dir to another dir to avoid CVE info leakage in its dir name.
            repo_name = target_repo.stem.split("_")[0]
            target_dir = self.project_path.parent / f"{repo_name}_claudecode"
            # subprocess.run(["cp", "-r", str(target_repo), str(target_dir)], check=True)
            self.project_path = target_dir
            logger.info(f"Set project path to {self.project_path} for Claudecode.")
        
        if target_commit_id != "":
            logger.info(f"Checkout commint {target_commit_id} in {self.project_path}")
            result = subprocess.run(["git", "checkout", "-f", target_commit_id], cwd=self.project_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                logger.error(f"Failed to checkout commit {target_commit_id} in {self.project_path}. Error: {result.stderr.decode()}")
                return False
        
        prompt = self.get_prompt()
        logger.info(f"Generated prompt for Claude Code: {prompt}")

        logger.info(f"Running Claude Code with prompt: {prompt} on project path: {self.project_path}")
        result = subprocess.run(["claude", "--model", "sonnet", "-p", prompt], cwd=self.project_path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # rm the copied repo to avoid disk space issue
        # subprocess.run(["rm", "-rf", str(self.project_path)], check=True)
        # logger.info(f"Removed copied project path {self.project_path} after running ClaudeCode.")

        if result.returncode != 0:
            logger.error(f"Failed to run Claude Code on {self.project_path}. Error: {result.stderr.decode()}")
            return False
        output = result.stdout.decode()

        with open(report_file / "report.txt", "w") as f:
            f.write(output)
        
        # find the chat history and cp it under the report_file dir
        project_path_abs = str(self.project_path.resolve()).rstrip("/")
        project_path_abs = project_path_abs.replace("/", "-").replace("_", "-").replace(".", "-")
        chat_history_path = Path.home() / f".claude/projects/{project_path_abs}/"
        files = [p for p in chat_history_path.iterdir() if p.suffix == ".jsonl"]
        files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        chat_file = files[0]
        chat_id = chat_file.stem
        agent_dir = chat_history_path / f"{chat_id}/"
        if agent_dir.exists():
            subprocess.run(["cp", "-r", str(agent_dir), str(report_file)], check=True)
        if chat_file.exists():
            subprocess.run(["cp", str(chat_file), str(report_file / "claude_chat.jsonl")], check=True)
        
        # rm chat history to save space
        subprocess.run(["rm", "-rf", str(chat_history_path)], check=True)