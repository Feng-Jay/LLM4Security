import yaml
import subprocess
from pathlib import Path

from .abs_tool import AbsTool
from pydantic import BaseModel, Field, field_validator
from typing import Self
from utils import logger, Config


CWE_TO_CODEQL_QUERY = {
    "cpp": 
    {
        "CWE-476": "/data/jiangjiajun/LLM4Security/resources/codeql_queries/c_NPD.qls",
        "CWE-401": "/data/jiangjiajun/LLM4Security/resources/codeql_queries/c_MLK.qls",
        "CWE-416": "/data/jiangjiajun/LLM4Security/resources/codeql_queries/c_UAF.qls"
    },
    "java": 
    {
        "CWE-022": "/data/jiangjiajun/LLM4Security/resources/codeql_queries/java_APT.qls",
        "CWE-078": "/data/jiangjiajun/LLM4Security/resources/codeql_queries/java_OSCI.qls",
        "CWE-079": "/data/jiangjiajun/LLM4Security/resources/codeql_queries/java_XSS.qls",
        "CWE-094": "/data/jiangjiajun/LLM4Security/resources/codeql_queries/java_CI.qls",
        "CWE-400": "/data/jiangjiajun/LLM4Security/resources/codeql_queries/java_RL.qls",
    }
}


class CodeQL(AbsTool, BaseModel):
    
    codeql_bin_path: Path = Field(
        default=Path("/data/jiangjiajun/LLM4Security/resources/codeql/codeql"),
        description="Path to the CodeQL's exec file."
    )
    database_path: Path = Field(
        default=Path("/data/jiangjiajun/LLM4Security/data/codeql-dbs/"),
        description="Path to store CodeQL databases."
    )
    programming_language: str = Field(
        default="cpp",
        description="Programming language of the target repository."
    )


    @field_validator("codeql_bin_path")
    def validate_paths(cls, v: Path) -> Path:
        if not v.exists():
            raise ValueError(f"Path {v} does not exist.")
        return v
    

    @field_validator("programming_language")
    def validate_language(cls, v: str) -> str:
        if v not in ["c-cpp", "java"]:
            raise ValueError(f"Unsupported programming language: {v}. Supported languages are 'cpp' and 'java'.")
        return v
    
    
    @classmethod
    def from_config(cls, config_file: Path = Path("../codeql.yaml")) -> Self:
        configs = yaml.safe_load(config_file.read_text())
        return cls(
            codeql_bin_path=Path(configs.get("codeql_bin_path", "/data/jiangjiajun/LLM4Security/resources/codeql/codeql")),
            database_path=Path(configs.get("codeql_db_dir", "/data/jiangjiajun/LLM4Security/data/codeql-dbs/")),
            programming_language=configs.get("programming_language", "c-cpp")
        )


    def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file: Path) -> bool:
        
        # first checkout to the target commit if commit_id is provided
        if target_commit_id != "":
            subprocess.run(" ".join(["git", "checkout", "-f", target_commit_id]), cwd=target_repo, shell=True)
            logger.info(f"Checked out to commit {target_commit_id} of {target_repo}.")
        else:
            logger.info(f"Running CodeQL on {target_repo} at commit {target_commit_id} for vulnerability type {vulnerability_type}.")
        
        # then build the codeql database
        if not (self.database_path / f"{target_repo.name}-{target_commit_id}").exists():
            
            if not self.database_path.exists():
                self.database_path.mkdir(parents=True)
            
            create_db_cmd = [
                str(self.codeql_bin_path),
                "database",
                "create",
                "--threads=3",
                str(self.database_path / f"{target_repo.name}-{target_commit_id}"),
                f"--language={self.programming_language}",  # assuming C/C++ code, modify as needed
                f"--source-root={str(target_repo)}",
                "--overwrite",
                "--build-mode=none"
            ]
            logger.info(f"Creating CodeQL database for {target_repo} at commit {target_commit_id}.")
            db_create_result = subprocess.run(" ".join(create_db_cmd), check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            print(db_create_result)
            if db_create_result.returncode != 0:
                logger.error(f"Failed to create CodeQL database for {target_repo} at commit {target_commit_id}. Error: {db_create_result.stderr.decode()}")
                return False
            logger.info(f"Successfully created CodeQL database for {target_repo} at commit {target_commit_id}.")
        else:
            logger.info(f"CodeQL database for {target_repo} at commit {target_commit_id} already exists. Skipping database creation.")
        
        # finally run the codeql query
        query_suite = CWE_TO_CODEQL_QUERY.get(self.programming_language, {}).get(vulnerability_type, "")

        db_check_cmd = [
            str(self.codeql_bin_path),
            "database",
            "analyze",
            str(self.database_path / f"{target_repo.name}-{target_commit_id}"),
            query_suite,
            "--format=sarif-latest",
            f"--output={str(report_file)}"
        ]
        
        logger.info(f"Scanning with {db_check_cmd}")
        db_scan_result = subprocess.run(" ".join(db_check_cmd), check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        if db_scan_result.returncode != 0:
            logger.error(f"Failed to run CodeQL analysis for {target_repo} at commit {target_commit_id}. Error: {db_scan_result.stderr.decode()}")
            return False
        
        logger.info(f"Successfully ran CodeQL analysis for {target_repo} at commit {target_commit_id}. Report saved to {report_file}.")

        return True