import os
import subprocess
from typing import Self
from pathlib import Path
from yaml import safe_load
from pydantic import BaseModel, Field, field_validator

from .abs_tool import AbsTool
from utils import logger, Config

CWE_TO_SEMGREP_RULE = {
    "cpp": {
        "CWE-476": ["r/cpp.lang.security.memory.null-deref.null-library-function.null-library-function",],
        "CWE-416": ["r/cpp.lang.security.containers.std-vector-invalidation.std-vector-invalidation",
                    "r/cpp.lang.security.strings.return-c-str.return-c-str",
                    "r/cpp.lang.security.strings.string-view-temporary-string.string-view-temporary-string",
                    "r/cpp.lang.security.use-after-free.local-variable-malloc-free.local-variable-malloc-free",
                    "r/cpp.lang.security.use-after-free.local-variable-new-delete.local-variable-new-delete",
                    "r/c.lang.security.function-use-after-free.function-use-after-free",
                    "r/c.lang.security.use-after-free.use-after-free"
                    ],
         "CWE-401": ["/data/jiangjiajun/LLM4Security/resources/semgrep-rules/c/mismatched-memory-management-cpp.yaml",
                    "/data/jiangjiajun/LLM4Security/resources/semgrep-rules/c/mismatched-memory-management.yaml",]
    },
    "java":{
        "CWE-022": [
            "r/java.jax-rs.security.jax-rs-path-traversal.jax-rs-path-traversal",
            "r/java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal",
            "r/java.micronaut.path-traversal.file-access-taint-msg.file-access-taint-msg",
            "r/java.micronaut.path-traversal.file-access-taint-sls.file-access-taint-sls",
            "r/java.micronaut.path-traversal.file-access-taint-ws.file-access-taint-ws",
            "r/java.micronaut.path-traversal.file-access-taint.file-access-taint",
            "r/java.micronaut.path-traversal.file-taint-msg.file-taint-msg",
            "r/java.micronaut.path-traversal.file-taint-sls.file-taint-sls",
            "r/java.micronaut.path-traversal.file-taint-ws.file-taint-ws",
            "r/java.micronaut.path-traversal.file-taint.file-taint",
            "r/java.servlets.security.httpservlet-path-traversal-deepsemgrep.httpservlet-path-traversal-deepsemgrep",
            "r/java.servlets.security.httpservlet-path-traversal.httpservlet-path-traversal",
            "r/java.spring.spring-tainted-path-traversal.spring-tainted-path-traversal",
            "r/gitlab.find_sec_bugs.FILE_UPLOAD_FILENAME-1",
            "r/gitlab.find_sec_bugs.PATH_TRAVERSAL_IN-1",
            "r/gitlab.find_sec_bugs.PATH_TRAVERSAL_OUT-1.PATH_TRAVERSAL_OUT-1",
            "r/gitlab.find_sec_bugs.PT_ABSOLUTE_PATH_TRAVERSAL-1",
            "r/gitlab.find_sec_bugs.PT_RELATIVE_PATH_TRAVERSAL-1",
            "r/gitlab.find_sec_bugs.WEAK_FILENAMEUTILS-1",
        ],
        "CWE-078":[
            "r/java.lang.security.audit.command-injection-formatted-runtime-call.command-injection-formatted-runtime-call",
            "r/java.lang.security.audit.command-injection-process-builder.command-injection-process-builder",
            "r/java.micronaut.command-injection.tainted-system-command-msg.tainted-system-command-msg",
            "r/java.micronaut.command-injection.tainted-system-command-sls.tainted-system-command-sls",
            "r/java.micronaut.command-injection.tainted-system-command-ws.tainted-system-command-ws",
            "r/java.micronaut.command-injection.tainted-system-command.tainted-system-command",
            "r/java.servlets.security.tainted-cmd-from-http-request-deepsemgrep.tainted-cmd-from-http-request-deepsemgrep",
            "r/java.servlets.security.tainted-cmd-from-http-request.tainted-cmd-from-http-request",
            "r/java.spring.command-injection.tainted-system-command.tainted-system-command",
            "r/java.spring.simple-command-injection-direct-input.simple-command-injection-direct-input",
            "r/java.lang.security.audit.tainted-cmd-from-http-request.tainted-cmd-from-http-request",
            "r/java.spring.security.injection.tainted-system-command.tainted-system-command",
            "r/gitlab.find_sec_bugs.COMMAND_INJECTION-1",
            "r/mobsf.mobsfscan.injection.command_injection.command_injection",
            "r/mobsf.mobsfscan.injection.command_injection_formated.command_injection_warning",

        ],
        "CWE-079":[
            "p/xss"
        ],
        "CWE-094":[
            "r/gitlab.find_sec_bugs.TEMPLATE_INJECTION_PEBBLE-1.TEMPLATE_INJECTION_FREEMARKER-1.TEMPLATE_INJECTION_VELOCITY-1",
            "r/gitlab.find_sec_bugs.SCRIPT_ENGINE_INJECTION-1.SPEL_INJECTION-1.EL_INJECTION-2.SEAM_LOG_INJECTION-1",
            "r/java.lang.security.audit.el-injection.el-injection",
            "r/java.lang.security.audit.ognl-injection.ognl-injection",
            "r/java.lang.security.audit.script-engine-injection.script-engine-injection",
            "r/java.spring.security.audit.spel-injection.spel-injection",
        ]
    }
}
        

class Semgrep(AbsTool, BaseModel):

    semgrep_path: Path = Field(
        default=Path("/home/jiangjiajun/miniconda3/bin/semgrep"),
        description="Path to the Semgrep bin."
        )


    programming_language: str = Field(
        default="cpp",
        description="Programming language of the target repository."
    )

    vul_type: str = Field(
        default="",
        description="Type of vulnerability to audit."
    )
    
    
    @field_validator("semgrep_path")
    def validate_paths(cls, v: Path) -> Path:
        if not v.exists():
            raise ValueError(f"Path {v} does not exist.")
        return v


    @field_validator("programming_language")
    def validate_language(cls, v: str) -> str:
        if v not in ["cpp", "java"]:
            raise ValueError(f"Unsupported programming language: {v}. Supported languages are 'cpp' and 'java'.")
        return v
    

    @classmethod
    def from_config(cls, config_file: Path = Path("../semgrep.yaml")) -> Self:
        configs = safe_load(config_file.read_text())
        return cls(
            semgrep_path=Path(configs.get("semgrep_path", "/home/jiangjiajun/miniconda3/bin/semgrep")),
            programming_language=configs.get("programming_language", "cpp"),
            vul_type=configs.get("vul_type", "")
        )


    def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file: Path) -> bool:
        if self.vul_type == "":
            self.vul_type = vulnerability_type
            logger.info(f"Set vulnerability type to {self.vul_type} for Semgrep.")

        if report_file.exists():
            logger.info(f"Semgrep report for {target_repo} already exists, skipping.")
            return True
        
        if self.vul_type != "real_world" and self.vul_type not in CWE_TO_SEMGREP_RULE[self.programming_language]:
            logger.error(f"Unsupported vulnerability type {self.vul_type} for language {self.programming_language}.")
            return False
        
        if target_commit_id != "":
            logger.info(f"Checking out to commit {target_commit_id} in {target_repo}.")
            subprocess.run(f"git checkout -f {target_commit_id}", shell=True, cwd=target_repo)
            logger.info(f"Checked out to commit {target_commit_id} in {target_repo}.")
        
        if self.vul_type == "real_world":
            # scan one time for all the rules
            rules = sum(CWE_TO_SEMGREP_RULE[self.programming_language].values(), [])
            rules = [" "] + rules
        else:
            rules = CWE_TO_SEMGREP_RULE[self.programming_language][self.vul_type]
            rules = [" "] + rules

        cmd_str = f"{self.semgrep_path} scan " + " --config ".join(rules) + " " + str(target_repo.absolute()) + f" --json --sarif-output={report_file}"

        logger.info(f"Scanning {target_repo} using cmd {cmd_str}.")

        subprocess.run(cmd_str, shell=True)

        logger.info(f"Semgrep scan completed for {target_repo}. Report saved to {report_file}.")
