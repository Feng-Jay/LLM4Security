import os
import yaml
import subprocess
from pathlib import Path
from .abs_tool import AbsTool
from pydantic import BaseModel, Field, field_validator
from typing import Self
from utils import logger, Config


class SpotBugs(BaseModel, AbsTool):

    plugin_dir: Path = Field(
        default = Path("/data/lifengjie/LLM4Security/resources/findsecbugs-plugin-1.14.0.jar"),
        description = "Path to the directory containing SpotBugs plugins."
    )

    checkers_filter_dir: Path = Field(
        default = Path("/data/lifengjie/LLM4Security/resources/spotbugs_filter/"),
        description = "Path to the directory containing SpotBugs filter files."
    )

    auxiliary_class_dir: Path = Field(
        default = Path("/data/lifengjie/LLM4Security/data/in_house/java/.m2/repository/"),
        description = "Path to the directory containing auxiliary classes for SpotBugs."
    )

    @classmethod
    def from_config(cls, config_path: Path) -> Self:
        with open(config_path, "r") as f:
            config_data = yaml.safe_load(f)
        
        plugin_dir = Path(config_data.get("plugin_dir"))
        checkers_filter_dir = Path(config_data.get("checkers_filter_dir"))
        auxiliary_class_dir = Path(config_data.get("auxiliary_class_dir"))

        return cls(plugin_dir=plugin_dir, checkers_filter_dir=checkers_filter_dir, auxiliary_class_dir=auxiliary_class_dir)
    
    @field_validator("checkers_filter_dir")
    def validate_checkers_filter_dir(cls, value: Path) -> Path:
        if not value.exists() or not value.is_dir():
            raise ValueError(f"Invalid checkers_filter_dir: {value}. It should be an existing directory.")
        return value
    
    @field_validator("plugin_dir")
    def validate_plugin_dir(cls, value: Path) -> Path:
        if not value.exists() or not value.is_file():
            raise ValueError(f"Invalid plugin_dir: {value}. It should be an existing file.")
        return value
    
    @field_validator("auxiliary_class_dir")
    def validate_auxiliary_class_dir(cls, value: Path) -> Path:
        if not value.exists() or not value.is_dir():
            raise ValueError(f"Invalid auxiliary_class_dir: {value}. It should be an existing directory.")
        return value
    
    def split_classes(self, classes_files: list[str], target_repo: Path) -> str:
        def count_class_files_in_dir(dir_path: str) -> int:
            cmd = "find {} -type f -name \"*.class\" | wc -l".format(dir_path)
            res = subprocess.run(cmd, shell=True, cwd=target_repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return int(res.stdout.decode().strip())

        if len(classes_files) == 1:
            return classes_files[0]
        
        dir_to_count = {file: count_class_files_in_dir(file) for file in classes_files}
        # remove 0 count dirs
        dir_to_count = {file: count for file, count in dir_to_count.items() if count > 0}
        classes_files = list(dir_to_count.keys())

        max_class_files = 6000
        if sum(dir_to_count.values()) <= max_class_files:
            return " ".join(classes_files)
        
        groups_by_prefix = {}
        for file in classes_files:
            prefix = file[2:].split("/")[0]
            if prefix not in groups_by_prefix:
                groups_by_prefix[prefix] = []
            groups_by_prefix[prefix].append(file)
        
        continue_splitting = True
        has_new_split = True
        while continue_splitting and has_new_split:
            continue_splitting = False
            has_new_split = False
            for prefix, group in list(groups_by_prefix.items()):
                if prefix == "target" or prefix == "build":
                    continue
                if sum(dir_to_count[file] for file in group) > max_class_files:
                    new_groups = {}
                    print(f"new_groups: {new_groups}")
                    for file in group:
                        if len(file) <= len(prefix) + 3 or len(file[len(prefix)+3:].split("/")) == 0:
                            continue
                        has_new_split = True
                        new_prefix = prefix + "/" + file[len(prefix)+3:].split("/")[0]
                        if new_prefix not in new_groups:
                            new_groups[new_prefix] = []
                        new_groups[new_prefix].append(file)
                    
                    groups_by_prefix[prefix] = []
                    for new_prefix, new_group in new_groups.items():
                        if sum(count_class_files_in_dir(file) for file in new_group) > max_class_files:
                            continue_splitting = True
                        groups_by_prefix[new_prefix] = new_group
        # groups_by_prefix = {k: v for k, v in groups_by_prefix.items() if len(v) > 0 }
        ret_str = "###SPLIT###".join([" ".join(group) for group in groups_by_prefix.values()])
        print(groups_by_prefix)
        # input("Press Enter to continue...")
        return ret_str

    def find_classes_files(self, target_repo: Path) -> str:
        classes_files = []
        if (target_repo / "pom.xml").exists():
            # find target/classes directory
            cmd = "find . -path \"*/target/classes\" -type d"
            res = subprocess.run(cmd, shell=True, cwd=target_repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res.returncode != 0:
                logger.error(f"Failed to find target/classes directory in {target_repo}. Error: {res.stderr.decode()}")
                return ""
            classes_dirs = res.stdout.decode().strip().split("\n")
            for classes_dir in classes_dirs:
                if classes_dir and len(classes_dir) > 0:
                    classes_files.append(classes_dir)
        elif (target_repo / "gradlew").exists():
            # find build/classes/java/main directory
            cmd = "find . -path \"*/build/classes\" -type d"
            res = subprocess.run(cmd, shell=True, cwd=target_repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res.returncode != 0:
                logger.error(f"Failed to find build/classes/ directory in {target_repo}. Error: {res.stderr.decode()}")
                return ""
            classes_dirs = res.stdout.decode().strip().split("\n")
            # print(f"Found classes directories in {target_repo}: {classes_dirs}")
            for classes_dir in classes_dirs:
                if classes_dir and len(classes_dir) > 0:
                    classes_files.append(classes_dir)
        else:
            logger.warning(f"No pom.xml or gradlew found in {target_repo}. Skipping auxiliary class collection for SpotBugs.")
            return ""
        # print(f"Found classes files for {target_repo}: {classes_files}")
        # input("Press Enter to continue...")
        return self.split_classes(classes_files, target_repo)
    
    def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file:Path) -> bool:
        repo_name = target_repo.stem
        
        if report_file.exists():
            logger.info(f"Report file {report_file} already exists. Skipping SpotBugs scan for {repo_name} at commit {target_commit_id}.")
            return True

        if vulnerability_type == "jleaks":
            vulnerability_type = "CWE-772"
        
        filter_file = self.checkers_filter_dir / f"{vulnerability_type}.xml"
        if not filter_file.exists():
            logger.error(f"Filter file for {vulnerability_type} does not exist at {filter_file}. Skipping CSA scan for {repo_name} at commit {target_commit_id}.")
            return False
        

        if not report_file.exists():
            report_file.mkdir(parents=True, exist_ok=True)

        target_classes = self.find_classes_files(target_repo)
        if len(target_classes) == 0:
            logger.warning(f"No classes files found for {repo_name} at commit {target_commit_id}. Skipping auxiliary class inclusion for SpotBugs.")
            return False


        env = os.environ.copy()
        env["JAVA_TOOL_OPTIONS"] = "-Djava.io.tmpdir=/data/lifengjie/tmp"
        amount = len(target_classes.split("###SPLIT###"))
        run_succ = True
        for idx, part in enumerate(target_classes.split("###SPLIT###")):
            part_report_file = report_file / f"{repo_name}_{target_commit_id}_part{idx}.xml"
            
            cmd = f"spotbugs -textui -progress -pluginList {self.plugin_dir} -include {filter_file} -effort:default -low -maxHeap 32768 -Djava.io.tmpdir=/data/lifengjie/tmp/ -xml={part_report_file} -auxclasspath {self.auxiliary_class_dir} {part}"
        
            logger.info(f"Running SpotBugs on {repo_name} {idx}/{amount} at commit {target_commit_id} with command: {cmd}")

            res = subprocess.run(cmd, shell=True, env=env, stderr=subprocess.PIPE, stdout=subprocess.PIPE, cwd=target_repo)
        
            if res.returncode != 0:
                logger.error(f"Failed to run SpotBugs on {repo_name} {idx}/{amount} at commit {target_commit_id}. Error: {res.stderr.decode()}")
                run_succ = False
            else:
                logger.info(f"Successfully ran SpotBugs on {repo_name} {idx}/{amount} at commit {target_commit_id}. Report saved to {part_report_file}.")
        
        if run_succ:
            logger.info(f"Successfully completed SpotBugs scan for {repo_name} at commit {target_commit_id}.")
        else:
            logger.error(f"SpotBugs scan completed with errors for {repo_name} at commit {target_commit_id}. Please check the logs for details.")
        return run_succ