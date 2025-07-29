import os
import yaml
from pathlib import Path
from typing import Optional, Self, List
from pydantic import BaseModel, Field
from .abs_tool import AbsTool
from utils import Config, logger

class Knighter(BaseModel, AbsTool):

    checker_dir:Path = Field(
        default=Path("./dependencies/Knighter/results/debug/"),
        description="Directory where checkers are stored."
    )

    llvm_dir: Path = Field(
        default=Path("../data/projects/llvm-project-llvmorg-18.1.8/"),
        description="Directory where LLVM binaries are located."
    )

    
    @classmethod
    def from_config(cls, config_file: Path = Path("../knighter.yaml")) -> Self:
        """Load configuration from a YAML file."""
        
        configs = yaml.safe_load(config_file.read_text())
        
        checker_dir = configs["checker_dir"]
        if not Path(checker_dir).exists():
            logger.error(f"Checker directory {checker_dir} does not exist.")
            raise FileNotFoundError(f"Checker directory {checker_dir} does not exist.")
        
        llvm_dir = configs.get("llvm_dir", "../data/projects/llvm-project-llvmorg-18.1.8/")
        if not Path(llvm_dir).exists():
            logger.error(f"LLVM directory {llvm_dir} does not exist.")
            raise FileNotFoundError(f"LLVM directory {llvm_dir} does not exist.")
        
        return cls(checker_dir=Path(checker_dir), llvm_dir=Path(llvm_dir))
    
    
    def get_checker_files(self, vulnerability_type: str) -> List[Path]:
        
        if vulnerability_type == "NPD":
            vulnerability_type = "Null-Pointer-Dereference"
        elif vulnerability_type == "OOB":
            vulnerability_type = "Out-of-Bound"
        
        checker_dirs = self.checker_dir.glob(f"test-{vulnerability_type}-*/checkers/*.cpp")
        checker_dirs = [checker for checker in checker_dirs if checker.is_file()]
        return checker_dirs

    
    def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file: Path) -> bool:

        checker_files = self.get_checker_files(vulnerability_type)

        if not checker_files:
            logger.warning(f"No checker files found for vulnerability type '{vulnerability_type}'")
            return False

        logger.info(f"get {len(checker_files)} checker files for vulnerability type '{vulnerability_type}'")
        logger.info(f"Running Knighter on target repository: {target_repo} at commit: {target_commit_id}")
        for checker_file in checker_files:

            # write checker 
            checker_code_write_dst = self.llvm_dir / "clang/lib/Analysis/plugins/SAGenTestHandling/SAGenTestChecker.cpp"
            with open(checker_code_write_dst, "w") as f:
                f.write(checker_file.read_text())
            logger.info(f"Checker file {checker_file} written to {checker_code_write_dst}")

            current_dir = os.getcwd()
            # build checker
            os.chdir(self.llvm_dir / "build")
            os.system("make SAGenTestPlugin CFLAGS+='-Wall' -j{}".format(32))
            os.chdir(current_dir)

            cmd =f"PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build " \
                f"--use-cc={self.llvm_dir}/build/bin/clang -load-plugin {self.llvm_dir}/build/lib/SAGenTestPlugin.so " \
                "-enable-checker custom.SAGenTestChecker " \
                "-disable-checker core -disable-checker cplusplus -disable-checker deadcode -disable-checker unix -disable-checker nullability -disable-checker security -maxloop 4 " \
                f"-o {report_file} make LLVM=1 ARCH=x86 -j32"
            os.chdir(target_repo)
            os.system(f"git checkout -f {target_commit_id}")
            logger.info("checkout to commit: {}".format(target_commit_id))
            os.system("make LLVM=1 ARCH=x86 allyesconfig")
            logger.info("make allyesconfig done")
            res = os.system(cmd)
            logger.info(f"Running command: {cmd} in {target_repo}")
            os.system("git checkout -f master")
            os.chdir(current_dir)
            print(f"Command executed with return code: {res}")
            # break
        pass
