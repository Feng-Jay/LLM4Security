import os
import yaml
import subprocess
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

    commits_dir:Path = Field(
        default=Path("./dependencies/Knighter/commits/commits.txt"),
        description="Directory where Linux commits are stored."
    )

    llvm_dir: Path = Field(
        default=Path("../data/projects/llvm-project-llvmorg-18.1.8/"),
        description="Directory where LLVM binaries are located."
    )

    patches_dir: Path = Field(
        default=Path("./resources/linux_patches/"),
        description="Directory where Linux patches are stored."
    )

    vul_type: str = Field(
        default="",
        description="Type of vulnerability to audit."
    )

    cwe_mappings: dict = {
        "CWE-401": "MLK",
        "CWE-416": "UAF",
        "CWE-476": "NPD"
    }

    localization: str = "fs"
    
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
        
        commits_dir = configs.get("commits_dir", "./dependencies/Knighter/commits/commits.txt")

        patches_dir = configs.get("patches_dir", "./resources/linux_patches/")

        vul_type = configs.get("vul_type", "")
        
        return cls(checker_dir=Path(checker_dir), llvm_dir=Path(llvm_dir), commits_dir=Path(commits_dir),
                    patches_dir=Path(patches_dir), vul_type=vul_type)
    
    
    def get_checker_files(self, vulnerability_type: str) -> List[Path]:
        
        vulnerability_type = self.cwe_mappings.get(self.vul_type, self.vul_type)
        # print(f"Get checker files for vulnerability type: {vulnerability_type}")
        # input("Press Enter to continue...")
        if vulnerability_type == "NPD":
            vulnerability_type = "Null-Pointer-Dereference"
        elif vulnerability_type == "OOB":
            vulnerability_type = "Out-of-Bound"
        elif vulnerability_type == "UBI":
            vulnerability_type = "Uninit-Data"
        elif vulnerability_type == "MLK":
            vulnerability_type = "Memory-Leak"

        lines = self.commits_dir.read_text().splitlines()
        commits = []
        for line in lines:
            line = line.strip()
            if vulnerability_type == "real_world":
                if "Null-Pointer-Dereference" in line or "UAF" in line or "Uninit-Data" in line or "Memory-Leak" in line:
                # if "Memory-Leak" in line in line:
                    commit_id = line.split(",")[0]
                    commits.append(commit_id)
            elif vulnerability_type in line:
                commit_id = line.split(",")[0]
                commits.append(commit_id)
        
        refine_result_lines = (self.checker_dir / "refine.log").read_text().splitlines()
        for commit in commits:
            for line in refine_result_lines:
                if commit in line and not ("Perfect" in line or "Refined" in line):
                    commits.remove(commit)
                    break

        logger.info(f"get {len(commits)} checkers for vulnerability type '{vulnerability_type}'")
        result_files = []
        for commit in commits:
            if not (self.checker_dir / commit).exists():
                continue
            candidate_files = (self.checker_dir / commit).glob("*.cpp")
            for file in candidate_files:
                if "-correct-repair" in file.name:
                    candidate_files = [file]
                    break
            result_files.append((self.checker_dir / commit / "checker1.cpp"))

        return result_files


    def set_localization(self, localization: str) -> None:
        self.localization = localization

    def prepare_build(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file:Path) -> bool:
        repo_name = target_repo.stem
        current_dir = os.getcwd()

        checker_files = self.get_checker_files(self.vul_type)
        if not checker_files:
            logger.warning(f"No checker files found for vulnerability type '{self.vul_type}'")
            return False
        
        for checker_file in checker_files:
            # write checker 
            checker_code_write_dst = self.llvm_dir / "clang/lib/Analysis/plugins/SAGenTestHandling/SAGenTestChecker.cpp"
            with open(checker_code_write_dst, "w") as f:
                f.write(checker_file.read_text())
            logger.info(f"Checker file {checker_file} written to {checker_code_write_dst}")

            # build checker
            os.chdir(self.llvm_dir / "build")
            os.system("make SAGenTestPlugin CFLAGS+='-Wall' -j{}".format(32))
           
            # build command
            os.chdir(target_repo)
            match repo_name:
                case "linux":
                    cmd ="{" + f"env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build " \
                        f"--use-cc={self.llvm_dir}/build/bin/clang -load-plugin {self.llvm_dir}/build/lib/SAGenTestPlugin.so " \
                            "-enable-checker custom.SAGenTestChecker " \
                            "-disable-checker core -disable-checker cplusplus -disable-checker deadcode -disable-checker unix -disable-checker nullability -disable-checker security -maxloop 4 " \
                        f"-o {report_file / target_commit_id} make LLVM=1 ARCH=x86 LLVM_IAS=1 -j32 KCFLAGS=\"-Wno-error -Wno-strict-prototypes -Qunused-arguments\" HOSTCFLAGS=\"-Wno-error\" HOSTCPPFLAGS=\"-Wno-error\" 2>&1 | tee ../KNighter_build_{target_commit_id}.log" + "}"
                    
                    os.system("make clean")
                    print(self.patches_dir)
                    for patch_file in self.patches_dir.glob("*.diff"):
                        patch_cmd = "patch -p1 --no-backup-if-mismatch --forward < {}".format(patch_file)
                        res = os.system(patch_cmd)
                    logger.info("apply patches done")
                    
                    os.system("make LLVM=1 ARCH=x86 allyesconfig")
                    logger.info("make allyesconfig done")

                    os.system("./scripts/config --enable COMPAT_BCMP")
                    os.system("./scripts/config --enable COMPAT_STPCPY")
                    os.system("scripts/config --disable LLVM_KCOV; scripts/config --disable LLVM_IAS;scripts/config --disable LLVM;scripts/config --disable LLVM_GCOV")
                    os.system("sed -i 's/CONFIG_MODULE_SIG=.*/CONFIG_MODULE_SIG=n/' .config")
                    os.system("sed -i 's/CONFIG_MODULE_SIG_ALL=.*/CONFIG_MODULE_SIG_ALL=n/' .config")
                    os.system("sed -i 's/CONFIG_XFS_DEBUG=.*/CONFIG_XFS_DEBUG=n/' .config")
                    os.system("sed -i 's/CONFIG_XFS_RT=.*/CONFIG_XFS_RT=n/' .config")
                    os.system("sed -i 's/CONFIG_XFS_ASSERT_FATAL=.*/CONFIG_XFS_ASSERT_FATAL=n/' .config")
                    os.system("sed -i 's/CONFIG_XFS_ONLINE_SCRUB=.*/CONFIG_XFS_ONLINE_SCRUB=n/' .config")
                    os.system("sed -i 's/CONFIG_XFS_ONLINE_REPAIR=.*/CONFIG_XFS_ONLINE_REPAIR=n/' .config")
                    # Append if missing
                    os.system(f"grep -q '^CONFIG_MODULE_SIG=' .config || echo 'CONFIG_MODULE_SIG=n' >> .config")
                    os.system(f"grep -q '^CONFIG_MODULE_SIG_ALL=' .config || echo 'CONFIG_MODULE_SIG_ALL=n' >> .config")
                    os.system("sed -i 's/CONFIG_MODULE_SIG_KEY=.*/CONFIG_MODULE_SIG_KEY=\"\"/' .config")
                    # input("Press Enter to continue...")
                    # tcl can automatically handle interactive prompts during build.
                    with open(f"./test.tcl", "w") as f:
                        f.write("#!/usr/bin/env expect\n")
                        f.write("set timeout -1\n")
                        f.write(f"spawn sh -c {cmd}\n")
                        f.write("expect {\n")
                        f.write(" -re {.*\\[N/y.*}       { send \"N\\r\"; exp_continue }\n")
                        f.write(" -re {.*\\[Y/n.*}       { send \"N\\r\"; exp_continue }\n")
                        f.write(" -re {.*choice\\[.*\\].*}   { send \"\\r\"; exp_continue }\n")
                        f.write(" eof\n")
                        f.write("}\n")
                        f.write("set ret [wait]\n")
                        f.write("set retcode [lindex $ret 3]\n")
                        f.write("exit $retcode\n")
                    os.system(f"chmod +x ./test.tcl")
                    res = os.system(f"./test.tcl")
                    logger.info(f"Running command: {cmd} in {target_repo}")
                    if res != 0:
                        logger.error(f"Run failed on vulnerability {target_repo} at commit {target_commit_id}.")
                        logger.error(f"Command failed with return code {res}.")
                        return False
                case "vim":
                    os.system("make clean")
                    logger.info("Applying patches for Vim...")
                    for patch_file in self.patches_dir.glob("*.diff"):
                        patch_cmd = "patch -p1 --no-backup-if-mismatch --forward < {}".format(patch_file)
                        res = os.system(patch_cmd)
                        
                    # os.system(f"make clean && cd src && autoconf && CC=clang LDFLAGS=\"-ltinfo\"  ./configure && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang -load-plugin {self.llvm_dir}/build/lib/SAGenTestPlugin.so -enable-checker custom.SAGenTestChecker -disable-checker core -disable-checker cplusplus -disable-checker deadcode -disable-checker unix -disable-checker nullability -disable-checker security -maxloop 4 -o {report_file / target_commit_id} make -j32 2>&1 | tee ../KNighter_build_vim_{target_commit_id}.log")
                    os.system(f"make clean && cd src && CC=clang ./configure && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang -load-plugin {self.llvm_dir}/build/lib/SAGenTestPlugin.so -enable-checker custom.SAGenTestChecker -disable-checker core -disable-checker cplusplus -disable-checker deadcode -disable-checker unix -disable-checker nullability -disable-checker security -maxloop 4 -o {report_file / target_commit_id} make -j32 2>&1 | tee ../KNighter_build_vim_{target_commit_id}.log")
                case "gpac":
                    os.system("make distclean")
                    os.system(f"CC=clang ./configure --disable-werror && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang -load-plugin {self.llvm_dir}/build/lib/SAGenTestPlugin.so -enable-checker custom.SAGenTestChecker -disable-checker core -disable-checker cplusplus -disable-checker deadcode -disable-checker unix -disable-checker nullability -disable-checker security -maxloop 4 -o {report_file / target_commit_id} make -j32 2>&1 | tee ../KNighter_build_gpac_{target_commit_id}.log")
                case "ImageMagick":
                    os.system("make clean")
                    os.system(f"CC=clang CXX=clang++ ./configure --disable-werror && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang -load-plugin {self.llvm_dir}/build/lib/SAGenTestPlugin.so -enable-checker custom.SAGenTestChecker -disable-checker core -disable-checker cplusplus -disable-checker deadcode -disable-checker unix -disable-checker nullability -disable-checker security -maxloop 4 -o {report_file / target_commit_id} make -j32 2>&1 | tee ../KNighter_build_ImageMagick_{target_commit_id}.log")
                case "bitlbee":
                    os.system("make clean")
                    os.system(f"CC=clang CXX=clang++ ./configure --disable-werror && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang -load-plugin {self.llvm_dir}/build/lib/SAGenTestPlugin.so -enable-checker custom.SAGenTestChecker -disable-checker core -disable-checker cplusplus -disable-checker deadcode -disable-checker unix -disable-checker nullability -disable-checker security -maxloop 4 -o {report_file / target_commit_id} make -j32 2>&1 | tee ../KNighter_build_bitlbee_{target_commit_id}.log")
                case "radare2":
                    os.system("make clean")
                    os.system(f"CC=clang CXX=clang++ ./configure && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang -load-plugin {self.llvm_dir}/build/lib/SAGenTestPlugin.so -enable-checker custom.SAGenTestChecker -disable-checker core -disable-checker cplusplus -disable-checker deadcode -disable-checker unix -disable-checker nullability -disable-checker security -maxloop 4 -o {report_file / target_commit_id} make all -j32  CS_COMMIT_ARCHIVE=1 2>&1 | tee ../KNighter_build_radare2_{target_commit_id}.log ")
        os.chdir(current_dir)
        return True

    
    # def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file: Path) -> bool:
    #     # vulnerability_type = "real_world"
    #     if self.vul_type == "":
    #         self.vul_type = vulnerability_type
    #         logger.info(f"Set vulnerability type to {self.vul_type} for Knighter.")

    #     checker_files = self.get_checker_files(self.vul_type)

    #     if not checker_files:
    #         logger.warning(f"No checker files found for vulnerability type '{self.vul_type}'")
    #         return False

    #     logger.info(f"get {len(checker_files)} checker files for vulnerability type '{self.vul_type}'")
    #     logger.info(f"Running Knighter on target repository: {target_repo} at commit: {target_commit_id}")
    #     for checker_file in checker_files:
    #         # write checker 
    #         checker_code_write_dst = self.llvm_dir / "clang/lib/Analysis/plugins/SAGenTestHandling/SAGenTestChecker.cpp"
    #         with open(checker_code_write_dst, "w") as f:
    #             f.write(checker_file.read_text())
    #         logger.info(f"Checker file {checker_file} written to {checker_code_write_dst}")

    #         current_dir = os.getcwd()
    #         # build checker
    #         os.chdir(self.llvm_dir / "build")
    #         os.system("make SAGenTestPlugin CFLAGS+='-Wall' -j{}".format(32))
    #         os.chdir(current_dir)
    #         # cmd =f"{self.llvm_dir}/build/bin/scan-build " \
    #         #     f"--use-cc={self.llvm_dir}/build/bin/clang -load-plugin {self.llvm_dir}/build/lib/SAGenTestPlugin.so " \
    #         #     "-enable-checker custom.SAGenTestChecker " \
    #         #     "-disable-checker core -disable-checker cplusplus -disable-checker deadcode -disable-checker unix -disable-checker nullability -disable-checker security -maxloop 4 " \
    #         #     f"-o {report_file / checker_file.parent.name} make CC=clang -j32 2>&1 | tee ../build_{target_commit_id}.log"
    #         cmd ="{" + f"env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build " \
    #             f"--use-cc={self.llvm_dir}/build/bin/clang -load-plugin {self.llvm_dir}/build/lib/SAGenTestPlugin.so " \
    #             "-enable-checker custom.SAGenTestChecker " \
    #             "-disable-checker core -disable-checker cplusplus -disable-checker deadcode -disable-checker unix -disable-checker nullability -disable-checker security -maxloop 4 " \
    #             f"-o {report_file / checker_file.parent.name} make LLVM=1 ARCH=x86 LLVM_IAS=1 -j32 KCFLAGS=\"-Wno-error -Wno-strict-prototypes -Qunused-arguments\" HOSTCFLAGS=\"-Wno-error\" HOSTCPPFLAGS=\"-Wno-error\" 2>&1 | tee ../build_{target_commit_id}.log" + "}"
            
    #         os.chdir(target_repo)
    #         os.system(f"git checkout -f {target_commit_id}")
    #         # os.chdir(target_repo/"src")
            
    #         os.system("make clean")
            
    #         # os.system("./configure --cc=clang")
            
    #         logger.info("checkout to commit: {}".format(target_commit_id))
    #         logger.info("apply the candidate patches")
    #         for patch_file in self.patches_dir.glob("*.diff"):
    #             patch_cmd = "patch -p1 --no-backup-if-mismatch --forward < {}".format(patch_file)
    #             res = os.system(patch_cmd)
    #         logger.info("apply patches done")
    #         os.system("make LLVM=1 ARCH=x86 allyesconfig")
    #         logger.info("make allyesconfig done")
    #         # os.system("./scripts/config --enable COMPAT_BCMP")
    #         os.system("./scripts/config --enable COMPAT_STPCPY")
    #         os.system("scripts/config --disable LLVM_KCOV; scripts/config --disable LLVM_IAS;scripts/config --disable LLVM;scripts/config --disable LLVM_GCOV")
    #         os.system("sed -i 's/CONFIG_MODULE_SIG=.*/CONFIG_MODULE_SIG=n/' .config")
    #         os.system("sed -i 's/CONFIG_MODULE_SIG_ALL=.*/CONFIG_MODULE_SIG_ALL=n/' .config")
    #         os.system("sed -i 's/CONFIG_XFS_DEBUG=.*/CONFIG_XFS_DEBUG=n/' .config")
    #         os.system("sed -i 's/CONFIG_XFS_RT=.*/CONFIG_XFS_RT=n/' .config")
    #         os.system("sed -i 's/CONFIG_XFS_ASSERT_FATAL=.*/CONFIG_XFS_ASSERT_FATAL=n/' .config")
    #         os.system("sed -i 's/CONFIG_XFS_ONLINE_SCRUB=.*/CONFIG_XFS_ONLINE_SCRUB=n/' .config")
    #         os.system("sed -i 's/CONFIG_XFS_ONLINE_REPAIR=.*/CONFIG_XFS_ONLINE_REPAIR=n/' .config")
    #         # Append if missing
    #         os.system(f"grep -q '^CONFIG_MODULE_SIG=' .config || echo 'CONFIG_MODULE_SIG=n' >> .config")
    #         os.system(f"grep -q '^CONFIG_MODULE_SIG_ALL=' .config || echo 'CONFIG_MODULE_SIG_ALL=n' >> .config")
    #         os.system("sed -i 's/CONFIG_MODULE_SIG_KEY=.*/CONFIG_MODULE_SIG_KEY=\"\"/' .config")
    #         # input("Press Enter to continue...")
    #         with open(f"{self.checker_dir.parent.parent}/test.tcl", "w") as f:
    #             f.write("#!/usr/bin/env expect\n")
    #             f.write("set timeout -1\n")
    #             f.write(f"spawn sh -c {cmd}\n")
    #             f.write("expect {\n")
    #             f.write(" -re {.*\\[N/y.*}       { send \"N\\r\"; exp_continue }\n")
    #             f.write(" -re {.*\\[Y/n.*}       { send \"N\\r\"; exp_continue }\n")
    #             f.write(" -re {.*choice\\[.*\\].*}   { send \"\\r\"; exp_continue }\n")
    #             f.write(" eof\n")
    #             f.write("}\n")
    #             f.write("set ret [wait]\n")
    #             f.write("set retcode [lindex $ret 3]\n")
    #             f.write("exit $retcode\n")
    #         os.system(f"chmod +x {self.checker_dir.parent.parent}/test.tcl")
    #         res = os.system(f"{self.checker_dir.parent.parent}/test.tcl")
    #         # res = os.system(cmd)
    #         logger.info(f"Running command: {cmd} in {target_repo}")
    #         if res != 0:
    #             logger.error(f"Run failed on vulnerability {self.vul_type} at commit {target_commit_id}.")
    #             logger.error(f"Command failed with return code {res}.")
    #         # os.system("git checkout -f master")
    #         os.chdir(current_dir)
    #         # break
    #     pass

    def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file: Path) -> bool:
        if self.vul_type == "":
            self.vul_type = vulnerability_type
            logger.info(f"Set vulnerability type to {self.vul_type} for Knighter.")

        logger.info(f"Running KNighter on {target_repo} at commit {target_commit_id} for vulnerability type {vulnerability_type}")

        if not target_repo.exists():
            logger.error(f"Target repository {target_repo} does not exist.")
            return False
        
        if not report_file.exists():
            report_file.mkdir(parents=True, exist_ok=True)
        if target_repo.stem != "linux":
            logger.info(f"Checking out commit {target_commit_id} in {target_repo}")
            result = subprocess.run(["git", "checkout", "-f", target_commit_id], cwd=target_repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                logger.error(f"Failed to checkout commit {target_commit_id} in {target_repo}. Error: {result.stderr.decode()}")
                return False
        
        logger.info(f"Get build command for {target_repo.stem}.")
        res = self.prepare_build(target_repo, target_commit_id, vulnerability_type, report_file)
        
        if not res:
            logger.error(f"Failed to scan on {target_repo} at commit {target_commit_id}.")
        
        return res
