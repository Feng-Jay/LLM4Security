import os
import yaml
import subprocess
from pathlib import Path
from .abs_tool import AbsTool
from pydantic import BaseModel, Field, field_validator
from typing import Self
from utils import logger, Config


class CSA(BaseModel, AbsTool):

    llvm_dir: Path = Field(
        default = Path("/data/lifengjie/sec/data/projects/llvm-project-llvmorg-18.1.8/"),
        description = "Path to the LLVM project directory."
    )

    patches_dir: Path = Field(
        default = Path("/data/lifengjie/LLM4Security/resources/linux_patches/"),
        description = "Path to the directory containing patches for the Linux kernel."
    )

    @classmethod
    def from_config(cls, config_path: Path) -> Self:
        with open(config_path, "r") as f:
            config_data = yaml.safe_load(f)
        llvm_dir = Path(config_data.get("llvm_dir"))
        patches_dir = Path(config_data.get("patches_dir"))
        return cls(llvm_dir=llvm_dir, patches_dir=patches_dir)

    def get_scan_rules(self, cwe_id: str) -> str:
        enable_rules = []
        disable_rules = []
        match cwe_id:
            case "CWE-401":
                disable_rules.extend(["core", "deadcode", "nullability", "optin", "security", "osx"])
                enable_rules.extend(["unix.Malloc", "unix.MismatchedDeallocator", "cplusplus.NewDeleteLeaks"])
                pass
            case "CWE-416":
                disable_rules.extend(["core", "deadcode", "nullability", "optin", "security", "osx"])
                enable_rules.extend(["unix.Malloc", "cplusplus.NewDelete"])
                pass
            case "CWE-476":
                disable_rules.extend(["deadcode", "optin", "security", "osx"])
                enable_rules.extend(["core.NullDereference", "core.NonNullParamChecker", "core.CallAndMessage", "cplusplus.StringChecker", "nullability.NullReturnedFromNonnull", "unix.cstring.NullArg", "unix.StdCLibraryFunctions"])
                pass
        ret_str = " ".join([f"-enable-checker {rule}" for rule in enable_rules] + [f"-disable-checker {rule}" for rule in disable_rules])
        return ret_str

    def prepare_build(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file:Path) -> bool:
        repo_name = target_repo.stem
        checkers = self.get_scan_rules(vulnerability_type)
        current_dir = os.getcwd()
        os.chdir(target_repo)
        match repo_name:
            case "linux":
                cmd ="{" + f"env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build " \
                    f"--use-cc={self.llvm_dir}/build/bin/clang {checkers} -maxloop 4 " \
                    f"-o {report_file / target_commit_id} make LLVM=1 ARCH=x86 LLVM_IAS=1 -j32 KCFLAGS=\"-Wno-error -Wno-strict-prototypes -Qunused-arguments\" HOSTCFLAGS=\"-Wno-error\" HOSTCPPFLAGS=\"-Wno-error\" 2>&1 | tee ../CSA_build_{target_commit_id}.log" + "}"
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
                    
                # os.system(f"make clean && cd src && autoconf && CC=clang LDFLAGS=\"-ltinfo\"  ./configure && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang {checkers} -maxloop 4 -o {report_file / target_commit_id} make -j32 2>&1 | tee ../CSA_build_vim_{target_commit_id}.log")
                os.system(f"make clean && cd src && CC=clang LDFLAGS=\"-ltinfo\"  ./configure && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang {checkers} -maxloop 4 -o {report_file / target_commit_id} make -j32 2>&1 | tee ../CSA_build_vim_{target_commit_id}.log")
            case "gpac":
                os.system("make clean")
                os.system(f"CC=clang ./configure --disable-werror && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang {checkers} -maxloop 4 -o {report_file / target_commit_id} make -j32 2>&1 | tee ../CSA_build_gpac_{target_commit_id}.log")
            case "ImageMagick":
                os.system("make clean")
                os.system(f"CC=clang CXX=clang++ ./configure --disable-werror && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang {checkers} -maxloop 4 -o {report_file / target_commit_id} make -j32 2>&1 | tee ../CSA_build_ImageMagick_{target_commit_id}.log")
            case "bitlbee":
                os.system("make clean")
                os.system(f"CC=clang CXX=clang++ ./configure --disable-werror && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang {checkers} -maxloop 4 -o {report_file / target_commit_id} make -j32 2>&1 | tee ../CSA_build_bitlbee_{target_commit_id}.log")
            case "radare2":
                os.system("make clean")
                os.system(f"CC=clang CXX=clang++ ./configure && env PATH={self.llvm_dir}/build/bin:$PATH {self.llvm_dir}/build/bin/scan-build --use-cc={self.llvm_dir}/build/bin/clang {checkers} -maxloop 4 -o {report_file / target_commit_id} make all -j32  CS_COMMIT_ARCHIVE=1 2>&1 | tee ../CSA_build_radare2_{target_commit_id}.log ")
        os.chdir(current_dir)
        return True
    
    def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file: Path) -> bool:
        logger.info(f"Running Clang Static Analyzer on {target_repo} at commit {target_commit_id} for vulnerability type {vulnerability_type}")

        if not target_repo.exists():
            logger.error(f"Target repository {target_repo} does not exist.")
            return False
        
        if not report_file.exists():
            report_file.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Checking out commit {target_commit_id} in {target_repo}")
        if target_repo.stem != "linux":
            result = subprocess.run(["git", "checkout", "-f", target_commit_id], cwd=target_repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                logger.error(f"Failed to checkout commit {target_commit_id} in {target_repo}. Error: {result.stderr.decode()}")
                return False
        
        logger.info(f"Get build command for {target_repo.stem}.")
        res = self.prepare_build(target_repo, target_commit_id, vulnerability_type, report_file)
        
        if not res:
            logger.error(f"Failed to scan on {target_repo} at commit {target_commit_id}.")
        
        return res