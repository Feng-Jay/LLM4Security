from pathlib import Path
from utils import logger, Config
from core import AbsTool, Knighter, Inferroi, RepoAudit, IRIS, LLMDFA, CodeQL, Semgrep, ClaudeCode, Codex, CSA, SpotBugs


def run_tools(configs: Config) -> bool:
    vulnerabilities = configs.get_vulnerability_info()
    # vulnerabilities = vulnerabilities[3:]
    logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from configuration.")
    match configs.tool:
        case "clang_static_analyzer":
            csa = CSA.from_config(Path("../clang_static_analyzer.yaml"))
            for vulnerability in vulnerabilities:
                logger.info(f"Running Clang Static Analyzer for vulnerability: {configs.vulnerability}")
                repo_name = vulnerability['repo_name']
                target_commit_id = vulnerability['commit_id']
                if len(vulnerability['repo_name'].split("/")) < 2:
                    target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[0])
                    dir_name = f"{vulnerability['repo_name']}-{target_commit_id[:-1]}-{configs.vulnerability}"
                else:
                    target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[1] + "_" + vulnerability['commit_id'][:-1])
                    dir_name = f"{vulnerability['repo_name'].split('/')[1]}-{target_commit_id[:-1]}-{configs.vulnerability}"
                csa.run_on_target(target_repo.resolve(), target_commit_id, 
                                    configs.vulnerability, 
                                    (configs.results_dir / dir_name).resolve())
        case "claudecode":
            claudecode = ClaudeCode.from_config(Path("../claudecode.yaml"))
            result_file = Path("../results/claudecode_in_house_final_without_localization/check_table.md")
            lines = result_file.read_text().splitlines()
            for vulnerability in vulnerabilities:
                logger.info(f"Running Claude Code for vulnerability: {configs.vulnerability}")
                if isinstance(vulnerability, dict):
                    repo_name = vulnerability['repo_name']
                    target_commit_id = vulnerability['commit_id']
                    is_pass = False
                    for line in lines:
                        if target_commit_id[:-1] in line and "- [x]" in line:
                            logger.info(f"Skip {repo_name} at commit {target_commit_id} because it is marked as fixed in the result file.")
                            is_pass = True
                            break
                    if is_pass:
                        continue
                    if len(vulnerability['repo_name'].split("/")) < 2:
                        target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[0])
                        dir_name = f"{vulnerability['repo_name']}-{target_commit_id[:-1]}-{configs.vulnerability}"
                    else:
                        target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[1] + "_" + vulnerability['commit_id'][:-1])
                        dir_name = f"{vulnerability['repo_name'].split('/')[1]}-{target_commit_id[:-1]}-{configs.vulnerability}"

                    if "localization" in vulnerability:
                        claudecode.set_localization(vulnerability["localization"])
                    if "src_localization" in vulnerability:
                        if "src_api" in vulnerability and vulnerability["src_api"] != "":
                            claudecode.set_src_localization(vulnerability["src_localization"] + " with call of source API: " + vulnerability["src_api"])
                        else:
                            claudecode.set_src_localization(vulnerability["src_localization"])
                    if "sink_localization" in vulnerability:
                        if "sink_api" in vulnerability and vulnerability["sink_api"] != "":
                            claudecode.set_sink_localization(vulnerability["sink_localization"] + " with call of sink API: " + vulnerability["sink_api"])
                        else:
                            claudecode.set_sink_localization(vulnerability["sink_localization"])
                else: 
                    repo_name = vulnerability
                    target_commit_id = ""
                    dir_name = f"{repo_name}-{configs.vulnerability}"
                    fl_info = configs.vulnerability_fl_info.get(vulnerability, [])
                    target_repo = configs.projects_dir / repo_name
                    print(f"fl info for {vulnerability}: {fl_info}")
                    claudecode.set_localization("; ".join(fl_info))
                claudecode.run_on_target(target_repo.resolve(), target_commit_id, 
                                        configs.vulnerability, 
                                        (configs.results_dir / dir_name).resolve())
        case "codex":
            codex= Codex.from_config(Path("../codex.yaml"))
            result_file = Path("../results/codex_in_house_without_localization/check_table.md")
            lines = result_file.read_text().splitlines()
            for vulnerability in vulnerabilities:
                logger.info(f"Running Codex for vulnerability: {configs.vulnerability}")
                if isinstance(vulnerability, dict):
                    repo_name = vulnerability['repo_name']
                    # target_repo = configs.projects_dir / repo_name
                    target_commit_id = vulnerability['commit_id']
                    if "c6ad94fbb7b280f39c2fbbdc1c140e51b1b466e9" not in target_commit_id:
                        logger.info(f"Skip {repo_name} at commit {target_commit_id} because it is not the target commit for the vulnerability.")
                        continue
                    is_pass = False
                    for line in lines:
                        if target_commit_id[:-1] in line and "- [x]" in line:
                            logger.info(f"Skip {repo_name} at commit {target_commit_id} because it is marked as fixed in the result file.")
                            is_pass = True
                            break
                    if is_pass:
                        continue
                    if len(vulnerability['repo_name'].split("/")) < 2:
                        target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[0])
                        dir_name = f"{vulnerability['repo_name']}-{target_commit_id[:-1]}-{configs.vulnerability}"
                    else:
                        target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[1] + "_" + vulnerability['commit_id'][:-1])
                        dir_name = f"{vulnerability['repo_name'].split('/')[1]}-{target_commit_id[:-1]}-{configs.vulnerability}"

                    if "localization" in vulnerability:
                        codex.set_localization(vulnerability["localization"])
                    if "src_localization" in vulnerability:
                        if "src_api" in vulnerability and vulnerability["src_api"] != "":
                            codex.set_src_localization(vulnerability["src_localization"] + " with call of source API: " + vulnerability["src_api"])
                        else:
                            codex.set_src_localization(vulnerability["src_localization"])
                    if "sink_localization" in vulnerability:
                        if "sink_api" in vulnerability and vulnerability["sink_api"] != "":
                            codex.set_sink_localization(vulnerability["sink_localization"] + " with call of sink API: " + vulnerability["sink_api"])
                        else:
                            codex.set_sink_localization(vulnerability["sink_localization"])
                else:
                    repo_name = vulnerability
                    target_commit_id = ""
                    dir_name = f"{repo_name}-{configs.vulnerability}"
                    fl_info = configs.vulnerability_fl_info.get(vulnerability, [])
                    target_repo = configs.projects_dir / repo_name
                    print(f"fl info for {vulnerability}: {fl_info}")
                    codex.set_localization("; ".join(fl_info))
                
                codex.run_on_target(target_repo.resolve(), target_commit_id, 
                                        configs.vulnerability, 
                                        (configs.results_dir / dir_name).resolve())
                # break
        case "repoaudit":
            repoaudit = RepoAudit.from_config(Path("../repoaudit.yaml"))
            for vulnerability in vulnerabilities:
                logger.info(f"Running RepoAudit for vulnerability: {configs.vulnerability}")
                target_repo = configs.projects_dir / vulnerability['repo_name']
                target_commit_id = vulnerability['commit_id']
                dir_name = f"{vulnerability['repo_name']}-{target_commit_id[:-1]}-{configs.vulnerability}"
                localization = vulnerability['localization']
                if "localization" in vulnerability:
                    repoaudit.set_localization(vulnerability["localization"])
                if "src_localization" in vulnerability and "sink_localization" in vulnerability:
                    repoaudit.set_src_localization(vulnerability["src_localization"])
                    repoaudit.set_sink_localization(vulnerability["sink_localization"])
                # if "src_api" in vulnerability and "sink_api" in vulnerability:
                #     repoaudit.set_src_api(vulnerability["src_api"])
                #     repoaudit.set_sink_api(vulnerability["sink_api"])
                # else:
                #     repoaudit.set_localization(localization.split("/")[0] + "/" + localization.split("/")[1])
                print(target_repo.resolve())
                repoaudit.run_on_target(target_repo.resolve(), target_commit_id, 
                                        configs.vulnerability, 
                                        (configs.results_dir / dir_name).resolve())
                # break
            pass
        case "knighter":
            knighter = Knighter.from_config(Path("../knighter.yaml"))
            for vulnerability in vulnerabilities:
                logger.info(f"Running Knighter for vulnerability: {configs.vulnerability}")
                target_repo = configs.projects_dir / vulnerability['repo_name']
                target_commit_id = vulnerability['commit_id']
                localization = vulnerability['localization']
                knighter.set_localization(localization)
                dir_name = f"{vulnerability['repo_name']}-{target_commit_id[:-1]}-{configs.vulnerability}"
                dir_name = f"{dir_name}-{localization}"
                print(repr(configs.results_dir / dir_name))
                knighter.run_on_target(target_repo.resolve(), target_commit_id, 
                                    configs.vulnerability, 
                                    (configs.results_dir / dir_name).resolve())
                # break
        case "iris":
            # vulnerabilities = configs.get_vulnerability_info()
            logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from configuration.")
            iris = IRIS.from_config(Path("../iris.yaml"))
            logger.info(f"get {len(vulnerabilities)} bugs")
            for vulnerability in vulnerabilities:
                if isinstance(vulnerability, dict):
                    repo_name = vulnerability['repo_name']
                else:
                    repo_name = vulnerability
                # if "apache__camel" not in repo_name:
                #     continue
                logger.info(f"Running IRIS for vulnerability: {configs.vulnerability} on {vulnerability}")
                iris.run_on_target(target_repo=repo_name, target_commit_id="", vulnerability_type=configs.vulnerability, report_file="")
                logger.info(f"Completed IRIS for vulnerability: {configs.vulnerability} on {vulnerability}")
                # break
            pass
        case "inferroi":
            inferroi = Inferroi.from_config(Path("../inferroi.yaml"))
            for vulnerability in vulnerabilities:
                logger.info(f"Running INFERROI for vulnerability: {configs.vulnerability}")
                if len(vulnerability["repo_name"].split("/")) < 2:
                    target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[0])
                else:
                    target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[1] + "_" + vulnerability['commit_id'][:-1])
                target_commit_id = vulnerability['commit_id']
                if "localization" in vulnerability:
                    localization = vulnerability['localization']
                    logger.info(f"Set localization to {localization} for INFERROI.")
                    inferroi.set_localization(localization)
                dir_name = f"{vulnerability['repo_name']}-{target_commit_id[:-1]}-{configs.vulnerability}"
                inferroi.run_on_target(target_repo.resolve(), target_commit_id, 
                                    configs.vulnerability, 
                                    (configs.results_dir / dir_name).resolve())
                logger.info(f"Completed INFERROI for vulnerability: {configs.vulnerability} on {vulnerability}")
                # break
            pass

        case "llmdfa":
            llmdfa = LLMDFA.from_config(Path("../llmdfa.yaml"))
            for vulnerability in vulnerabilities:
                logger.info(f"Running LLMDFA for vulnerability: {configs.vulnerability}")
                fl_info = configs.vulnerability_fl_info.get(vulnerability, [])
                if len(fl_info) != 0:
                    fl_files = configs.vulnerability_fl_info[vulnerability]
                    print(f"fl files for {vulnerability}: {fl_files}")
                    llmdfa.set_fl_files(fl_files)
                else:
                    llmdfa.set_fl_files([])
                if isinstance(vulnerability, dict):
                    target_commit_id = vulnerability.get('commit_id', "")
                    projects_dir = Path(configs.projects_dir)
                    target_repo = projects_dir / vulnerability['repo_name']
                    # continue
                llmdfa.run_on_target(target_repo=vulnerability, target_commit_id="", vulnerability_type=configs.vulnerability, report_file="")
                logger.info(f"Completed LLMDFA for vulnerability: {configs.vulnerability} on {vulnerability}")
                # llmdfa.run_on_target(target_repo=target_repo, target_commit_id=target_commit_id, vulnerability_type=configs.vulnerability, report_file="")
                # logger.info(f"Completed LLMDFA for vulnerability: {configs.vulnerability} on {vulnerability}")
                # break
        case "codeql":
            codeql = CodeQL.from_config(Path("../codeql.yaml"))
            for vulnerability in vulnerabilities:
                logger.info(f"Running CodeQL for vulnerability: {configs.vulnerability}")
                if configs.vulnerability == "jleaks":
                    target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[1] + "_" + vulnerability['commit_id'][:-1])
                    target_commit_id = ""
                    repo_name = vulnerability['repo_name'].split("/")[1]
                    dir_name = f"{repo_name}-{target_commit_id[:-1]}-{configs.vulnerability}"
                elif isinstance(vulnerability, dict):
                    if vulnerability["repo_name"] == "linux":
                        # target_repo = configs.projects_dir / "linux_knighter"
                        target_repo = configs.projects_dir / "linux"
                    else:
                        target_repo = configs.projects_dir / vulnerability['repo_name']
                    target_commit_id = vulnerability['commit_id']
                    repo_name = vulnerability['repo_name']
                    if vulnerability.get("localization", "") != "":
                        repo_name = repo_name + "_" + vulnerability['localization'].replace("/", "_")
                    dir_name = f"{repo_name}-{target_commit_id[:-1]}-{configs.vulnerability}"
                    if "localization" in vulnerability:
                        localization = vulnerability['localization']
                        # dir_name = f"{dir_name}-{localization}"
                        if localization.startswith("drivers"):
                            if len(localization.split("/")) > 1:
                                localization = "drivers/" + localization.split("/")[1]
                        else:
                            localization = localization.split("/")[0]
                        target_repo = target_repo / localization
                        src_api = vulnerability.get("src_api", "")
                        sink_api = vulnerability.get("sink_api", "")
                        template = f"""extensions:
  - addsTo:
      pack: codeql/cpp-all
      extensible: allocationFunctionModel
    data:
      - ["", "", false, "{src_api}", "0", "", "", true]

  - addsTo:
      pack: codeql/cpp-all
      extensible: deallocationFunctionModel
    data:
      - ["", "", false, "{sink_api}", "0"]
"""                     
                    with open("/data/lifengjie/LLM4Security/resources/codeql-packs/custom-cpp-modules/models/memory.yml", "w") as f:
                        f.write(template)
                    # input("Press Enter to continue...")
                else:
                    target_repo = configs.projects_dir / vulnerability
                    target_commit_id = ""
                    repo_name = vulnerability
                    dir_name = f"{repo_name}"
                codeql.run_on_target(target_repo=target_repo.resolve(), target_commit_id=target_commit_id, 
                                     vulnerability_type=configs.vulnerability, 
                                     report_file=(configs.results_dir / (dir_name)).resolve())
                logger.info(f"Completed CodeQL for vulnerability: {configs.vulnerability} on {vulnerability}")
                # break
            pass

        case "spotbugs":
            spotbugs = SpotBugs.from_config(Path("../spotbugs.yaml"))
            for vulnerability in vulnerabilities:
                logger.info(f"Running SpotBugs for vulnerability: {configs.vulnerability}")
                if isinstance(vulnerability, dict):
                    repo_name = vulnerability['repo_name']
                    target_commit_id = vulnerability['commit_id']
                    if len(vulnerability['repo_name'].split("/")) < 2:
                        target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[0])
                        dir_name = f"{vulnerability['repo_name']}-{target_commit_id[:-1]}-{configs.vulnerability}"
                    else:
                        target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[1] + "_" + vulnerability['commit_id'][:-1])
                        dir_name = f"{vulnerability['repo_name'].split('/')[1]}-{target_commit_id[:-1]}-{configs.vulnerability}"
                else: 
                    repo_name = vulnerability
                    target_commit_id = ""
                    dir_name = f"{repo_name}-{configs.vulnerability}"
                    fl_info = configs.vulnerability_fl_info.get(vulnerability, [])
                    target_repo = configs.projects_dir / repo_name
                spotbugs.run_on_target(target_repo.resolve(), target_commit_id, 
                                        configs.vulnerability, 
                                        (configs.results_dir / dir_name).resolve())


        case "semgrep":
            # TODO: Implement Semgrep integration
            semgrep = Semgrep.from_config(Path("../semgrep.yaml"))
            for vulnerability in vulnerabilities:
                logger.info(f"Running Semgrep for vulnerability: {configs.vulnerability}")
                if isinstance(vulnerability, dict):
                    target_repo = configs.projects_dir / vulnerability['repo_name']
                    target_commit_id = vulnerability['commit_id']
                    repo_name = vulnerability['repo_name']
                    if "localization" in vulnerability:
                        localization = vulnerability['localization']
                        repo_name = repo_name + "_" + vulnerability['localization'].replace("/", "_")
                        # dir_name = f"{dir_name}-{localization}"
                        if localization.startswith("drivers"):
                            if len(localization.split("/")) > 1:
                                localization = "drivers/" + localization.split("/")[1]
                        else:
                            localization = localization.split("/")[0]
                        # target_repo = target_repo / localization

                    dir_name = f"{repo_name}-{target_commit_id[:-1]}-{configs.vulnerability}"
                else:
                    target_repo = configs.projects_dir / vulnerability
                    target_commit_id = ""
                    repo_name = vulnerability
                    dir_name = f"{repo_name}"
                print(repr(configs.results_dir / dir_name))
                semgrep.run_on_target(target_repo=target_repo.resolve(), target_commit_id=target_commit_id, 
                                     vulnerability_type=configs.vulnerability, 
                                     report_file=(configs.results_dir / (dir_name + ".json")).resolve())
                logger.info(f"Completed Semgrep for vulnerability: {configs.vulnerability} on {vulnerability}")
                # break
            pass
        case _:
            logger.error(f"Unknown tool: {configs.tool}. Supported tools are: 'repoaudit', 'knighter', 'inferroi'.")
            return False
    pass


if __name__ == "__main__":
    configs = Config.from_yaml()
    run_tools(configs)
    pass