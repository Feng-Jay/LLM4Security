from pathlib import Path
from utils import logger, Config
from core import AbsTool, Knighter, Inferroi, RepoAudit, IRIS, LLMDFA


def run_tools(configs: Config) -> bool:
    vulnerabilities = configs.get_vulnerability_info()
    logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from configuration.")
    match configs.tool:
        case "repoaudit":
            repoaudit = RepoAudit.from_config(Path("../repoaudit.yaml"))
            for vulnerability in vulnerabilities:
                logger.info(f"Running RepoAudit for vulnerability: {configs.vulnerability}")
                target_repo = configs.projects_dir / vulnerability['repo_name']
                target_commit_id = vulnerability['commit_id']
                dir_name = f"{vulnerability['repo_name']}-{target_commit_id[:-1]}-{configs.vulnerability}"
                print(repr(configs.results_dir / dir_name))
                localization = vulnerability['localization']
                # if configs.vulnerability == "CWE-401":
                repoaudit.set_localization(vulnerability["localization"])
                repoaudit.set_src_localization(vulnerability["src_localization"])
                repoaudit.set_sink_localization(vulnerability["sink_localization"])
                # else:
                #     repoaudit.set_localization(localization.split("/")[0] + "/" + localization.split("/")[1])
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
                dir_name = f"{vulnerability['repo_name']}-{target_commit_id[:-1]}-{configs.vulnerability}"
                print(repr(configs.results_dir / dir_name))
                knighter.run_on_target(target_repo.resolve(), target_commit_id, 
                                    configs.vulnerability, 
                                    (configs.results_dir / dir_name).resolve())
                break
        case "iris":
            vulnerabilities = configs.get_vulnerability_info()
            logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from configuration.")
            iris = IRIS.from_config(Path("../iris.yaml"))
            logger.info(f"get {len(vulnerabilities)} bugs")
            for vulnerability in vulnerabilities:
                logger.info(f"Running IRIS for vulnerability: {configs.vulnerability} on {vulnerability}")
                iris.run_on_target(target_repo=vulnerability, target_commit_id="", vulnerability_type=configs.vulnerability, report_file="")
                logger.info(f"Completed IRIS for vulnerability: {configs.vulnerability} on {vulnerability}")
                # break
            pass
        case "inferroi":
            inferroi = Inferroi.from_config(Path("../inferroi.yaml"))
            for vulnerability in vulnerabilities:
                logger.info(f"Running INFERROI for vulnerability: {configs.vulnerability}")
                target_repo = configs.projects_dir / (vulnerability['repo_name'].split("/")[1] + "_" + vulnerability['commit_id'][:-1])
                target_commit_id = vulnerability['commit_id']
                localization = vulnerability['localization']
                inferroi.set_localization(localization)
                dir_name = f"{vulnerability['repo_name']}-{target_commit_id[:-1]}-{configs.vulnerability}"
                print(repr(configs.results_dir / dir_name))
                inferroi.run_on_target(target_repo.resolve(), target_commit_id, 
                                    configs.vulnerability, 
                                    (configs.results_dir / dir_name).resolve())
                # break
            pass
        
        case "llmdfa":
            llmdfa = LLMDFA.from_config(Path("../llmdfa.yaml"))
            for vulnerability in vulnerabilities:
                # print(configs.vulnerability_fl_info)
                # break
                logger.info(f"Running LLMDFA for vulnerability: {configs.vulnerability}")
                if vulnerability in configs.vulnerability_fl_info:
                    fl_files = configs.vulnerability_fl_info[vulnerability]
                    llmdfa.set_fl_files(fl_files)
                else:
                    llmdfa.set_fl_files([])
                llmdfa.run_on_target(target_repo=vulnerability, target_commit_id="", vulnerability_type=configs.vulnerability, report_file="")
                logger.info(f"Completed LLMDFA for vulnerability: {configs.vulnerability} on {vulnerability}")
                # break
        case _:
            logger.error(f"Unknown tool: {configs.tool}. Supported tools are: 'repoaudit', 'knighter', 'inferroi'.")
            return False
    pass


if __name__ == "__main__":
    configs = Config.from_yaml()
    run_tools(configs)
    pass