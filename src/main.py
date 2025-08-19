from pathlib import Path
from utils import logger, Config
from core import AbsTool, Knighter, Inferroi, RepoAudit


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
                if configs.vulnerability == "CWE-401":
                    repoaudit.set_localization(vulnerability["localization"])
                else:
                    repoaudit.set_localization("src")
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
        
        case _:
            logger.error(f"Unknown tool: {configs.tool}. Supported tools are: 'repoaudit', 'knighter', 'inferroi'.")
            return False
    pass


if __name__ == "__main__":
    configs = Config.from_yaml()
    run_tools(configs)
    pass