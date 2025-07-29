from pathlib import Path
from utils import logger, Config
from core import AbsTool, Knighter


def run_tools(configs: Config) -> bool:
    vulnerabilities = configs.get_vulnerability_info()
    logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities from configuration.")
    if configs.tool == "Knighter":
        knighter = Knighter.from_config(Path("../knighter.yaml"))
        for vulnerability in vulnerabilities:
            logger.info(f"Running Knighter for vulnerability: {vulnerability}")
            target_repo = configs.projects_dir / vulnerability['repo_name']
            target_commit_id = vulnerability['commit_id']
            knighter.run_on_target(target_repo.resolve(), target_commit_id, configs.vulnerability, configs.results_file.resolve())
            break
    pass


if __name__ == "__main__":
    configs = Config.from_yaml()
    run_tools(configs)
    pass