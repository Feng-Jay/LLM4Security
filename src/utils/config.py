import time
import json
import yaml
import loguru
import pandas as pd
from typing import Self, List, Dict
from pathlib import Path
from pydantic import BaseModel, Field

logger = loguru.logger


class Config(BaseModel):
    projects_dir: Path
    vulnerability: str
    vulnerability_info: Dict[str, List]
    vulnerability_fl_info: Dict[str, List]
    tool: str
    log_dir: Path
    log_file: Path
    results_dir: Path
    results_file: Path

    @classmethod
    def from_yaml(cls, config_file: Path = Path("../config.yaml")) -> Self:
        configs = yaml.safe_load(config_file.read_text())
        
        # set the logger
        time_stamp = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
        global logger
        log_dir = Path(configs["log"])
        if not log_dir.exists():
            log_dir.mkdir(parents=True)
        log_file = log_dir / f"{configs['tool']}-{configs['vulnerability']}-{time_stamp}.log"
        logger.add(
            log_file,
            rotation="1 day",
            retention="7 days",
            level="DEBUG",
        )
        
        # prepare results dir and file
        results_dir = Path(configs["results"])
        if not results_dir.exists():
            results_dir.mkdir(parents=True)
        results_file = results_dir / f"{configs['tool']}-{configs['vulnerability']}-{time_stamp}.txt"

        # load vulnerability info
        if not Path(configs["vulnerability_info_file"]).exists():
            logger.error(f"Vulnerability info file {configs['vulnerability_info_file']} does not exist.")
            raise FileNotFoundError(f"Vulnerability info file {configs['vulnerability_info_file']} does not exist.")

        # for c vuls
        if configs["vulnerability_info_file"].endswith(".json"):
            vulnerability_info = json.load(Path(configs["vulnerability_info_file"]).open("r"))
        # for java vuls
        elif configs["vulnerability_info_file"].endswith(".csv"):
            df = pd.read_csv(configs["vulnerability_info_file"])
            vulnerability_info = df.groupby("cwe_id")["project_slug"].apply(lambda x: list(set(x))).to_dict()
            print(vulnerability_info)
        # load fl files if provided
        vulnerability_fl_info = {}
        if "vulnerability_fl_file" in configs:
            if Path(configs["vulnerability_fl_file"]).exists():
                df = pd.read_csv(configs["vulnerability_fl_file"])
                vulnerability_fl_info = df.groupby("project_slug")["file"].apply(lambda x: list(set(x))).to_dict()

        logger.info("Configuration loaded.")

        return cls(
            projects_dir=Path(configs["projects_dir"]),
            vulnerability=configs["vulnerability"],
            vulnerability_info=vulnerability_info,
            vulnerability_fl_info=vulnerability_fl_info,
            tool=configs["tool"],
            log_dir=log_dir,
            log_file=log_file,
            results_dir=results_dir,
            results_file=results_file
        )
    
    def get_vulnerability_info(self) -> List[Dict]:
        """Get vulnerability information from the loaded configuration."""
        return self.vulnerability_info.get(self.vulnerability, [])
    
