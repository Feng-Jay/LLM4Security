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
    order: int = 0

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

        tool_name = configs["tool"]
        if tool_name not in configs["tools"]:
            logger.error(f"Tool {tool_name} not found in configuration.")
            raise ValueError(f"Tool {tool_name} not found in configuration.")
        tool_configs = configs["tools"][tool_name]

        # prepare results dir and file
        results_dir = Path(tool_configs["results"])
        if not results_dir.exists():
            results_dir.mkdir(parents=True)
        results_file = results_dir / f"{tool_name}-{tool_configs['vulnerability']}-{time_stamp}.txt"

        # load vulnerability info
        if not Path(tool_configs["vulnerability_info_file"]).exists():
            logger.error(f"Vulnerability info file {tool_configs['vulnerability_info_file']} does not exist.")
            raise FileNotFoundError(f"Vulnerability info file {tool_configs['vulnerability_info_file']} does not exist.")

        # for c vuls
        if tool_configs["vulnerability_info_file"].endswith(".json"):
            vulnerability_info = json.load(Path(tool_configs["vulnerability_info_file"]).open("r"))
        # for java vuls
        elif tool_configs["vulnerability_info_file"].endswith(".csv"):
            df = pd.read_csv(tool_configs["vulnerability_info_file"])
            vulnerability_info = df.groupby("cwe_id")["project_slug"].apply(lambda x: list(set(x))).to_dict()
            for vul in vulnerability_info:
                vulnerability_info[vul] = sorted(vulnerability_info[vul])
            print(vulnerability_info)
        
        # load fl files if provided
        vulnerability_fl_info = {}
        if "vulnerability_fl_file" in configs:
            if Path(tool_configs["vulnerability_fl_file"]).exists():
                df = pd.read_csv(tool_configs["vulnerability_fl_file"])
                vulnerability_fl_info = df.groupby("project_slug")["file"].apply(lambda x: list(set(x))).to_dict()

        logger.info("Configuration loaded.")

        return cls(
            projects_dir=Path(tool_configs["projects_dir"]),
            vulnerability=tool_configs["vulnerability"],
            vulnerability_info=vulnerability_info,
            vulnerability_fl_info=vulnerability_fl_info,
            tool=configs["tool"],
            log_dir=log_dir,
            log_file=log_file,
            results_dir=results_dir,
            results_file=results_file,
            order=configs.get("order", 0),
        )
    
    def get_vulnerability_info(self) -> List[Dict]:
        """Get vulnerability information from the loaded configuration."""
        return self.vulnerability_info.get(self.vulnerability, [])
    
