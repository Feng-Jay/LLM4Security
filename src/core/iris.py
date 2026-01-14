from .abs_tool import AbsTool
from utils import Config, logger
import subprocess
from pathlib import Path
from typing import Self
from yaml import safe_load
from pydantic import BaseModel, Field

class IRIS(AbsTool, BaseModel):
    iris_path: Path = Field(
        default=Path("./dependencies/iris/"),
        description="Path to the IRIS tool."
    )

    llm_model: str = Field(
        default="gpt-4",
        description="LLM model to use for IRIS."
    )

    vul_type: str = Field(
        default="",
        description="Type of vulnerability to audit."
    )

    @classmethod
    def from_config(cls, config_file: Path = Path("../iris.yaml")) -> Self:
        config = safe_load(config_file.read_text())
        iris_path = config.get("iris_path", "./dependencies/iris/src")
        if not Path(iris_path).exists():
            logger.error(f"IRIS path {iris_path} does not exist.")
            raise FileNotFoundError(f"IRIS path {iris_path} does not exist.")
        
        llm_model = config.get("llm_model", "gpt-4")
        
        vul_type = config.get("vul_type", "")

        return cls(
            iris_path=Path(iris_path),
            llm_model=llm_model,
            vul_type=vul_type
        )
    
    def run_on_target(self, target_repo: Path, target_commit_id: str, vulnerability_type: str, report_file: Path) -> bool:

        if self.vul_type == "":
            self.vul_type = vulnerability_type
            logger.info(f"Set vulnerability type to {self.vul_type} for IRIS.")

        cmd = f"conda run -n iris python3 src/neusym_vul.py --query {self.vul_type.lower()}wLLM --run-id expr --llm {self.llm_model} {target_repo}"
        if (self.iris_path / "output" / target_repo).exists():
            logger.info(f"IRIS output for {target_repo} already exists, skipping.")
            # return True
        subprocess.run(cmd, shell=True, cwd=self.iris_path)
        return True