from pathlib import Path
from abc import ABC, abstractmethod
from typing import Optional, Self
from pydantic import BaseModel, Field

class AbsTool(ABC):

    @abstractmethod
    def run_on_target(self, target_repo: Path, target_commit_id: str) -> bool:
        """
        Run the tool on the specified target repository and commit ID.
        Args:
            target_repo (Path): Path to the target repository.
            target_commit_id (str): Commit ID to run the tool against.
        Returns:
            bool: True if the tool ran successfully, False otherwise.
        """
        raise NotImplementedError("Subclasses must implement this method.")
    
