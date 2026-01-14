import json
import os
from pathlib import Path

def get_repos(json_file:Path):
    content_dict = json.load(open(json_file, "r"))
    ret = []
    for key in content_dict:
        for item in content_dict[key]:
            if "localization" in item and item["localization"] != "":
                ret.append(item["repo_name"] + "/" + item["localization"])
            else:
                ret.append(item["repo_name"])

    return ret

repo_names = get_repos("./real_world/c_projects.json")
repo_names.extend(
    get_repos("./real_world/java_projects.json"))


for item in repo_names:
    print(f"Processing {item}...")
    os.system(f"cloc /data/LLM4Security/data/projects/{item}")
