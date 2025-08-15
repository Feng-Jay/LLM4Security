import time
import json
import datetime
import subprocess
import pandas as pd
from pathlib import Path
from random import sample
from dateutil import parser
from concurrent.futures import ThreadPoolExecutor, as_completed


def extract_jleaks_data():
    # Read the CSV file containing JLeaks data
    df = pd.read_csv("./in_house/java/JLeaks.csv")
    ret_list = []
    commit_set = set()
    for index, row in df.iterrows():
        repo_name = row['projects']
        commit_id = row['commit url'].split('/')[-1] + "^"
        if commit_id in commit_set:
            for item in ret_list:
                if item["commit_id"] == commit_id:
                    item["localization"] += "&&" + row["defect method"]
            continue
        commit_set.add(commit_id)
        repo_link = "https://github.com/" + repo_name
        localization = row["defect method"]
        buggy_time = row["UTC of buggy commit"]
        dt = parser.isoparse(buggy_time)
        if dt.year < 2022:
            continue
        ret_list.append({
            "repo_name": repo_name,
            "repo_link": repo_link,
            "commit_id": commit_id,
            "localization": localization,
            "time": dt.strftime("%Y-%m-%d"),
        })
    
    print(len(ret_list), "JLeaks data extracted")
    sampled_list = sample(ret_list, 10)
    out_dict = {"jleaks": sampled_list}
    # print(len(sampled_list), "JLeaks data sampled")
    with open("./in_house/java/jleaks_vulnerabilities2.json", "w") as f:
        f.write(json.dumps(out_dict, indent=4))


def clone_project(url: str, dst_path: Path):
    try:
        if dst_path.exists():
            return ""
        print(f"git clone {url}.git {dst_path}")
        subprocess.run(["git", "clone", url + ".git", str(dst_path)],
                        check=True, stderr=subprocess.PIPE)
        return f"[OK] Cloned {url}"
    except subprocess.CalledProcessError as e:
        return f"[ERROR] {url}: {e.stderr.decode('utf-8').strip()}"
        return ""


def download_jleaks_data():
    projects_path = Path("./in_house/java/projects")
    if not projects_path.exists():
        projects_path.mkdir(parents=True, exist_ok=True)
    json_dict = json.load(open("./in_house/java/jleaks_vulnerabilities.json", "r"))["jleaks"]

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_repo = {
            executor.submit(clone_project, repo["repo_link"],
                            projects_path / (repo["repo_name"].split("/")[1] + "_" + repo["commit_id"][:-1])): repo
            for repo in json_dict
        }
        for future in as_completed(future_to_repo):
            print(future.result())
    pass


if __name__ == "__main__":
    # extract_jleaks_data()
    download_jleaks_data()
    