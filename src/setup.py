import json
import os
vulnerabilities_info_c = "../data/in_house/c/vulnerabilities.json"
with open(vulnerabilities_info_c, 'r') as file:
    vulnerabilities_info = json.load(file)


def download_projects():
    if not os.path.exists("../data/projects"):
        os.makedirs("../data/projects")
    
    repo_links = set([(item["repo_name"], item["repo_link"]) for k, v in vulnerabilities_info.items() for item in v])
    
    for repo_link in repo_links:
        print(f"Cloning repository: {repo_link}")
        
        if os.path.exists(f"../data/projects/{repo_link[0]}"):
            print(f"Repository {repo_link[0]} already exists, skipping.")
            continue

        os.system(f"git clone {repo_link[1]} ../data/projects/{repo_link[0]}")
    pass


if __name__ == "__main__":
    download_projects()
    pass