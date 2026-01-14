import json
import os


projects_json = "./real_world/java_projects.json"
projects_dict = json.load(open(projects_json, "r"))

for k, v in projects_dict.items():
    for item in v:
        print(f"Cloning {item['repo_name']}...")
        os.system(f"git clone {item['repo_link']} ./projects/{item['repo_name']}")