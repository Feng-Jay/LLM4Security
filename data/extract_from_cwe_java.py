import json
import pandas as pd

df_info = pd.read_csv("./in_house/java/project_info.csv")
df_fix_info = pd.read_csv("./in_house/java/fix_info.csv")


fix_json_dict = {}
for index, row in df_fix_info.iterrows():
    if row['project_slug'] not in fix_json_dict.keys():
        fix_json_dict[row['project_slug']] = [row['file']]
    else:
        fix_json_dict[row['project_slug']].append(row['file'])
# print(fix_json_dict)
output_json_dict = {}
projects_counter = {}
for index, row in df_info.iterrows():
    if row['cwe_id'] not in output_json_dict.keys():
        output_json_dict[row['cwe_id']] = []
    
    output_json_dict[row['cwe_id']].append({
        "repo_name": row['project_slug'],
        "repo_link": row['github_url'],
        "commit_id": row['buggy_commit_id'],
        "time": "yyyy-mm-dd",
        "localization": ";".join(fix_json_dict[row['project_slug']]) if row['project_slug'] in fix_json_dict.keys() else "",
        })
    if row["cwe_id"] != "CWE-079":
        continue
    project_name = row['project_slug'].split("__")[1].split("_")[0]
    if project_name not in projects_counter.keys():
        projects_counter[project_name] = 1
    else:
        projects_counter[project_name] += 1
print(sorted(projects_counter.items(), key=lambda x: x[1], reverse=True)[:3])
# with open("./in_house/java/vulnerabilities.json", "w") as f:
#     f.write(json.dumps(output_json_dict, indent=4))

