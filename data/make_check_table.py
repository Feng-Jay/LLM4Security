import json
import pandas as pd
from pathlib import Path

# bug_info_json_file = Path("./in_house/c/reposvul_vulnerabilities.json")
# bug_info = json.loads(bug_info_json_file.read_text())
# project_name = "linux"

# out_list = []
# for vul_type in bug_info.keys():
#     if not vul_type.startswith("CWE-4"):
#         continue
#     for bug in bug_info[vul_type]:
#         out_list.append(
#             {
#                 "vul_type": vul_type,
#                 "vul_name": project_name + "-" + bug["commit_id"],
#                 "url": bug["html_url"],
#                 "RepoAudit": "False",
#                 "CodeQL": "False",
#                 "Semgrep": "False",
#                 "Knighter": "False",
#             }
#         )
# df = pd.DataFrame(out_list)
# df.to_excel(f"./in_house/c/{project_name}_check_table.xlsx", index=False)


# vul_info_csv = pd.read_csv("./in_house/java/project_info.csv")
# out_list = []
# for _, row in vul_info_csv.iterrows():
#     out_list.append(
#         {
#             "vul_type": row["cwe_id"],
#             "vul_name": row["project_slug"],
#             "url": row["github_url"] + "/commit/" + row["fix_commit_ids"].split(";")[0],
#             "CodeQL": "",
#             "Semgrep": "",
#             "IRIS": "",
#             "LLMDFA": "",
#             "INFERROI": ""
#         }
#     )

# df = pd.DataFrame(out_list)
# df.to_excel(f"./in_house/java/java_check_table.xlsx", index=False)


vul_info_json_file = Path("./in_house/java/jleaks_vulnerabilities.json")
vul_info_json = json.loads(vul_info_json_file.read_text())["jleaks"]


out_list = []
for bug in vul_info_json:
        out_list.append(
            {
                "vul_type": "CWE-400",
                "vul_name": bug["repo_name"],
                "url": bug["repo_link"] + "/commit/" + bug["commit_id"][:-1],
                "localization": bug["localization"],
            }
        )
df = pd.DataFrame(out_list)
df.to_excel(f"./in_house/java/jleaks_check_table.xlsx", index=False)
