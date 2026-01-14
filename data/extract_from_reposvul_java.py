import json

repos_vul_json = open("./in_house/java/ReposVul_java.jsonl", "r")

lines = repos_vul_json.readlines()

vuls = []

cwes = list()

for line in lines:
    object: dict = json.loads(line)
    cwes.extend(object["cwe_id"])
    object.pop("details")
    object.pop("windows_before")
    object.pop("windows_after")
    object["localization"] = ""
    vuls.append(object)
# print(set(cwes))

# get cwe-190s
# cwe_190s = [vul for vul in vuls if "CWE-190" in vul["cwe_id"]]
# cwe_190s.sort(key=lambda x: x["cve_id"])
# print(len(cwe_190s))
# with open("./in_house/c/cwe_190_IntOver_linux.json", "w") as f:
#     f.write(json.dumps(cwe_190s, indent=4))

# get cwe_401s
# cwe_401s = [vul for vul in vuls if "CWE-401" in vul["cwe_id"]]
# cwe_401s.sort(key=lambda x: x["cve_id"])
# print(len(cwe_401s))
# with open("./in_house/c/cwe_401_MLk_linux.json", "w") as f:
#     f.write(json.dumps(cwe_401s, indent=4))

# get cwe_416s
# cwe_416s = [vul for vul in vuls if "CWE-416" in vul["cwe_id"]]
# cwe_416s.sort(key=lambda x: x["cve_id"])
# print(len(cwe_416s))
# with open("./in_house/c/cwe_416_UAF_linux_new.json", "w") as f:
#     f.write(json.dumps(cwe_416s, indent=4))

# get cwe_476s
cwe_476s = [vul for vul in vuls if "CWE-78" in vul["cwe_id"]]
cwe_476s.sort(key=lambda x: x["cve_id"])
# print(len(cwe_476s))
projects = dict()

for item in cwe_476s:
    project = item["project"]
    if project not in projects:
        projects[project] = 1
    else:
        projects[project] += 1

sorted_projects = sorted(projects.items(), key=lambda x: x[1], reverse=True)

print(sorted_projects[:])
# with open("./in_house/java/cwe_476_NPD.json", "w") as f:
#     f.write(json.dumps(cwe_476s, indent=4))

# get cwe_787 or 125
# cwe_787_125s = [
#     vul for vul in vuls if "CWE-787" in vul["cwe_id"] or "CWE-125" in vul["cwe_id"]
# ]
# cwe_787_125s.sort(key=lambda x: x["cve_id"])
# print(len(cwe_787_125s))
# with open("./in_house/c/cwe_UAF_linux.json", "w") as f:
#     f.write(json.dumps(cwe_787_125s, indent=4))


# list = json.load(open("/Users/ffengjay/Postgraduate/Prepare4Phd/LLM4Security/data/in_house/cwe_190_IntOver_linux.json", "r", encoding="utf-8"))
# print(len(list))

