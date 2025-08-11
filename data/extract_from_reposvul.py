import json

repos_vul_json = open("./in_house/c/ReposVul_c.jsonl", "r")

lines = repos_vul_json.readlines()

vuls = []

for line in lines:
    object: dict = json.loads(line)
    if "torvalds/linux" not in object["project"]:
        continue
    object.pop("details")
    object.pop("windows_before")
    object.pop("windows_after")
    vuls.append(object)

# get cwe-190s
cwe_190s = [vul for vul in vuls if "CWE-190" in vul["cwe_id"]]
cwe_190s.sort(key=lambda x: x["cve_id"])
print(len(cwe_190s))
with open("./in_house/c/cwe_190_IntOver_linux.json", "w") as f:
    f.write(json.dumps(cwe_190s, indent=4))

# get cwe_401s
cwe_401s = [vul for vul in vuls if "CWE-401" in vul["cwe_id"]]
cwe_401s.sort(key=lambda x: x["cve_id"])
print(len(cwe_401s))
with open("./in_house/c/cwe_401_MLk_linux.json", "w") as f:
    f.write(json.dumps(cwe_401s, indent=4))

# get cwe_416s
cwe_416s = [vul for vul in vuls if "CWE-416" in vul["cwe_id"]]
cwe_416s.sort(key=lambda x: x["cve_id"])
print(len(cwe_416s))
with open("./in_house/c/cwe_416_UAF_linux.json", "w") as f:
    f.write(json.dumps(cwe_416s, indent=4))

# get cwe_476s
cwe_476s = [vul for vul in vuls if "CWE-476" in vul["cwe_id"]]
cwe_476s.sort(key=lambda x: x["cve_id"])
print(len(cwe_476s))
with open("./in_house/c/cwe_476_NPD_linux.json", "w") as f:
    f.write(json.dumps(cwe_476s, indent=4))

# get cwe_787 or 125
cwe_787_125s = [
    vul for vul in vuls if "CWE-787" in vul["cwe_id"] or "CWE-125" in vul["cwe_id"]
]
cwe_787_125s.sort(key=lambda x: x["cve_id"])
print(len(cwe_787_125s))
with open("./in_house/c/cwe_787_125_OOB_linux.json", "w") as f:
    f.write(json.dumps(cwe_787_125s, indent=4))


# list = json.load(open("/Users/ffengjay/Postgraduate/Prepare4Phd/LLM4Security/data/in_house/cwe_190_IntOver_linux.json", "r", encoding="utf-8"))
# print(len(list))

