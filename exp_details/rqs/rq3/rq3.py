import json
import pandas as pd

data = pd.read_excel("./extracted_false_positive_reasons.xlsx", skiprows=27, header=None, sheet_name="Sheet2")

data_dict = data.to_dict(orient="records")

res = {}

for item in data_dict:
    file_name = item[0]
    tool = ""
    if file_name.startswith("INFERROI"):
        tool = "INFERROI"
        pass
    elif file_name.startswith("knighter"):
        tool = "knighter"
        pass
    elif file_name.startswith("LLMDFA"):
        tool = "LLMDFA"
        pass
    elif file_name.startswith("CodeQL"):
        tool = "CodeQL"
        pass
    elif file_name.startswith("semgrep"):
        tool = "semgrep"
        pass
    elif file_name.endswith(".sarif"):
        tool = "iris"
        pass
    else:
        tool = "repoaudit"
    if tool not in res:
        res[tool] = {}
    if item[1] not in res[tool]:
        res[tool][item[1]] = 0
    res[tool][item[1]] += 1

key_map = {
    "B2": "D1",
    "B3": "D2",
    "B4": "D3",
    "C1": "B1",
    "D1": "C1",
}

for tool in res:
    new_dict = {}
    for key in res[tool]:
        # new_key = key_map.get(key, key)
        new_key = key
        if new_key not in new_dict:
            new_dict[new_key] = 0
        new_dict[new_key] += res[tool][key]
    res[tool] = new_dict

print(json.dumps(res, indent=4))

keys = [k for tool in res for k in res[tool].keys()]
keys = list(set(keys))
keys.sort()

# print table
result_dict = {}
tools = ["repoaudit", "knighter", "iris", "LLMDFA", "INFERROI", "CodeQL", "semgrep"]
for tool in tools:
    data = []
    for key in keys:
        data.append(res[tool].get(key, 0))
    result_dict[tool] = data
print(result_dict)

print("&".join(result_dict.keys()))
for index, key in enumerate(keys):
    print(key, end=" & ")
    for tool in result_dict:
        total = sum(result_dict[tool])
        # print(result_dict[tool][index], end=" & ")
        if result_dict[tool][index] == 0:
            print("0/{} (0.0\%)".format(total), end=" & ")
        else:
            print(f"{result_dict[tool][index]}/{total} ({result_dict[tool][index] / total * 100:.1f}\%)", end=" & ")
    print(" \\\\")
    print("\\midrule")
