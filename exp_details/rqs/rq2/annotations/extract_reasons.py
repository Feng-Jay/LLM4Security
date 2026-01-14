import json
import pandas as pd
from pathlib import Path

files = Path("./").iterdir()

reasons = {}

for file in files:
    # if not file.suffix == ".csv":
    #     continue
    print(f"Processing file: {file}")
    if file.name not in reasons:
        reasons[file.name] = []
    match file.suffix:
        case ".json":
            json_obj = json.load(open(file, "r"))
            if "INFERROI" in file.name:
                for item in json_obj:
                    if not item["is_human_confirmed_true"]:
                        reasons[file.name].append(item["reason"])
            else:
                for k, v in json_obj.items():
                    if v["is_human_confirmed_true"] == "False":
                        reasons[file.name].append(v["reason"])
            pass
        case ".sarif":
            sarif_obj = json.load(open(file, "r"))
            for item in sarif_obj:
                if "semgrep" not in file.name.lower():
                    item = item["entry"]["result"]
                if not item["is_human_confirmed_true"]:
                    reasons[file.name].append(item["reason"])
            pass
        case ".csv":
            # print(file)
            lines = open(file, "r").readlines()
            for line in lines:
                reason = line.strip().split(", \"")[-1]
                if "FALSE;" in line:
                    reasons[file.name].append(reason)
            pass
        case ".txt":
            lines = open(file, "r").readlines()
            for line in lines:
                if "FALSE;" in line:
                    reason = line.strip().split("FLASE;")[-1]
                    reasons[file.name].append(reason[: -1])
            pass
        case _:
            continue
    print(f"File {file} has {len(reasons[file.name])} false positives.")

print("Summary of extracted reasons for false positives:")
counter = 0
for k, v in reasons.items():
    counter += len(v)
    print(f"{k}: {len(v)} false positives")
print(f"Total false positives: {counter}")

# rows = [(k, v) for k, values in reasons.items() for v in values]
# df = pd.DataFrame(rows, columns=["key", "value"])

# df.to_excel("extracted_false_positive_reasons.xlsx", index=False)