import re
import json
from pathlib import Path
from datetime import datetime


lines = Path("./cost_knigher.txt").read_text().splitlines()

commit_id = ""
CWE = ""
total_time = 0
result = {}
for line in lines:
    if len(line.strip()) == 0:
        if CWE == "":
            continue
        if not CWE in result:
            result[CWE] = {}
        result[CWE][commit_id] = {
                "generate_time": total_time,
                "input_tokens": int(input_tokens),
                "output_tokens": int(output_tokens),
        }
        total_time = 0
        continue
    if line.startswith("generate:") or line.startswith("refine:"):
        if line.startswith("generate:"):
            time = line.split("generate:")[1].strip()[1:-1]
        else:
            time = line.split("refine:")[1].strip()[1:-1]
        begin_time, end_time = time.split(", ")
        begin_time = begin_time.strip()
        end_time = end_time.strip()
        fmt = "%Y-%m-%d %H:%M:%S.%f"
        # print(end_time, begin_time)
        delta = datetime.strptime(end_time, fmt) - datetime.strptime(begin_time, fmt)
        minutes = delta.total_seconds() / 60.0
        # total_time += minutes
    elif line.startswith("token:"):
        input_tokens, output_tokens = line.split("token:")[1].strip().split(", ")
    elif line.startswith("check:"):
        # print(line)
        begin_time, end_time = line.split("check:")[1].strip()[1:-1].split(", ")
        fmt = "%Y-%m-%d %H:%M:%S.%f"
        begin_time = begin_time.strip()
        end_time = end_time.strip()
        delta = datetime.strptime(end_time, fmt) - datetime.strptime(begin_time, fmt)
        minutes = delta.total_seconds() / 60.0
        total_time += minutes
        pass
    else:
        print(line)
        commit_id, CWE = line.strip().split(",")
print(result)
print(json.dumps(result, indent=4))
total_time_all = []
for cwe in result:
    print(f"CWE: {cwe}")
    input_tokens = 0
    output_tokens = 0
    time = 0
    for commit in result[cwe]:
        input_tokens += result[cwe][commit]["input_tokens"]
        output_tokens += result[cwe][commit]["output_tokens"]
        time += result[cwe][commit]["generate_time"]
        total_time_all.append(result[cwe][commit]["generate_time"])
    print(f"  Total input tokens: {input_tokens}")
    print(f"  Total output tokens: {output_tokens}")
    print(f"  Total time (minutes): {time}")

print(f"Overall total time (minutes): {sum(total_time_all)}")
print(f"Overall average time (minutes): {sum(total_time_all)/len(total_time_all)}")
print(f"Overall max time (minutes): {max(total_time_all)}")
print(f"Overall min time (minutes): {min(total_time_all)}")