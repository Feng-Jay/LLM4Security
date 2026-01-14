import re
import json
from pathlib import Path
from datetime import datetime

logs_dir = Path("./")

def parse_repoaudit(log_path: Path):
    lines = log_path.read_text().splitlines()
    input_counter = 0
    output_counter = 0
    samples = 1
    begin_time = lines[0].split(" - INFO - ")[0]
    end_time = lines[-1].split(" - INFO - ")[0]
    fmt = "%Y-%m-%d %H:%M:%S,%f"
    delta = datetime.strptime(end_time, fmt) - datetime.strptime(begin_time, fmt)
    minutes = delta.total_seconds() / 60.0
    for line in lines:
        if "Input token cost: " in line:
            input_counter += int(line.split("Input token cost:")[1].strip())
        elif "Output token cost: " in line:
            output_counter += int(line.split("Output token cost:")[1].strip())
        # elif "Query number: " in line:
            # samples += int(line.split("Query number:")[1].strip())
    return input_counter, output_counter, samples, minutes

def parse_knighter(log_path: Path):
    lines = log_path.read_text().splitlines()
    input_counter = 0
    output_counter = 0
    samples = 1
    tmp_input_counter = 0
    tmp_output_counter = 0
    tmp_list = []
    pattern = re.compile(r"Input tokens: (\d+), Output tokens: (\d+)")

    begin_time = lines[0].split("| INFO")[0].strip()
    end_time = lines[-1].split(" | ERROR")[0].strip()
    fmt = "%Y-%m-%d %H:%M:%S.%f"
    print(end_time, begin_time)
    delta = datetime.strptime(end_time, fmt) - datetime.strptime(begin_time, fmt)
    minutes = delta.total_seconds() / 60.0
    current_commit = ""
    for line in lines:
        if pattern.search(line):
            match = pattern.search(line)
            tmp_input_counter += int(match.group(1))
            tmp_output_counter += int(match.group(2))
        if "Find a perfect checker" in line:
            input_counter += tmp_input_counter
            output_counter += tmp_output_counter
            samples += 1
            tmp_list.append((tmp_input_counter, tmp_output_counter, current_commit))
        if "checker_gen:gen_checker:49 - Processing" in line:
            current_commit = line.split("Processing ")[1]
            tmp_input_counter = 0
            tmp_output_counter = 0
    print(tmp_list)
    input("Press Enter to continue...")
    print(min([item[0] for item in tmp_list]))
    print(max([item[0] for item in tmp_list]))
    print(min([item[1] for item in tmp_list]))
    print(max([item[1] for item in tmp_list]))
    return input_counter, output_counter, samples, minutes

def parse_iris(log_path: Path):
    lines = log_path.read_text().splitlines()
    input_counter = 0
    output_counter = 0
    samples = 1
    pattern1 = re.compile(r"input tokens:(\d+), output tokens:(\d+)")
    pattern2 = re.compile(r"input_token_sum=(\d+), output_token_sum=(\d+)")
    time_pattern = re.compile(r"\[INFO\] \[(.*)\]")
    begin_time = time_pattern.search(lines[0]).group(1)
    end_time = time_pattern.search(lines[-1]).group(1)
    fmt = "%Y-%m-%d %H:%M:%S"
    delta = datetime.strptime(end_time, fmt) - datetime.strptime(begin_time, fmt)
    minutes = delta.total_seconds() / 60.0
    tmp_in_sum = 0
    tmp_out_sum = 0
    for line in lines:
        match = pattern1.search(line)
        if match:
            input_counter = int(match.group(1))
            output_counter = int(match.group(2))
        if "input_token_sum=" in line:
            match = pattern2.search(line)
            if match:
                tmp_in_sum = int(match.group(1))
                tmp_out_sum = int(match.group(2))
    input_counter += tmp_in_sum
    output_counter += tmp_out_sum
    return input_counter, output_counter, samples, minutes

def parse_llmdfa(log_path: Path):
    input_cost = 0
    output_cost = 0
    samples = 1
    for dir in log_path.iterdir():
        if not dir.is_dir():
            continue
        if (dir / "report.json").exists():
            report = json.load(open(dir / "report.json", "r"))
            input_cost += report.get("input_token_cost", 0)
            output_cost += report.get("output_token_cost", 0)
    return input_cost, output_cost, samples

def parse_inferroi(log_path: Path):
    lines = log_path.read_text().splitlines()
    input_cost = 0
    output_cost = 0
    samples = 1
    begin_time = lines[0].split(" | INFO ")[0]
    end_time = lines[-1].split(" | INFO ")[0]
    fmt = "%Y-%m-%d %H:%M:%S.%f"
    delta = datetime.strptime(end_time, fmt) - datetime.strptime(begin_time, fmt)
    minutes = delta.total_seconds() / 60.0
    pattern = re.compile(r"input tokens: (\d+); output tokens: (\d+)")
    for line in lines:
        match = pattern.search(line)
        if match:
            input_cost += int(match.group(1))
            output_cost += int(match.group(2))
    return input_cost, output_cost, samples, minutes

def parse_codeql_or_semgrep(log_path: Path):
    # Placeholder for future implementation
    lines = log_path.read_text().splitlines()
    begin_time = lines[0].split(" | INFO ")[0]
    end_time = lines[-1].split(" | INFO ")[0]
    fmt = "%Y-%m-%d %H:%M:%S.%f"
    delta = datetime.strptime(end_time, fmt) - datetime.strptime(begin_time, fmt)
    minutes = delta.total_seconds() / 60.0
    return 0, 0, 1, minutes

costs = {}

llmdfa_times = {
    "xwiki-platform": ("2025-11-07 14:36", "2025-11-10 19:54"),
    "jenkins": ("2025-11-07 14:25", "2025-11-07 23:15"),
    "keycloak": ("2025-11-07 14:36", "2025-11-10 11:37"),
    "xstream": ("2025-10-15 10:21", "2025-10-16 02:54"),
    "workflow-cps-plugin": ("2025-10-15 14:41", "2025-10-15 15:25"),
    "tika": ("2025-10-15 11:42", "2025-10-16 15:16"),
}


for log in logs_dir.iterdir():
    if log.name.startswith("repoaudit"):
        input_cost, output_cost, samples, time = parse_repoaudit(log)
        print(f"repoaudit: input cost: {input_cost}, output cost: {output_cost}, samples: {samples}, time: {time} minutes")
        if not "repoaudit" in costs:
            costs["repoaudit"] = []
        costs["repoaudit"].append((input_cost, output_cost, samples, time, log.name))

    elif log.name.startswith("knighter"):
        print(log.name)
        input_cost, output_cost, samples, time = parse_knighter(log)
        print(f"knighter: input cost: {input_cost}, output cost: {output_cost}, samples: {samples}, time: {time} minutes")
        if not "knighter" in costs:
            costs["knighter"] = []
        costs["knighter"].append((input_cost, output_cost, samples, time, log.name))
    
    elif log.name.startswith("iris"):
        input_cost, output_cost, samples, time= parse_iris(log)
        print(f"iris: input cost: {input_cost}, output cost: {output_cost}, samples: {samples}, time: {time} minutes")
        if not "iris" in costs:
            costs["iris"] = []
        costs["iris"].append((input_cost, output_cost, samples, time, log.name))
        
    elif log.name.startswith("llmdfa"):
        input_cost, output_cost, samples = parse_llmdfa(log)
        repo_name = log.name.split("llmdfa_")[1]
        fmt = "%Y-%m-%d %H:%M"
        time = datetime.strptime(llmdfa_times.get(repo_name)[1], fmt) - datetime.strptime(llmdfa_times.get(repo_name)[0], fmt)
        minutes = time.total_seconds() / 60.0
        print(f"llmdfa: input cost: {input_cost}, output cost: {output_cost}, samples: {samples}, time: {minutes} minutes")
        if not "llmdfa" in costs:
            costs["llmdfa"] = []
        costs["llmdfa"].append((input_cost, output_cost, samples, minutes, log.name))

    elif log.name.startswith("inferroi"):
        input_cost, output_cost, samples, time = parse_inferroi(log)
        print(f"inferroi: input cost: {input_cost}, output cost: {output_cost}, samples: {samples}, time: {time} minutes")
        if not "inferroi" in costs:
            costs["inferroi"] = []
        costs["inferroi"].append((input_cost, output_cost, samples, time, log.name))
    
    elif log.name.startswith("codeql") or log.name.startswith("semgrep"):
        input_cost, output_cost, samples, time = parse_codeql_or_semgrep(log)
        tool_name = "codeql" if log.name.startswith("codeql") else "semgrep"
        print(f"{tool_name}: samples: {samples}, time: {time} minutes")
        if not tool_name in costs:
            costs[tool_name] = []
        costs[tool_name].append((input_cost, output_cost, samples, time, log.name))
    else:
        continue

print("===================== Detailed Costs =====================")
print(json.dumps(costs, indent=4))
with open("cost_summary.json", "w") as f:
    json.dump(costs, f, indent=4)
print("===================== Cost Summary =====================")
for tool in costs.keys():
    min_input = min([item[0] for item in costs[tool]])
    max_input = max([item[0] for item in costs[tool]])
    avg_input = round(sum([item[0] for item in costs[tool]]) / sum(item[2] for item in costs[tool]), 2)
    min_output = min([item[1] for item in costs[tool]])
    max_output = max([item[1] for item in costs[tool]])
    avg_output = round(sum([item[1] for item in costs[tool]]) / sum(item[2] for item in costs[tool]), 2)
    min_time = min([item[3] for item in costs[tool]])
    max_time = max([item[3] for item in costs[tool]])
    avg_time = round(sum([item[3] for item in costs[tool]]) / sum(item[2] for item in costs[tool]), 10)
    print(f"{tool} input cost: min={min_input}, max={max_input}, avg={avg_input}")
    print(f"{tool} output cost: min={min_output}, max={max_output}, avg={avg_output}")
    print(f"{tool} time (minutes): min={min_time}, max={max_time}, avg={avg_time}, samples={sum([item[2] for item in costs[tool]])}")