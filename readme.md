# LLM4Security

This repository contains the replication package for our empirical study:

**LLM-based Vulnerability Detection at Project Scale: An Empirical Study**

It includes evaluation scripts, prompts/configurations, and datasets metadata used to compare multiple project-scale LLM-based vulnerability detectors with traditional static analyzers on two complementary settings:
1) an **in-house benchmark** of known real-world vulnerabilities, and  
2) a set of **recent, actively maintained real-world projects** for analyzing false positives and practical usability.

> [!NOTE]
> Some result artifacts (e.g., large logs / SARIF) may be tracked via Google Drive links in the `exp_details` directory due to GitHub file size limits.

---

## Repository Structure

- `appendix/`  
  Appendix materials for the paper.
- `exp_details/`  
  Experiment logs, tool outputs, and detailed results for each RQ.  
    - `exp_details/results/` may contain large artifacts (logs/SARIF), so we provide a Google Drive link in the README under this directory.
- `data/`  
  Dataset metadata, project lists, and vulnerability instance lists.
- `figs/`  
  Figures and visualizations used in the paper.
- `resources/`  
  Supporting resources such as codeql and semgrep rule sets, and linux-kernel patches to make it compilable.
- `src/`  
  Our evaluation framework to run tools easily on target benchmark.

---

## Evaluated Methods

| Candidate Methods | Methodology       | Supported PLs                     | Vulnerability Types                                          | Evaluated BenchMark           | Project Level？   | Link |
| ----------------- | ----------------- | --------------------------------- | ------------------------------------------------------------ | ----------------------------- | ----------------- | ----------------- |
| RepoAudit ✅       | LLM               | C/Cpp, Java, Python, Go           | NPD, MLK, UAF                                                | Many Real-world Projects      | YES               |https://github.com/PurCL/RepoAudit |
| KNighter ✅         | LLM + SAST        | C/Cpp                             | Multi | Linux Kernel                  | YES               | https://github.com/ise-uiuc/KNighter                 |
| LLMDFA ✅            | LLM + Validator   | Java, C/Cpp (partially supported) | APT, OSCI, XSS                                          | Juliet Test Suite, TaintBench | YES               | https://github.com/chengpeng-wang/LLMDFA |
| IRIS ✅              | LLM + SAST        | Java                              | APT, OSCI, XSS, Code Injection                               | CWE-Bench-Java                | YES               | https://github.com/iris-sast/iris |
| INFERROI ✅          | LLM or LLM + SAST | Java                              | Resource Leak                                                | JLeaks,                       | YES (with codeql) | https://github.com/cs-wangchong/InferROI-Replication |
| CodeQL ✅           | Static Analyzer   | C/Cpp, Java                       | All above        | Many Real-world Projects      | YES               | https://codeql.github.com/
| Semgrep ✅          | Static Analyzer   | C/Cpp, Java                       | All above        | Many Real-world Projects      | YES               | https://semgrep.dev/

## Requirements

### System
- Linux / macOS (recommended)
- Python 3.11+

## How to run

> [!NOTE] 
> Since our repo contains several submodules, please first clone it with `--recursive` flag:

```bash
git clone --recursive https://github.com/Feng-Jay/LLM4Security.git {path to your local repo}
```

Then, install the required python packages and setup the project:

```bash
cd {path to your local repo}
pip install -r requirements.txt
```

In case you forget to add the --recursive flag during clone, you can run the following command to update submodules

```bash
git submodule update --init --recursive
```

Then run a specific tool by modifying corresponding configuration files.

For example, to run RepoAudit on the in-house benchmark, you can modify the `example.yaml` and `repoaudit.yaml` like this:

```yaml
# example.yaml
tool: "repoaudit"

tools:
  repoaudit:
    # configurations fit your environment
  ...
```

```yaml
# repoaudit.yaml
repoaudit_path: /path/to/LLM4Security/src/dependencies/RepoAudit_main/src
project_path: /path/to/LLM4Security/data/projects/linux
vul_type: NPD
model_name: claude-3.5
```
Then, you can run the evaluation script:

```bash
cd src/ && python main.py
```