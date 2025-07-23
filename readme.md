# LLM4Security

## How to run

```bash
git clone https://github.com/Feng-Jay/LLM4Security.git {path to your local repo}
cd {path to your local repo}
pip install -r requirements.txt
# clone projects, you can skip linux to avoid long time cloning, use mirror in https://mirrors.tuna.tsinghua.edu.cn/help/linux.git/
cd src && python setup.py 
```

## Selected Methods

| Candidate Methods | Methodology       | Supported PLs                     | Vulnerability Types                                          | Evaluated BenchMark           | Project Level？   | Link |
| ----------------- | ----------------- | --------------------------------- | ------------------------------------------------------------ | ----------------------------- | ----------------- | ----------------- |
| RepoAudit         | LLM               | C/Cpp, Java, Python, Go           | NPD, MLK, UAF                                                | Many Real-world Projects      | YES               |https://github.com/PurCL/RepoAudit |
| KNighter          | LLM + SAST        | C/Cpp                             | Any (NPD, IntOver, Misuse, Concurrency, MemLeak, BufOver, OOB, UAF, UBI) | Linux Kernel                  | YES               | https://github.com/ise-uiuc/KNighter                 |
| LLift             | SAST + LLM        | C/Cpp                             | UBI                                                          | Linux Kernel                  | YES               | https://github.com/seclab-ucr/LLift |
| LLMDFA            | LLM + Validator   | Java, C/Cpp (partially supported) | APT, DBZ, OSCI, XSS                                          | Juliet Test Suite, TaintBench | YES               | https://github.com/chengpeng-wang/LLMDFA |
| IRIS              | LLM + SAST        | Java                              | APT, OSCI, XSS, Code Injection                               | CWE-Bench-Java                | YES               | https://github.com/iris-sast/iris |
| INFERROI          | LLM or LLM + SAST | Java                              | Resource Leak                                                | JLeaks,                       | YES (with codeql) | https://github.com/cs-wangchong/InferROI-Replication |
| LLMSAN            | LLM               | Java                              | APT, XSS, OSCI, DBZ, NPD                                     |                               | YES               | https://github.com/chengpeng-wang/LLMSAN |


## Evaluation Criteria

### In-house Evaluation

This evaluation setting aims to evaluate the effectiveness of selected baselines on already known vulnerabilities. In this way, we can easily compare the performance of different methods on the same set of vulnerabilities.

It should be noted that we should give each type of CWE a benchmark to fit all above methods.

#### Important Vulnerabilities Types

> [!NOTE]
> Filtered by referencing [2024 Top-25 Most Dangerous SWE leaderboard](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html):

C/CPP: NPD, MLK, UAF, UBI, IntOver, OOB

There are some already known vulnerability reports:

- [existing reports#1](https://github.com/fusion-scan/fusion-scan.github.io/blob/master/index.html): contains NPD, MLK, UAF vulnerabilities.

- [existing reports#2](https://dl.acm.org/doi/10.1145/3368089.3409686): contains 8 UBI vulnerabilities in Linux Kernel.

- [existing reports#3](https://link.springer.com/content/pdf/10.1186/s42400-020-00058-2.pdf): contains 8 IntOver vulnerabilities in Linux Kernel.

- [existing reports#4](https://www.usenix.org/system/files/sec20-chen-weiteng.pdf): contains 8 OOB vulnerabilities in Linux Kernel.


Java: XSS, OSCI, APT, Code Injection, NPD, Resource Leak (CWE-400)

- [existing reports#1](https://github.com/iris-sast/cwe-bench-java/tree/698fb7248ae30cb7f7782d59c841f05ad70ea9cc): contains XSS, OSCI, APT and Code Injection vulnerabilities in Java.

- [existing reports#2](https://github.com/ucd-plse/Static-Bug-Detectors-ASE-Artifact/blob/main/INSTALL.md): contains 102 NPD vulnerabilities in Java.

- [existing reports#3](https://github.com/Dcollectors/JLeaks): contains 1,094 Resource Leak vulnerabilities in Java. 

### Real-world Projects