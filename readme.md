# LLM4Security


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

Java: XSS, OSCI, APT, Code Injection, NPD, Resource Leak (CWE-400)


### Real-world Projects