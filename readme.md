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