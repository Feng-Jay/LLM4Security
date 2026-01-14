# Experiment Details README

In this directory, we provide detailed information about the experiments conducted in this project, including logs, results, and analysis of each RQ.

Since the detection results of evaluated methods are large, often exceeding github's file size limit, we store the full output of the 7 evaluated methods in a separate [Google Drive link](https://drive.google.com/drive/folders/1DchvMVuzhVIsdr7ZI5dKdqFXPKqSlWHo?usp=sharing).

The structure of the results in this google drive is as follows:

```
results/
├── INFERROI                    # Directory for INFERROI in-house evaluation results, logs, and chat history
├── INFERROI_real_world         # Directory for INFERROI real-world evaluation results, logs, and chat history
├── LLMDFA_real_world           # Directory for LLMDFA real-world evaluation results
├── codeql                      # Directory for codeql in-house evaluation results  
├── codeql_real_world           # Directory for codeql real-world evaluation results
├── knighter_checkers           # Directory for knighter checkers, logs, chat history
├── knighter_final_inhouse      # Directory for knighter in-house evaluation results
├── knighter_final_real_world   # Directory for knighter real-world evaluation results
├── repoaudit                   # Directory for repoaudit in-house evaluation results
├── repoaudit_real_world        # Directory for repoaudit real-world evaluation results
├── semgrep                     # Directory for semgrep in-house evaluation results
└── semgrep_real_world          # Directory for semgrep real-world evaluation results
```

The structure of this directory is as follows:

```
exp_details/
│── readme.md                # This README file
│── logs                     # Directory containing logs and chat history for each method
│── rqs                      # Directory containing details for each Research Question
│   │── rq1                  # Directory for Research Question 1
│   |   │── rq1.xlsx         # Detailed results in Excel format for RQ1
|   │
│   │── rq2                  # Directory for Research Question 2
│   |   │── annotations      # Detailed lables for each warning reported by each method for RQ2
│   |   │── table.xlsx       # Detailed results in Excel format for RQ2
|   |
│   │── rq3                  # Directory for Research Question 2
│   |   │── rq3.py           # Python script for RQ3 analysis
│   |   │── rq3.xlsx         # Taxonomy results in Excel format for RQ3
|   |
│   │── rq4                  # Directory for Research Question 2
│   |   │── cal_cost.py      # Python script for RQ4 analysis
│   |   │── table.xlsx       # Overhead results in Excel format for rq4
|   |   │── cost_knighter.py # Cost details for knighter
```