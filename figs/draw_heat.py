import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# 1) Load data
df = pd.read_csv("rq3_reasons.csv", index_col="Reason")

# 2) Define row colors (same semantics as your LaTeX colors)
row_colors = {
    "A1": "#086FD6",
    "A2": "#086FD6",
    "B1": "#CED108",
    "C1": "#33CC0D",
    "D1": "#D01010",
    "D2": "#D01010",
    "D3": "#D01010",
    "D4": "#D01010",
}
# tools / columns
cols = ["RepoAudit", "Knighter", "IRIS", "LLMDFA", "INFERROI", "CodeQL", "Semgrep"]

# numeric percentages for each cell (same order as your LaTeX)
data_pct = [
    [16.9,  0.0, 53.5, 42.9, 25.0, 33.8, 71.4],  # A1
    [24.6, 25.9,  0.0,  0.0,  0.0,  1.5,  0.0],  # A2
    [18.5, 55.6, 14.9, 57.1, 28.6, 13.2,  4.1],  # B1
    [16.9,  0.0, 18.8,  0.0,  0.0,  0.0,  0.0],  # C1
    [ 9.2,  3.7, 11.9,  0.0, 10.7, 29.4,  8.2],  # D1
    [ 3.1,  0.0,  1.0,  0.0, 35.7,  5.9, 12.2],  # D2
    [ 0.0, 11.1,  0.0,  0.0,  0.0, 10.3,  0.0],  # D3
    [10.8,  3.7,  0.0,  0.0,  0.0,  5.9,  4.1],  # D4
]

index = ["A1", "A2", "B1", "C1", "D1", "D2", "D3", "D4"]

data_annot = [
    ["11/65\n(16.9%)", "0/29\n(0.0%)",  "54/101\n(53.5%)", "6/14\n(42.9%)",  "7/28\n(25.0%)",  "32/77\n(41.6%)", "35/49\n(71.4%)"],
    ["16/65\n(24.6%)", "7/29\n(24.1%)", "0/101\n(0.0%)",   "0/14\n(0.0%)",   "0/28\n(0.0%)",   "1/77\n(1.3%)",   "0/49\n(0.0%)"],
    ["12/65\n(18.5%)", "17/29\n(58.6%)","15/101\n(14.9%)", "8/14\n(57.1%)",  "8/28\n(28.6%)",  "9/77\n(11.7%)",  "2/49\n(4.1%)"],
    ["11/65\n(16.9%)", "0/29\n(0.0%)",  "19/101\n(18.8%)", "0/14\n(0.0%)",   "0/28\n(0.0%)",   "0/77\n(0.0%)",   "0/49\n(0.0%)"],
    ["6/65\n(9.2%)",   "1/29\n(3.4%)",  "12/101\n(11.9%)", "0/14\n(0.0%)",   "3/28\n(10.7%)",  "20/77\n(26.0%)", "4/49\n(8.2%)"],
    ["2/65\n(3.1%)",   "0/29\n(0.0%)",  "1/101\n(1.0%)",   "0/14\n(0.0%)",   "10/28\n(35.7%)", "4/77\n(5.2%)",   "6/49\n(12.2%)"],
    ["0/65\n(0.0%)",   "3/29\n(10.3%)", "0/101\n(0.0%)",   "0/14\n(0.0%)",   "0/28\n(0.0%)",   "7/77\n(9.1%)",  "0/49\n(0.0%)"],
    ["7/65\n(10.8%)",  "1/29\n(3.4%)",  "0/101\n(0.0%)",   "0/14\n(0.0%)",   "0/28\n(0.0%)",   "4/77\n(5.2%)",   "2/49\n(4.1%)"],
]

df_annot = pd.DataFrame(data_annot, index=index, columns=cols)

# 3) Create figure
plt.figure(figsize=(8, 4))  # adjust for paper layout

ax = sns.heatmap(
    df,
    annot=df_annot.values,          # show numbers in cells
    fmt="s",           # one decimal place
    cmap="YlOrRd",       # choose a color map you like
    vmin=0,
    vmax=100,
    # cbar_kws={"label": "False positive rate (%)"},
    annot_kws={"size": 7},  # try 7–8 for paper figures

)
for text in ax.texts:
    text.set_fontweight("bold")
ax.xaxis.tick_top()                 # move tick labels

# 4) Color each row label by its category color
yticklabels = ax.get_yticklabels()
for label in yticklabels:
    reason = label.get_text()
    if reason in row_colors:
        label.set_color(row_colors[reason])
    label.set_fontweight("bold")   # make it bold
ax.set_yticklabels(yticklabels, rotation=0)

xticklabels = ax.get_xticklabels()
for label in xticklabels:
    label.set_fontweight("bold")
ax.set_xticklabels(xticklabels, rotation=0)  # rotation optional

# 5) Axis labels and title
# ax.set_xlabel("Tool")
ax.set_ylabel("FP reason")
# ax.set_title("False-positive reasons per tool on real-world projects")

plt.tight_layout()
plt.savefig("rq3_heatmap.pdf", bbox_inches="tight")   # use PDF for LaTeX
plt.close()