from venn import venn, draw_venn
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_excel("/Users/ffengjay/Postgraduate/Prepare4Phd/LLM4Security/data/in_house/c/linux_check_table.xlsx", 
                   sheet_name="Inhouse_Java")

rows = df.to_dict(orient="records")

dict_of_dict_of_sets = {}
for row in rows:
    vul_type = row["vul_type"]
    vul_name = row["vul_name"]
    if vul_type not in dict_of_dict_of_sets:
        dict_of_dict_of_sets[vul_type] = dict()
    for k, v in row.items():
        if v == 1.0:
            if k not in dict_of_dict_of_sets[vul_type]:
                dict_of_dict_of_sets[vul_type][k] = set()
            dict_of_dict_of_sets[vul_type][k].add(vul_name)

def draw_venn_diagram(datas, filePath = "./venn.pdf"):
    print(datas)
    color_map = {
    "CodeQL":   "#1f77b4",  # soft blue
    "Semgrep":  "#2ca02c",  # bright green
    "IRIS":     "#9467bd",  # purple
    "INFERROI": "#d62728",  # red
    }
    venn(datas, fontsize=30, figsize=(20, 20))

    # from matplotlib_venn import venn2, venn3
    # if len(datas) == 2:
    #     colors = [color_map.get(name, "#AAAAAA") for name in datas.keys()]
    #     venn2([set(datas[item]) for item in datas.keys()], set_labels = datas.keys(), set_colors=colors)
    # elif len(datas) == 3:
    #     colors = [color_map.get(name, "#AAAAAA") for name in datas.keys()]
    #     venn3([set(datas[item]) for item in datas.keys()], set_labels = datas.keys(), set_colors=colors)
    # print("Creating venn diagrams...")
    plt.savefig(filePath)
    plt.close()

# print(dict_of_dict_of_sets)
for vul_type in dict_of_dict_of_sets:
    print(f"Drawing venn diagram for vulnerability type: {vul_type}")
    if len(dict_of_dict_of_sets[vul_type]) < 2:
        print(f"Skipping {vul_type} as it has less than 2 sets.")
        continue
    # print(dict_of_dict_of_sets[vul_type].keys())
    order = [ "IRIS", "INFERROI", "CodeQL", "Semgrep"]
    dict_of_dict_of_sets[vul_type] = {k: dict_of_dict_of_sets[vul_type][k] for k in order if k in dict_of_dict_of_sets[vul_type]}
    draw_venn_diagram(dict_of_dict_of_sets[vul_type], 
                      filePath=f"./venn_{vul_type}.pdf")