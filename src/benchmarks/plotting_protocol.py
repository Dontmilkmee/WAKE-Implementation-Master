import matplotlib.pyplot as plt
import csv
import matplotlib as mpl

upperbound_logarithms = ["8", "16", "32", "64"]

parties = []

time_compiler = [[] for _ in range(4)]
time_optimized = [[] for _ in range(4)]
time_gm17_compiler = [[] for _ in range(4)]
time_gm17_optimized = [[] for _ in range(4)]
time_bd = [[] for _ in range(4)]

time_pr_party_compiler = [[] for _ in range(4)]
time_pr_party_optimized = [[] for _ in range(4)]
time_per_party_gm17_compiler = [[] for _ in range(4)]
time_per_party_gm17_optimized = [[] for _ in range(4)]
time_pr_party_bd = [[] for _ in range(4)]

with open('data/optimized_and_compiler_output.csv','r') as csvfile:
    lines = csv.reader(csvfile, delimiter=',')
    for row in lines:
        i = upperbound_logarithms.index(row[0])
        if i == 0:
            parties.append(int(row[1]))
        time_compiler[i].append(float(row[2])/1e9)
        time_pr_party_compiler[i].append(float(row[3])/1e9)
        time_optimized[i].append(float(row[4])/1e9)
        time_pr_party_optimized[i].append(float(row[5])/1e9)
        time_bd[i].append(float(row[6])/1e9)
        time_pr_party_bd[i].append(float(row[7])/1e9)
        time_gm17_compiler[i].append(float(row[8])/1e9)
        time_per_party_gm17_compiler[i].append(float(row[9])/1e9)
        time_gm17_optimized[i].append(float(row[10])/1e9)
        time_per_party_gm17_optimized[i].append(float(row[11])/1e9)

title_strings = ["$2^{8}-1$","$2^{16}-1$","$2^{32}-1$","$2^{64}-1$"]

for i in range(4):
    exp = int(upperbound_logarithms[i])
    
    #plot all
    plt.plot(parties, time_compiler[i], color = 'r', linestyle = 'solid', marker = 'o',label = "COMP BPRP")
    plt.plot(parties, time_optimized[i], color = 'b', linestyle = 'solid', marker = 'x',label = "OPT BPRP")
    plt.plot(parties, time_gm17_compiler[i], color = 'g', linestyle = 'solid', marker = 'D',label = "COMP GM17")
    plt.plot(parties, time_gm17_optimized[i], color = 'y', linestyle = 'solid', marker = '^',label = "OPT GM17")
    plt.plot(parties, time_bd[i], color = 'indigo', linestyle = 'solid', marker = 's', label = "BD")

    plt.xlabel('party amount')
    plt.ylabel('seconds')
    plt.title(f'Upper-bound {title_strings[i]}', fontsize = 15)
    plt.grid()
    plt.legend()
    plt.savefig(f'plots/protocol_times/total_upper_bound_{exp}.png', dpi=300)
    plt.clf()

for i in range(4):
    exp = int(upperbound_logarithms[i])
    #plot all
    plt.plot(parties, time_pr_party_compiler[i], color = 'r', linestyle = 'solid', marker = 'o',label = "COMP BPRP")
    plt.plot(parties, time_pr_party_optimized[i], color = 'b', linestyle = 'solid', marker = 'x',label = "OPT BPRP")
    plt.plot(parties, time_per_party_gm17_compiler[i], color = 'g', linestyle = 'solid', marker = 'D',label = "COMP GM17")
    plt.plot(parties, time_per_party_gm17_optimized[i], color = 'y', linestyle = 'solid', marker = '^',label = "OPT GM17")
    plt.plot(parties, time_pr_party_bd[i], color = 'indigo', linestyle = 'solid', marker = 's', label = "BD")
    plt.xlabel('party amount')
    plt.ylabel('seconds / party amount')
    plt.title(f'Upper-bound {title_strings[i]}', fontsize = 15)
    plt.grid()
    plt.legend()
    plt.savefig(f'plots/protocol_times/pr_party_upper_bound_{exp}.png', dpi=300)
    plt.clf()

#set global params
mpl.rcParams['lines.markersize'] = 4
mpl.rcParams.update({'font.size': 8.5})

# 4 plots total
fig, axs = plt.subplots(2, 2)
axs[0,0].plot(parties, time_compiler[0], color = 'r', linestyle = 'solid', marker = 'o',label = "Comp RPRP")
axs[0,0].plot(parties, time_optimized[0], color = 'b', linestyle = 'solid', marker = 'x',label = "OPT BPRP")
axs[0,0].plot(parties, time_gm17_compiler[0], color = 'g', linestyle = 'solid', marker = 'D',label = "COMP GM17")
axs[0,0].plot(parties, time_gm17_optimized[0], color = 'y', linestyle = 'solid', marker = '^',label = "OPT GM17")
axs[0,0].plot(parties, time_bd[0], color = 'indigo', linestyle = 'solid', marker = 's', label = "BD")
axs[0,0].grid()
axs[0,0].set_title("${2^8}-1$", fontsize=9.5)

axs[0,1].plot(parties, time_compiler[1], color = 'r', linestyle = 'solid', marker = 'o')
axs[0,1].plot(parties, time_optimized[1], color = 'b', linestyle = 'solid', marker = 'x')
axs[0,1].plot(parties, time_gm17_compiler[1], color = 'g', linestyle = 'solid', marker = 'D')
axs[0,1].plot(parties, time_gm17_optimized[1], color = 'y', linestyle = 'solid', marker = '^')
axs[0,1].plot(parties, time_bd[1], color = 'indigo', linestyle = 'solid', marker = 's')
axs[0,1].grid()
axs[0,1].set_title("${2^{16}}-1$", fontsize=9.5)

axs[1,0].plot(parties, time_compiler[2], color = 'r', linestyle = 'solid', marker = 'o')
axs[1,0].plot(parties, time_optimized[2], color = 'b', linestyle = 'solid', marker = 'x')
axs[1,0].plot(parties, time_gm17_compiler[2], color = 'g', linestyle = 'solid', marker = 'D')
axs[1,0].plot(parties, time_gm17_optimized[2], color = 'y', linestyle = 'solid', marker = '^')
axs[1,0].plot(parties, time_bd[2], color = 'indigo', linestyle = 'solid', marker = 's')
axs[1,0].grid()
axs[1,0].set_title("${2^{32}}-1$", fontsize=9.5)


axs[1,1].plot(parties, time_compiler[3], color = 'r', linestyle = 'solid', marker = 'o')
axs[1,1].plot(parties, time_optimized[3], color = 'b', linestyle = 'solid', marker = 'x')
axs[1,1].plot(parties, time_gm17_compiler[3], color = 'g', linestyle = 'solid', marker = 'D')
axs[1,1].plot(parties, time_gm17_optimized[3], color = 'y', linestyle = 'solid', marker = '^')
axs[1,1].plot(parties, time_bd[3], color = 'indigo', linestyle = 'solid', marker = 's')
axs[1,1].grid()
axs[1,1].set_title("${2^{64}}-1$", fontsize=9.5)

fig.text(0.52, 0.015, 'party amount', ha='center', va='center')
fig.text(0.0, 0.5, 'seconds', ha='center', va='center', rotation='vertical')

plt.figlegend(ncol = 5, bbox_to_anchor=(0.9,0), prop = {"size": 8.2})
plt.tight_layout()
plt.savefig(f'plots/protocol_times/total_upper_bound_big', bbox_inches='tight', dpi=300)

# 4 plots pr-party
fig, axs = plt.subplots(2, 2)
axs[0,0].plot(parties, time_pr_party_compiler[0], color = 'r', linestyle = 'solid', marker = 'o',label = "COMP BPRP")
axs[0,0].plot(parties, time_pr_party_optimized[0], color = 'b', linestyle = 'solid', marker = 'x',label = "OPT BPRP")
axs[0,0].plot(parties, time_per_party_gm17_compiler[0], color = 'g', linestyle = 'solid', marker = 'D',label = "COMP GM17")
axs[0,0].plot(parties, time_per_party_gm17_optimized[0], color = 'y', linestyle = 'solid', marker = '^',label = "OPT GM17")
axs[0,0].plot(parties, time_pr_party_bd[0], color = 'indigo', linestyle = 'solid', marker = 's', label = "BD")
axs[0,0].grid()
axs[0,0].set_title("${2^8}-1$", fontsize=9.5)

axs[0,1].plot(parties, time_pr_party_compiler[1], color = 'r', linestyle = 'solid', marker = 'o')
axs[0,1].plot(parties, time_pr_party_optimized[1], color = 'b', linestyle = 'solid', marker = 'x')
axs[0,1].plot(parties, time_per_party_gm17_compiler[1], color = 'g', linestyle = 'solid', marker = 'D')
axs[0,1].plot(parties, time_per_party_gm17_optimized[1], color = 'y', linestyle = 'solid', marker = '^')
axs[0,1].plot(parties, time_pr_party_bd[1], color = 'indigo', linestyle = 'solid', marker = 's')
axs[0,1].grid()
axs[0,1].set_title("${2^{16}}-1$", fontsize=9.5)

axs[1,0].plot(parties, time_pr_party_compiler[2], color = 'r', linestyle = 'solid', marker = 'o')
axs[1,0].plot(parties, time_pr_party_optimized[2], color = 'b', linestyle = 'solid', marker = 'x')
axs[1,0].plot(parties, time_per_party_gm17_compiler[2], color = 'g', linestyle = 'solid', marker = 'D')
axs[1,0].plot(parties, time_per_party_gm17_optimized[2], color = 'y', linestyle = 'solid', marker = '^')
axs[1,0].plot(parties, time_pr_party_bd[2], color = 'indigo', linestyle = 'solid', marker = 's')
axs[1,0].grid()
axs[1,0].set_title("${2^{32}}-1$", fontsize=9.5)


axs[1,1].plot(parties, time_pr_party_compiler[3], color = 'r', linestyle = 'solid', marker = 'o')
axs[1,1].plot(parties, time_pr_party_optimized[3], color = 'b', linestyle = 'solid', marker = 'x')
axs[1,1].plot(parties, time_per_party_gm17_compiler[3], color = 'g', linestyle = 'solid', marker = 'D')
axs[1,1].plot(parties, time_per_party_gm17_optimized[3], color = 'y', linestyle = 'solid', marker = '^')
axs[1,1].plot(parties, time_pr_party_bd[3], color = 'indigo', linestyle = 'solid', marker = 's')
axs[1,1].grid()
axs[1,1].set_title("${2^{64}}-1$", fontsize=9.5)

fig.text(0.52, 0.015, 'party amount', ha='center', va='center')
fig.text(0.0, 0.5, 'seconds / party amount', ha='center', va='center', rotation='vertical')

plt.figlegend(ncol = 5, bbox_to_anchor=(0.9,0), prop = {"size": 8.2})
plt.tight_layout()
plt.savefig(f'plots/protocol_times/pr_party_upper_bound_big', bbox_inches='tight', dpi=300)
plt.clf()

#########################################Predict with larger party amounts###################################################
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error
import numpy as np

worst_normalized_rmse_so_far = 0
predict_x_vals = np.array([100, 250, 500, 1000, 2500, 5000]).reshape(-1,1)
upperbound_logarithms = ["8 ", "16", "32", "64"]
with open('protocol_time_predictions/protocol_time_predictions.txt', 'w') as file:
    #compiler BPRP
    file.write("COMPILER BPRP\n")
    for i in range(4):
        x = np.array(parties).reshape(-1,1)
        y = np.array(time_pr_party_compiler[i])
        linear_regressor = LinearRegression()
        linear_regressor.fit(x, y)
        
        y_pred = linear_regressor.predict(x)

        normalized_rmse = mean_squared_error(y, y_pred, squared=False)/np.mean(y)
        if normalized_rmse > worst_normalized_rmse_so_far:
            worst_normalized_rmse_so_far = normalized_rmse
        file.write(f"{upperbound_logarithms[i]}: ")
        for predict_x in linear_regressor.predict(predict_x_vals):
            file.write(f"{round(predict_x, 2)}, ")
        file.write("\n")

    #opt BPRP
    file.write("\nOPT BPRP\n")
    for i in range(4):
        x = np.array(parties).reshape(-1,1)
        y = np.array(time_pr_party_optimized[i])
        linear_regressor = LinearRegression()
        linear_regressor.fit(x, y)
        
        y_pred = linear_regressor.predict(x)

        normalized_rmse = mean_squared_error(y, y_pred, squared=False)/np.mean(y)
        if normalized_rmse > worst_normalized_rmse_so_far:
            worst_normalized_rmse_so_far = normalized_rmse
        file.write(f"{upperbound_logarithms[i]}: ")
        for predict_x in linear_regressor.predict(predict_x_vals):
            file.write(f"{round(predict_x, 2)}, ")
        file.write("\n")

    #comp GM17
    file.write("\nCOMP GM17\n")
    for i in range(4):
        x = np.array(parties).reshape(-1,1)
        y = np.array(time_per_party_gm17_compiler[i])
        linear_regressor = LinearRegression()
        linear_regressor.fit(x, y)
        
        y_pred = linear_regressor.predict(x)

        normalized_rmse = mean_squared_error(y, y_pred, squared=False)/np.mean(y)
        if normalized_rmse > worst_normalized_rmse_so_far:
            worst_normalized_rmse_so_far = normalized_rmse
        file.write(f"{upperbound_logarithms[i]}: ")
        for predict_x in linear_regressor.predict(predict_x_vals):
            file.write(f"{round(predict_x, 2)}, ")
        file.write("\n")

    #opti GM17
    file.write("\nOPT GM17\n")
    for i in range(4):
        x = np.array(parties).reshape(-1,1)
        y = np.array(time_per_party_gm17_optimized[i])
        linear_regressor = LinearRegression()
        linear_regressor.fit(x, y)
        
        y_pred = linear_regressor.predict(x)

        normalized_rmse = mean_squared_error(y, y_pred, squared=False)/np.mean(y)
        if normalized_rmse > worst_normalized_rmse_so_far:
            worst_normalized_rmse_so_far = normalized_rmse
        file.write(f"{upperbound_logarithms[i]}: ")
        for predict_x in linear_regressor.predict(predict_x_vals):
            file.write(f"{round(predict_x, 2)}, ")
        file.write("\n")

    file.write("\n")
    file.write(f"Worst normalized RMSE: {worst_normalized_rmse_so_far}")