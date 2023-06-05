import matplotlib.patches as mpatches
import matplotlib.lines as mlines
import matplotlib.pyplot as plt
import numpy as np
import csv
import re
import pandas as pd

bounds = ["$2^{8}-1$","$2^{16}-1$","$2^{32}-1$","$2^{64}-1$"]
time_comp_sign = []
time_comp_ver = []
time_opt_sign_and_session_auth = []
time_opt_ver = []

time_gm17_comp_sign = []
time_gm17_comp_ver = []
time_gm17_opt_sign_and_session_auth = []
time_gm17_opt_ver = []

with open('data/sign_and_verify_outputs.csv','r') as csvfile:
    lines = csv.reader(csvfile, delimiter=',')
    for row in lines:
        time_comp_sign.append(float(row[1])/1e6)
        time_comp_ver.append(float(row[2])/1e6)
        time_opt_sign_and_session_auth.append(float(row[3])/1e6)
        time_opt_ver.append(float(row[4])/1e6)
        time_gm17_comp_sign.append(float(row[5])/1e6)
        time_gm17_comp_ver.append(float(row[6])/1e6)
        time_gm17_opt_sign_and_session_auth.append(float(row[7])/1e6)
        time_gm17_opt_ver.append(float(row[8])/1e6)

barWidth = 0.125
br1 = np.arange(len(bounds))
br2 = [x + barWidth for x in br1]
br3 = [x + 2*barWidth for x in br1]
br4 = [x + 3*barWidth for x in br1]

#plot sign and session auth (BPRP and GM17)
plt.bar(br1, time_comp_sign, color ='r', width = barWidth,
        edgecolor ='grey', label ='COMP BPRP')
plt.bar(br2, time_opt_sign_and_session_auth, color ='b', width = barWidth,
        edgecolor ='grey', label ='OPT BPRP')
plt.bar(br3, time_gm17_comp_sign, color ='g', width = barWidth,
        edgecolor ='grey', label ='COMP GM17')
plt.bar(br4, time_gm17_opt_sign_and_session_auth, color ='y', width = barWidth,
        edgecolor ='grey', label ='OPT GM17')
 
plt.xlabel('Upperbounds')
plt.ylabel('Time in milliseconds (ms)')
plt.xticks([r + barWidth for r in range(len(bounds))],
        bounds)

plt.legend(loc='center')
plt.savefig(f'plots/sign_and_session_auth_times/sign_and_session_auth.png', dpi=300)
plt.clf()


#plot verification times
plt.bar(br1, time_comp_ver, color ='r', width = barWidth,
        edgecolor ='grey', label ='COMP BPRP')
plt.bar(br2, time_opt_ver, color ='b', width = barWidth,
        edgecolor ='grey', label ='OPT BPRP')
plt.bar(br3, time_gm17_comp_ver, color ='g', width = barWidth,
        edgecolor ='grey', label ='COMP GM17')
plt.bar(br4, time_gm17_opt_ver, color ='y', width = barWidth,
        edgecolor ='grey', label ='OPT GM17')

plt.xlabel('Upperbounds')
plt.ylabel('Time in milliseconds (ms)')
plt.xticks([r + barWidth for r in range(len(bounds))],
        bounds)
plt.yticks([0,5,10,15,20,25,30,35,40,45])
plt.legend()
plt.savefig(f'plots/verification_times/verification_plot.png', dpi=300)
plt.clf()


#plot signing versus verification times
markers = ['o', 'x', 'D', '^']
markersize = 35
marker_legend_size = 8
dot = mlines.Line2D([], [], color="black", marker='o', linestyle='None', markersize=marker_legend_size, label='n=8')
cross = mlines.Line2D([], [], color="black", marker='x', linestyle='None', markersize=marker_legend_size, label='n=16')
diamond = mlines.Line2D([], [], color="black", marker='D', linestyle='None', markersize=marker_legend_size, label='n=32')
triangle = mlines.Line2D([], [], color="black", marker='^', linestyle='None', markersize=marker_legend_size, label='n=64')

#BPRP
for i in range(4):
        plt.scatter(time_comp_sign[i], time_comp_ver[i], color='r', label = 'COMP BPRP', marker=markers[i], s=markersize)
        plt.scatter(time_opt_sign_and_session_auth[i], time_opt_ver[i], color='b', label = 'OPT BPRP', marker=markers[i], s=markersize)
plt.plot(time_comp_sign, time_comp_ver, color='r', zorder=0)
plt.plot(time_opt_sign_and_session_auth, time_opt_ver, color='b', zorder=0)
red_patch = mpatches.Patch(color='red', label='COMP BPRP')
blue_patch = mpatches.Patch(color='blue', label='OPT BPRP')
plt.legend(handles=[red_patch, blue_patch, dot, cross, diamond, triangle])
plt.xlabel('Signature creation time in milliseconds (ms)')
plt.ylabel('Signature verification time in milliseconds (ms)')
plt.savefig(f'plots/sign_vs_verification_times/sign_vs_verification_plot_bprp.png', dpi=300)
plt.clf()

#GM17
for i in range(4):
        plt.scatter(time_gm17_comp_sign[i], time_gm17_comp_ver[i], color='g', label = 'COMP GM17', marker=markers[i], s=markersize)
        plt.scatter(time_gm17_opt_sign_and_session_auth[i], time_gm17_opt_ver[i], color='y', label = 'OPT GM17', marker=markers[i], s=markersize)
plt.plot(time_gm17_comp_sign, time_gm17_comp_ver, color='g', zorder=0)
plt.plot(time_gm17_opt_sign_and_session_auth, time_gm17_opt_ver, color='y', zorder=0)
green_patch = mpatches.Patch(color='green', label='COMP GM17')
yellow_patch = mpatches.Patch(color='yellow', label='OPT GM17')
plt.legend(loc='center', handles=[green_patch, yellow_patch, dot, cross, diamond, triangle])
plt.xlabel('Signature creation time in milliseconds (ms)')
plt.ylabel('Signature verification time in milliseconds (ms)')
plt.savefig(f'plots/sign_vs_verification_times/sign_vs_verification_plot_gm17.png', dpi=300)
plt.clf()



################################Plotting all data points################################
data_points_grouped_by_upperbound = [[],[],[],[]]
with open('data/all_sign_and_verify_data.txt','r') as file:
      lines = file.readlines()
      index = 0
      for line in lines:
                stripped_line = re.sub('\n', '', line).strip()
                if line[0] == 'U':
                        if stripped_line.split(":")[1] != "255":
                                index += 1
                else:
                        data_points_grouped_by_upperbound[index].append(stripped_line.split(","))

data_points_grouped_by_upperbound = [[[float(x)/1e6 for x in inner_list] for inner_list in lst] for lst in data_points_grouped_by_upperbound]

colors = ['r', 'b', 'g', 'y']
shapes = ['o', 'x']   

#n=8
data_points_grouped_by_type_255 = list(list(zip(*data_points_grouped_by_upperbound[0])))
time_255_sig = []
time_255_ver = []
for i in range(4):
        time_255_sig.append(list(data_points_grouped_by_type_255[i*2]))
        time_255_ver.append(list(data_points_grouped_by_type_255[i*2+1]))

df = pd.DataFrame(time_255_sig[0:2], index=["COMP BPRP", "OPT BPRP"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature creation time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_sig[3:5], index=["COMP GM17", "OPT GM17"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature creation time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_ver[0:2], index=["COMP BPRP", "OPT BPRP"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature verification time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_ver[3:5], index=["COMP GM17", "OPT GM17"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature verification time")
plt.subplots_adjust(left=0.25)
plt.show()

#n=16
data_points_grouped_by_type_255 = list(list(zip(*data_points_grouped_by_upperbound[1])))
time_255_sig = []
time_255_ver = []
for i in range(4):
        time_255_sig.append(list(data_points_grouped_by_type_255[i*2]))
        time_255_ver.append(list(data_points_grouped_by_type_255[i*2+1]))

df = pd.DataFrame(time_255_sig[0:2], index=["COMP BPRP", "OPT BPRP"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature creation time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_sig[3:5], index=["COMP GM17", "OPT GM17"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature creation time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_ver[0:2], index=["COMP BPRP", "OPT BPRP"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature verification time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_ver[3:5], index=["COMP GM17", "OPT GM17"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature verification time")
plt.subplots_adjust(left=0.25)
plt.show()

#n=32
data_points_grouped_by_type_255 = list(list(zip(*data_points_grouped_by_upperbound[2])))
time_255_sig = []
time_255_ver = []
for i in range(4):
        time_255_sig.append(list(data_points_grouped_by_type_255[i*2]))
        time_255_ver.append(list(data_points_grouped_by_type_255[i*2+1]))

df = pd.DataFrame(time_255_sig[0:2], index=["COMP BPRP", "OPT BPRP"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature creation time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_sig[3:5], index=["COMP GM17", "OPT GM17"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature creation time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_ver[0:2], index=["COMP BPRP", "OPT BPRP"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature verification time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_ver[3:5], index=["COMP GM17", "OPT GM17"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature verification time")
plt.subplots_adjust(left=0.25)
plt.show()

#n=64
data_points_grouped_by_type_255 = list(list(zip(*data_points_grouped_by_upperbound[3])))
time_255_sig = []
time_255_ver = []
for i in range(4):
        time_255_sig.append(list(data_points_grouped_by_type_255[i*2]))
        time_255_ver.append(list(data_points_grouped_by_type_255[i*2+1]))

df = pd.DataFrame(time_255_sig[0:2], index=["COMP BPRP", "OPT BPRP"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature creation time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_sig[3:5], index=["COMP GM17", "OPT GM17"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature creation time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_ver[0:2], index=["COMP BPRP", "OPT BPRP"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature verification time")
plt.subplots_adjust(left=0.25)
plt.show()

df = pd.DataFrame(time_255_ver[3:5], index=["COMP GM17", "OPT GM17"])
df.T.boxplot(vert=False, sym='')
plt.xlabel("Signature verification time")
plt.subplots_adjust(left=0.25)
plt.show()