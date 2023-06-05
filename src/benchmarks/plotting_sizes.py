import matplotlib.pyplot as plt
import csv

bounds = ["$2^{8}-1$", "$2^{16}-1$", "$2^{32}-1$", "$2^{64}-1$"]
comp_sizes = []
opti_sizes = []
gm17_comp_sizes = []
gm17_opti_sizes = []

with open('data/signature_sizes.csv','r') as csvfile:
    lines = csv.reader(csvfile, delimiter=',')
    for row in lines:
     comp_sizes.append(float(row[0]))
     opti_sizes.append(float(row[1]))
     gm17_comp_sizes.append(float(row[2]))
     gm17_opti_sizes.append(float(row[3]))


plt.plot(bounds, comp_sizes, color = 'r', linestyle = 'solid', marker = 'o',label = "COMP BPRP")
plt.plot(bounds, opti_sizes, color = 'b', linestyle = 'solid', marker = 'x',label = "OPT BPRP")
plt.plot(bounds, gm17_comp_sizes, color = 'g', linestyle = 'solid', marker = 'D',label = "COMP GM17")
plt.plot(bounds, gm17_opti_sizes, color = 'indigo', linestyle = 'solid', marker = '^',label = "OPT GM17")
plt.xlabel('Upperbounds')
plt.ylabel('size in bytes')
plt.grid()
plt.legend()
plt.savefig(f'plots/sizes/sizes.png', dpi=300)
plt.clf()