import pylab
import matplotlib.pyplot as plt

def load_data(file_name):
	data_file = open(file_name, 'r')

	file_num = []
	exe_time = []

	for line in data_file:
		tmp = line.split(',')
		file_num.append(tmp[0])
		exe_time.append(tmp[1])

	return (file_num, exe_time)

def plot_data(X, Y, x_label, y_label):
	length = len(Y)

	pylab.figure(1)

	pylab.plot(X, Y, 'rx')
	pylab.xlabel(x_label)
	pylab.ylabel(y_label)

	pylab.show()

(file_num_1bytes, exe_time_1bytes) = load_data('./results/results_1bytes.txt')
(file_num_1kbytes, exe_time_1kbytes) = load_data('./results/results_1kbytes.txt')
(file_num_10kbytes, exe_time_10kbytes) = load_data('./results/results_10kbytes.txt')

(bl_file_num_1bytes, bl_exe_time_1bytes) = load_data('./baseline_results/baseline_results_1bytes.txt')
(bl_file_num_100bytes, bl_exe_time_100bytes) = load_data('./baseline_results/baseline_results_100bytes.txt')
(bl_file_num_1kbytes, bl_exe_time_1kbytes) = load_data('./baseline_results/baseline_results_1kbytes.txt')
(bl_file_num_10kbytes, bl_exe_time_10kbytes) = load_data('./baseline_results/baseline_results_10kbytes.txt')

#plot_data(file_num_1bytes, exe_time_1bytes, 'file number', 'encryption time')
axes = plt.subplot(111)

plt.xlabel('File Numbers')
plt.ylabel('Execution Time (s)')
plt.axis([0, 110, 0.004, 0.25])

# ax.plot(10, 0.2, 'g.', label='1 Byte')
# ax.legend(loc='upper left')


# line1 = plt.plot(file_num_1bytes, exe_time_1bytes, 'g.')
# plt.plot(bl_file_num_1bytes, bl_exe_time_1bytes, 'r.', file_num_1kbytes, exe_time_1kbytes, 'gs', bl_file_num_1kbytes, bl_exe_time_1kbytes, 'rs', file_num_10kbytes, exe_time_10kbytes, 'g^', bl_file_num_10kbytes, bl_exe_time_10kbytes, 'r^')
#
# axes.legend(line1, '1 Byte', loc='upper left')

plt.scatter(file_num_1bytes, exe_time_1bytes, s=50, label='1 B', c='blue', marker='_', alpha=None, edgecolors='white')

plt.scatter(bl_file_num_1bytes, bl_exe_time_1bytes, s=50, label='1 B (baseline)', c='red', marker='_', alpha=None, edgecolors='white')

# plt.scatter(file_num_100bytes, exe_time_100bytes, s=50, label='100 B', c='green', marker='o', alpha=None, edgecolors='white')
#
# plt.scatter(bl_file_num_100bytes, bl_exe_time_100bytes, s=50, label='100 B (baseline)', c='red', marker='o', alpha=None, edgecolors='white')

plt.scatter(file_num_1kbytes, exe_time_1kbytes, s=50, label='1 KB', c='blue', marker='+', alpha=None, edgecolors='white')

plt.scatter(bl_file_num_1kbytes, bl_exe_time_1kbytes, s=50, label='1 KB (baseline)', c='red', marker='+', alpha=None, edgecolors='white')

plt.scatter(file_num_10kbytes, exe_time_10kbytes, s=50, label='10 KB', c='blue', marker='^', alpha=None, edgecolors='white')

plt.scatter(bl_file_num_10kbytes, bl_exe_time_10kbytes, s=50, label='10 KB (baseline)', c='red', marker='^', alpha=None, edgecolors='white')

plt.legend(loc='upper left', fontsize='small')

plt.show()
