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

(file_num, exe_time) = load_data('./results.txt')
plot_data(file_num, exe_time, 'file number', 'encryption time')
#plt.plot(file_num, exe_time, 'ro')
plt.show()
