import pylab
import matplotlib.pyplot as plt

def load_data(file_name):
	data_file = open(file_name, 'r')

	pt_len = []
	ct_len = []
	enc_t = []
	dec_t = []
	re_t = []

	for line in data_file:
		tmp = line.split(',')
		pt_len.append(tmp[0])
		ct_len.append(tmp[1])
		enc_t.append(tmp[2])
		dec_t.append(tmp[3])
		re_t.append(tmp[4])

	return (pt_len, ct_len, enc_t, dec_t, re_t)

def plot_data(X, Y, x_label, y_label):
	length = len(Y)

	pylab.figure(1)

	pylab.plot(X, Y, 'rx')
	pylab.xlabel(x_label)
	pylab.ylabel(y_label)

	pylab.show()

(pt_len, ct_len, enc_t, dec_t, re_t) = load_data('../results/1.txt')
#plot_data(pt_len, enc_t, 'plaintext length', 'encryption time')
plt.plot(pt_len, enc_t, 'ro', pt_len, dec_t, 'bs', pt_len, re_t, 'g^')
plt.show()
