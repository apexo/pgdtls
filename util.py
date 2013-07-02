from reactor import clock

_t0 = clock()

def log(msg):
	dt = int((clock() - _t0) * 1000.0 + 0.5)
	print("%6d %s" % (dt, msg))
