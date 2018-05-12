import multiprocessing, time,signal
from time import gmtime, strftime
p = multiprocessing.Process(target=time.sleep, args=(1000,))
print p, p.is_alive()

p.start()
print p, p.is_alive()
print strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
p.join(10)
print strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
p.terminate()
time.sleep(0.1)
print p, p.is_alive()

print p.exitcode
