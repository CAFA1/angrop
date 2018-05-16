import multiprocessing, time,signal
from time import gmtime, strftime
from multiprocessing import Pool
import progressbar
def test1():
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
def run_worker(addr):
    print multiprocessing.current_process()
    print "Analyzing "+str(addr)
    time.sleep(1)
    return addr
def test2():
    def _addresses_to_check_with_caching(analysis_tuples,show_progress=True):
        num_addrs = len(analysis_tuples)
        widgets = ['ROP: ', progressbar.Percentage(), ' ',
                   progressbar.Bar(marker=progressbar.RotatingMarker()),
                   ' ', progressbar.ETA(), ' ', progressbar.FileTransferSpeed()]
        progress = progressbar.ProgressBar(widgets=widgets, maxval=num_addrs)
        if show_progress:
            progress.start()

        for i, a in enumerate(analysis_tuples):
            if show_progress:
                progress.update(i)
            print a
            yield a
        if show_progress:
            progress.finish()

    #:param processes: number of processes to use
    #If initializer is not None then each worker process will call initializer(*initargs) when it starts.
    pool = Pool(processes=3)
    analysis_tuples=range(100)
    it = pool.imap_unordered(run_worker, _addresses_to_check_with_caching(analysis_tuples), chunksize=5)
    for i in it:
        print i

    pool.close()
test2()