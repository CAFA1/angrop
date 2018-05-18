#!/usr/bin/env python




import os
import r2pipe
import sys
import multiprocessing, time
from time import gmtime, strftime
import copy
#func_name_str
#return func_addr
def get_func_addr(r2,func_name_str):
    #afl list funcs
    funcs_str = r2.cmd("aaa;afl")
    funcs_list=funcs_str.split('\n')
    func_str1=''
    for tmp in funcs_list:
        if(tmp.find(func_name_str)!=-1):
            func_str1=tmp
            break
    if(func_str1!=''):
        func_addr=int(func_str1.split(' ')[0],16)
        return func_addr
    return 0
class Func_open_read:
    def __init__(self,func_name='',call_open_bbl=set(),call_read_bbl=set()):
        self.func_name=func_name
        self.call_open_bbl=call_open_bbl
        self.call_read_bbl=call_read_bbl


#get the functions  which call read
#return list of the functions
def get_ref_open_read(r2):
    # data structure {func_name:Func_open_read}
    funcs_open_read=dict()
    #1. get func name
    #axt find reference
    read_str = r2.cmd("aaa;axt sym.imp.read")
    read_str_list=read_str.split('\n')
    funcs_name=set()
    for tmp in read_str_list:
        funcs_name.add(tmp.split(' ')[0])
        print 'step1 get func_name: '+tmp.split(' ')[0]
    #2. get func call read bbl addr
    for func_name in funcs_name:
        tmpobj=copy.deepcopy(Func_open_read(func_name))
        for tmp in read_str_list:
            tmp_name=tmp.split(' ')[0]
            if(tmp_name==func_name):
                tmp_read=tmp.split(' ')[1]
                #find bbl addrs!!!
                read_str_bbl = r2.cmd("ab "+tmp_read)
                tmpi=read_str_bbl.find('addr: ')
                read_str_bbl_int=int(read_str_bbl[tmpi+6:tmpi+6+10],16)
                tmpobj.call_read_bbl.add(read_str_bbl_int)
        #deepcopy!!!
        funcs_open_read[func_name]=copy.deepcopy(tmpobj)
    #3. get func call open bbl addr
    open_str = r2.cmd("axt sym.imp.open")
    open_str_list=open_str.split('\n')
    for func_name in funcs_name:
        tmpobj=copy.copy(funcs_open_read[func_name])
        for tmp in open_str_list:
            tmp_name=tmp.split(' ')[0]
            if(tmp_name==func_name):
                tmp_open=tmp.split(' ')[1]
                open_str_bbl = r2.cmd("ab "+tmp_open)
                tmpi=open_str_bbl.find('addr: ')
                open_str_bbl_int=int(open_str_bbl[tmpi+6:tmpi+6+10],16)
                tmpobj.call_open_bbl.add(open_str_bbl_int)
    return funcs_open_read

    
def write_file(strmy):
    result_log=open('/data/result.log','a')
    result_log.write(strmy)
    result_log.close()
def write_file_start(strmy):
    result_log=open('/data/result.log','w')
    result_log.write(strmy)
    result_log.close()

def symbolic_execution(project,open_addr,read_addr):
    entry_state = project.factory.blank_state(addr=open_addr)
    pg = project.factory.simgr(entry_state,save_unconstrained=True)
    os.system('rm /data/find_read.flag')

    #symbolic execution until the unconstrained successor
    while len(pg.unconstrained)==0:
        if(os.path.isfile('/data/find_read.flag')):
            print 'execute to read'
            break
        pg.step()

def main(r2,project):

    
    #get the funcs addrs which should be analysed
    funcs_open_read=get_ref_open_read(r2)

    i=0
    for key,func_addr in funcs_open_read.iteritems():
        print 'test function: '+func_addr.func_name
        write_file('test function: '+func_addr.func_name+'\n')
        for open_addr in func_addr.call_open_bbl:
            for read_addr in func_addr.call_read_bbl:
                print str(i)+' symbolic_execution from '+hex(open_addr)+' to '+hex(read_addr)
                write_file('symbolic_execution from '+hex(open_addr)+' to '+hex(read_addr)+'\n')
                i=i+1
                #write_file('\n'+func_addr[1]+' : '+hex(func_addr[0])+'\n')
                pp=multiprocessing.Process(target=symbolic_execution,args=(project,open_addr,read_addr))
                pp.start()
                print strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
                #3 mimutes
                pp.join(60*3)
                print strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
                pp.terminate()
                time.sleep(1)
                #print pp, pp.is_alive()







if __name__ == '__main__':
    sys.path.insert(0,'/home/l/Downloads/angrop')
    #print sys.path
    import angr
    if(len(sys.argv)!=2):
        print "python test_read.py file_name"

    file_name_arg=sys.argv[1]
    project= angr.Project(file_name_arg)
    r2 = r2pipe.open(file_name_arg)
    #open result log file
    write_file_start('start test '+file_name_arg+'\n')

    main(r2,project)
    #get_ref_open_read(r2)

    print 'ok main'


