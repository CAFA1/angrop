#!/usr/bin/env python



import angr
import os
import r2pipe
import sys
import multiprocessing, time
from time import gmtime, strftime
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
#get the functions  which call read
#return list of the functions
def get_ref_funcs(file_name_arg):
    r2 = r2pipe.open(file_name_arg)
    #axt find reference
    read_str = r2.cmd("aaa;axt sym.imp.read")
    read_str_list=read_str.split('\n')
    funcs_name=[]
    funcs_addr=[]
    for tmp in read_str_list:
        funcs_name.append(tmp.split(' ')[0])
        print tmp.split(' ')[0]

    for tmp in funcs_name:
        funcs_addr.append((get_func_addr(r2,tmp),tmp))
        #print hex(get_func_addr(r2,tmp))
    return funcs_addr

def symbolic_execution(project,func_addr,result_log):
    entry_state = project.factory.blank_state(addr=func_addr[0])
    pg = project.factory.simgr(entry_state,save_unconstrained=True)
    os.system('rm /tmp/find_read.flag')

    #symbolic execution until the unconstrained successor
    while len(pg.unconstrained)==0:
        if(os.path.isfile('/tmp/find_read.flag')):
            #log every file name
            tmp_file=open('/tmp/find_read.flag','r')
            result_log.write(tmp_file.read())
            tmp_file.close()
            result_log.write('\nmalware!\n')
            break
        pg.step()

def main(file_name_arg):
    #open result log file
    result_log=open('./result.log','w')
    #get the funcs addrs which should be analysed
    func_addr_list=get_ref_funcs(file_name_arg)
    project= angr.Project(file_name_arg)
    i=0
    for func_addr in func_addr_list:
        i=i+1
        print str(i)+'/'+str(len(func_addr_list))+' '+func_addr[1]+' : '+hex(func_addr[0])
        result_log.write(func_addr[1]+' : '+hex(func_addr[0]))
        pp=multiprocessing.Process(target=symbolic_execution,args=(project,func_addr,result_log))
        pp.start()
        print strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
        #3 mimutes
        pp.join(60*3)
        print strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
        pp.terminate()
        time.sleep(0.1)
        print pp, pp.is_alive()
    result_log.close()







if __name__ == '__main__':
    if(len(sys.argv)!=2):
        print "python test_read.py file_name"
    main(sys.argv[1])

    print 'ok main'


