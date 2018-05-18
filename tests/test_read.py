#!/usr/bin/env python




import os
import r2pipe
import sys
import multiprocessing, time
from time import gmtime, strftime
import copy

def find_call_func_addr(r2,file_name_arg,func_name):
    #sym._b60293298036c511146dbe64f815cc65.constprop.1 0x401662 [CALL] call sym.imp.popen
    popen_str = r2.cmd("axt "+func_name)
    popen_str_list=popen_str.split('\n')
    my_open_addr_f=open('/mnt/hgfs/test1/addrs/'+os.path.basename(file_name_arg)+'.'+func_name.split('.')[-1],'w')
    tmp_set=set()
    for tmp in popen_str_list:
        if(tmp.find('[CALL]')==-1):
            break
        popen_func=tmp.split(' ')[0]
        popen_addr= r2.cmd('afl|grep '+popen_func).split(' ')[0]
        if(popen_addr not in tmp_set):
            tmp_set.add(popen_addr)
            print popen_addr
            my_open_addr_f.write(popen_addr+' '+popen_func+'\n')
    my_open_addr_f.close()




if __name__ == '__main__':
    
    if(len(sys.argv)!=2):
        print "python test_read.py file_name"

    file_name_arg=sys.argv[1]
    
    r2 = r2pipe.open(file_name_arg)
    r2.cmd("aaa;")
    
    print 'popen:'
    #find_popen(r2,file_name_arg)
    find_call_func_addr(r2,file_name_arg,'sym.imp.popen')
    print 'system:'
    #find_system(r2,file_name_arg)
    find_call_func_addr(r2,file_name_arg,'sym.imp.system')
    print 'recv'
    #find_recv(r2,file_name_arg)
    find_call_func_addr(r2,file_name_arg,'sym.imp.recv')
    print 'ok main'


