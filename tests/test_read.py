#!/usr/bin/env python




import os
import r2pipe
import sys
import multiprocessing, time
from time import gmtime, strftime
import copy
mnt_dir='/mnt/hgfs/test1/'
def find_call_func_addr(p_dir,r2,file_name_arg,func_name):
    global mnt_dir
    #sym._b60293298036c511146dbe64f815cc65.constprop.1 0x401662 [CALL] call sym.imp.popen
    popen_str = r2.cmd("axt "+func_name)
    print popen_str
    popen_str_list=popen_str.split('\n')
    base_name=os.path.basename(file_name_arg)
    #p_dir=os.path.dirname(file_name_arg).split('/')[-1]+'/'
    mnt_p_dir=mnt_dir+'addrs/'+p_dir+'/'
    try:
        os.system('mkdir '+mnt_p_dir)
    except:
        print 'dir already exists.' 

    my_open_addr_f=open(mnt_p_dir+base_name+'.'+func_name.split('.')[-1],'w')
    tmp_set=set()
    for tmp in popen_str_list:
        if(tmp.find('[CALL]')==-1):
            break
        popen_func=tmp.split(' ')[0]
        popen_addr_cmd= r2.cmd('afl|grep '+'" '+popen_func+'"')
        print popen_addr_cmd
        popen_addr_cmd_list=popen_addr_cmd.split('\n')
        which_func_int=0
        if(len(popen_addr_cmd_list)>1):
            for i in range(len(popen_addr_cmd_list)):
                print i,popen_addr_cmd_list[i]
            which_func_int=input('which func[0-'+str(len(popen_addr_cmd_list)-1)+']: ')
        popen_addr_cmd=popen_addr_cmd_list[which_func_int]
        popen_addr=popen_addr_cmd.split(' ')[0]
        if(popen_addr not in tmp_set):
            tmp_set.add(popen_addr)
            print popen_addr,popen_func
            my_open_addr_f.write(popen_addr+' '+popen_func+'\n')
    my_open_addr_f.close()




if __name__ == '__main__':
    
    if(len(sys.argv)!=3):
        print "python test_read.py file_name p_dir"

    file_name_arg=sys.argv[1]
    p_dir=sys.argv[2]
    r2 = r2pipe.open(file_name_arg)
    r2.cmd("aaa;")
    
    print 'popen:'
    #find_popen(r2,file_name_arg)
    find_call_func_addr(p_dir,r2,file_name_arg,'sym.imp.popen')
    print 'system:'
    #find_system(r2,file_name_arg)
    find_call_func_addr(p_dir,r2,file_name_arg,'sym.imp.system')
    print 'recv'
    #find_recv(r2,file_name_arg)
    find_call_func_addr(p_dir,r2,file_name_arg,'sym.imp.recv')
    print 'read'
    find_call_func_addr(p_dir,r2,file_name_arg,'sym.imp.read')
    print 'execl'
    find_call_func_addr(p_dir,r2,file_name_arg,'sym.imp.execl')

    base_name=os.path.basename(file_name_arg)
    print "windows:!!!!!\ncd /d D:\\source\\idapython\npython test.py D:\\source\\test1\\install_dir\\"+p_dir+'\\'+base_name
    print 'test_read.py ok '


