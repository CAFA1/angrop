#!/usr/bin/env python



import angr
import os
import r2pipe



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
def get_ref_funcs():
    r2 = r2pipe.open("sample_elf/test_elf")
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


def main():
    #open result log file
    result_log=open('./result.log','w')
    #get the funcs addrs which should be analysed
    func_addr_list=get_ref_funcs()
    project= angr.Project("sample_elf/test_elf")
    for func_addr in func_addr_list:
        print func_addr[1]+' : '+hex(func_addr[0])
        result_log.write(func_addr[1]+' : '+hex(func_addr[0]))
        #symbolic execution from the func addr
        entry_state =  project.factory.blank_state(addr=func_addr[0])
        pg = project.factory.simgr(entry_state,save_unconstrained=True)
        os.system('rm /tmp/find_read.flag')
        findflag=0
        #symbolic execution until the unconstrained successor
        while len(pg.unconstrained)==0:
            if(os.path.isfile('/tmp/find_read.flag')):
                result_log.write(' malware!\n')
                findflag=1
                break
            pg.step()
        #if(len(pg.unconstrained)!=0):
        #    unconstrained_path = pg.unconstrained[0]
    result_log.close()







if __name__ == '__main__':
    main()

    print 'ok main'


