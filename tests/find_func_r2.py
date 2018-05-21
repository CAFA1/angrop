import os
import subprocess
import r2pipe
import sys
#return file name
work_dir='/home/l/Downloads/test/'
def get_file_name(file_dir):
    file_elf=[]
    for root,dirs,files in os.walk(file_dir):
        for file in files:
            out_bytes=subprocess.check_output(['file',os.path.join(root,file)])
            if(out_bytes.find('ELF')!=-1):
                #print out_bytes
                file_elf.append(out_bytes.split(':')[0])
    return file_elf
#return file name
def get_file_name_strings(file_dir):
    #system
    string_interesting='"evil|system|read|recv|popen|hack|exec|setuid|http|send|write"'
    file_elf=[]
    i=0
    for root,dirs,files in os.walk(file_dir):
        for file in files:
            this_file=os.path.join(root,file)
            out_bytes=subprocess.check_output(['file',os.path.join(root,file)])
            #print 'file output:\n'+out_bytes
            if(out_bytes.find('ELF')!=-1 and out_bytes.find('LSB relocatable')==-1):
                try:
                    out_bytes1=subprocess.check_output('strings '+os.path.join(root,file)+' |egrep '+string_interesting,shell=True)
                    print 'string output: '+out_bytes1
                    if(out_bytes1!=''):
                        print 'find file : '+this_file+' !!!!!!' + ' '+str(i)
                        file_elf.append(this_file)
                        i=i+1
                except:
                    pass
    return file_elf
#return the file name which has the func
def get_func_elf(file_name_list,func_name):
    file_elf_func=[]
    for file_tmp in file_name_list:
        r2 = r2pipe.open(file_tmp)
        #axt find reference
        read_str = r2.cmd("aaa;afl |grep "+func_name)
        print read_str
        if(read_str!=''):
            file_elf_func.append(file_tmp)
            print file_tmp
    return file_elf_func



if __name__ == '__main__':
    #main()
    work_dir='/home/l/Downloads/test/'
    if(len(sys.argv)!=2):
        print "python find_func_r2.py dir"
        exit()
    dir1= sys.argv[1]
    dir2=work_dir+dir1
    #string1 = sys.argv[2]
    files_name=get_file_name_strings(dir2)
    for i in range(len(files_name)):
        print i,files_name[i]
    optinstr='which file do you want to test[0-'+str(len(files_name)-1)+']: '
    input_file_int = input(optinstr)
    test_file=files_name[input_file_int]

    cp_cmd = 'python test_cp.py '+test_file+' '+dir1
    os.system(cp_cmd)
    print 'find_func_r2.py ok'