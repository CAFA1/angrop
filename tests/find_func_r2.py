import os
import subprocess
import r2pipe
import sys
#return file name
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
    string_interesting='"evil|system|read|recv|popen"'
    file_elf=[]
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
                        print 'find file : '+this_file+' !!!!!!'
                        file_elf.append(this_file)
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
    if(len(sys.argv)!=2):
        print "python find_func_r2.py dir"
        exit()
    dir1= sys.argv[1]
    #string1 = sys.argv[2]
    files_name=get_file_name_strings(dir1)
    
    #funcs1=get_func_elf(funcs,'parse_tiff_ifd')
    print 'ok'