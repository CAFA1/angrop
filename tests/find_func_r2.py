import os
import subprocess
import r2pipe
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
def get_file_name1(file_dir):
    file_elf=[]
    for root,dirs,files in os.walk(file_dir):
        for file in files:
            out_bytes=subprocess.check_output(['file',os.path.join(root,file)])
            if(out_bytes.find('ELF')!=-1):
                try:
                    out_bytes1=subprocess.check_output('strings '+os.path.join(root,file)+' |grep mybad',shell=True)
                    if(out_bytes1!=''):
                        file_elf.append(out_bytes.split(':')[0])
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
    funcs=get_file_name1('/data/Problems_of_Concept_C_src/LibRaw')
    #funcs1=get_func_elf(funcs,'parse_tiff_ifd')
    print 'ok'