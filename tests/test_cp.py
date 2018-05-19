#cp the elf to windows for analysis
import os
import sys

if __name__ == '__main__':
    
    if(len(sys.argv)!=3):
        print "python test_cp.py files_name p_dir\neg:python test_cp.py ~/Downloads/test/p_17//test_xcb_image_shm p_17"
        #
        exit()
    file_name_path= sys.argv[1]
    p_dir_str=sys.argv[2]

    file_base_name=os.path.basename(file_name_path)
    
    mnt_dir='/mnt/hgfs/test1/install_dir/'+p_dir_str+'/'
    mnt_file_name=mnt_dir+file_base_name
    try:
    	os.makedirs(mnt_dir,0777)
    except:
    	print 'dir already exists.'
    cp_cmd='cp '+file_name_path+' '+mnt_dir
    print cp_cmd
    os.system('cp '+file_name_path+' '+mnt_dir)
    get_test_func_cmd = 'python test_read.py '+mnt_file_name+' '+p_dir_str
    print get_test_func_cmd
    os.system(get_test_func_cmd)
    print 'test_cp.py ok'