#cp the elf to windows for analysis
import os
import sys

if __name__ == '__main__':
    
    if(len(sys.argv)!=2):
        print "python test_cp.py files_name\neg:python test_cp.py ~/Downloads/test/p_17//test_xcb_image_shm"
        #
        exit()
    file_name_path= sys.argv[1]
    file_base_name=os.path.basename(file_name_path)
    p_dir_str=os.path.dirname(file_name_path).split('/')[-1]
    mnt_dir='/mnt/hgfs/test1/install_dir/'+p_dir_str+'/'
    mnt_file_name=mnt_dir+file_base_name
    try:
    	os.makedirs(mnt_dir,0777)
    except:
    	print 'dir already exists.'
    os.system('cp '+file_name_path+' '+mnt_dir)
    print 'python test_read.py '+mnt_file_name
    
    print 'ok'