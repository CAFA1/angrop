import os
def call_ropgadget(binary):
    os.system('python ../ROPgadget/ROPgadget.py --nojop --binary '+binary+' >ropgadget.log')
    file_log=open('./ropgadget.log','r')
    lines=file_log.readlines()
    file_log.close()
    gadgets=[]
    for line in lines:
        if(line.find(':')!=-1):
            try:
                gadgets.append(int(line.split(':')[0],16))
            except:
                print 'warning: ropgadget  convert line : '+line
    #for i in gadgets:
    #    print hex(i)
    return gadgets
call_ropgadget('sample_elf/test_elf')