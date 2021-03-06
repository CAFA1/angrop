import angr
from angr.sim_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# read
######################################
def write_file(strmy):
    result_log=open('/data/result.log','a')
    result_log.write(strmy)
    result_log.close()
class read(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length):
        self.argument_types = {0: SimTypeFd(),
                               1: self.ty_ptr(SimTypeArray(SimTypeChar(), length)),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = SimTypeLength(self.state.arch)

        # TODO handle errors
        length = self.state.posix.read(fd, dst, length)
        filename=self.state.posix.get_file(fd)
        #filter read passwd file
        if(filename.name.find('passwd')!=-1 or 1):
            print filename.name+' !!!'
            #print "test!!!!"
            fff=open('/data/find_read.flag','w')
            fff.close()
            write_file('read file name: '+filename.name+'\n')



        return length
