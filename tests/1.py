#coding=utf-8 #coding:utf-8
import angr
#logging.getLogger("angrop").setLevel('DEBUG')
p = angr.Project("/bin/ls")
irsb = p.factory.block(0x4022cd)
irsb_n=irsb.vex.next
'''
.init:00000000004022CD                 add     rsp, 8
.init:00000000004022D1                 retn
'''
print 'ok'