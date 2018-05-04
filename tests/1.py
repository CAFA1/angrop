#coding=utf-8 #coding:utf-8
#pyvex test
import angr
import pyvex
import archinfo
proj = angr.Project("/bin/ls")
state = proj.factory.entry_state()
irsb=proj.factory.block(0x4022cd)

print 'ok'
