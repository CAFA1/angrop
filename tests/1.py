#coding=utf-8 #coding:utf-8
import angr
#logging.getLogger("angrop").setLevel('DEBUG')
proj = angr.Project("/bin/ls")
state = proj.factory.entry_state()
input = state.solver.BVS('input', 64)
state.solver.add(input < 2**32)
a=state.satisfiable()
print 'ok'
