import angr, angrop
import logging
#logging.getLogger("angrop").setLevel('DEBUG')
p = angr.Project("sample_elf/test_elf")
cfg=p.analyses.CFGFast(force_complete_scan=False,show_progressbar=False)
print 'ok'
'''
rop = p.analyses.ROP()
rop.find_gadgets()
#chain = rop.set_regs(rax=0x1337, rbx=0x56565656)
chain = rop.write_to_mem(addr=0x400,string_data='/bin/sh')
chain.payload_str()
#'\xb32@\x00\x00\x00\x00\x007\x13\x00\x00\x00\x00\x00\x00\xa1\x18@\x00\x00\x00\x00\x00VVVV\x00\x00\x00\x00'
chain.print_payload_code()
'''