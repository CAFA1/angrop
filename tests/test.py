import angr, angrop
import logging
logging.getLogger("angrop").setLevel('DEBUG')
p = angr.Project("/bin/ls")
rop = p.analyses.ROP()
rop.find_gadgets()
chain = rop.set_regs(rax=0x1337, rbx=0x56565656)
chain.payload_str()
#'\xb32@\x00\x00\x00\x00\x007\x13\x00\x00\x00\x00\x00\x00\xa1\x18@\x00\x00\x00\x00\x00VVVV\x00\x00\x00\x00'
chain.print_payload_code()