#include "stdio.h"
#include "stdlib.h"
#include "string.h"

void func2()
{
	 
	asm ("xchg %%rsp,%%rax;ret" 
	      :::
	    ); 
	asm ("pop %%rax;ret" 
	      :::
	    ); 
	asm ("pop %%rdi;ret" 
	      :::
	    ); 
	asm ("pop %%rsi;ret" 
	      :::
	    ); 
	asm ("pop %%rdx;ret" 
	      :::
	    ); 
	asm ("pop %%rcx;ret" 
	      :::
	    ); 
	asm ("pop %%rbx;ret" 
	      :::
	    ); 

}
int main(int argc,char*argv[])
{
	printf("hello world!\n");
}