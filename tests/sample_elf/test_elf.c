#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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
    asm ("pop %%rsp;xchg %%rax,%%rsp;ret"
      :::
    );
     asm ("pop %%rax;xchg %%rax,%%rsp;ret"
      :::
    );

}
void func_test()
{
    int fd;
    char buff[500];
    fd=open("/etc/passwd",O_RDONLY);
	read(fd,buff,500);
	printf("%s\n",buff);
}
void func_test1()
{
    int fd;
    char buff[500];
    fd=open("/etc/passwd",O_RDONLY);
	read(fd,buff,500);
	printf("%s\n",buff);
}
int main(int argc,char*argv[])
{
	int a=1;


	scanf("%d",&a);
	if(a==1)
		printf("hello world!\n");
	else
		printf("hello\n");
	func_test();


	return 1;
}