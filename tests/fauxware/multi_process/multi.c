#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>



int main(int argc, char **argv)
{
	char username[9];
	
	int pid;

	username[8] = 0;
	
	if(pid=fork())
	{
		printf("parent: \n");
		read(0, username, 8);
		if(strcmp(username,"sneakey"))
		{
			printf("sneakey\n");
		}
	}else{
		printf("child: \n");
		read(0, username, 8);
		if(strcmp(username,"snooby"))
		{
			printf("snooby\n");
		}
	}
	
	

	
}
