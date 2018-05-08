#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>







int main(int argc, char **argv)
{
	char username[9];
	char password[9];
	int authed;

	username[8] = 0;


	printf("Username: \n");
	read(0, username, 8);
	if(username[0]=='1')
	{
	    if(username[1]=='2')
	    {
	        printf("12\n");
	    }
	    else{
	        printf("1x\n");
	    }
	}
	else{
	    if(username[1]=='3')
	    {
	        printf("x3\n");
	    }
	    else{
	        printf("xx\n");
	    }
	}
}
