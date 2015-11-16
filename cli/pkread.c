#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include "../pkt/settings.h"
#include "../pkt/map.h"

int readport(unsigned short p){
	int numread=0;
    char buf[1024];
	FILE *fp,*fr;
	mapcontainerdtype cont;
	cont.cmd=11;
	cont.r1 = p;
	
	fp=fopen("/proc/pktab","wb");
	if(fp){
		fwrite(&cont,sizeof(mapcontainerdtype),1,fp);
        fclose(fp);
	}
	else{printf("Unable to write on /proc/pktab \n");return -1;}
	fr=fopen("/proc/pktab","r");
	if(fr){
		buf[fread(buf,1,1024,fr)]='\0';
		fclose(fr);
		printf("%s",buf);
		
	}
	else {printf("Unable to Read /proc/pktab \n");return -1;}
}
int main (int argc, char *argv[])
{
	unsigned short r1,r2,tmp,i;
	r1 = atoi(argv[1]);
	r2 = atoi(argv[2]);
	if (r1>r2) {tmp=r1;r1=r2;r2=tmp;}
	for(i = r1;i<=r2;i++) readport(i);

  return 0;
}
