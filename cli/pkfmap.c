#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include "../pkt/settings.h"
#include "../pkt/map.h"
#define d(...) printf(__VA_ARGS__)

uint32_t QUADIP(unsigned int a,unsigned int b,unsigned int c,unsigned int d)
{
  return (a+(b*256)+(c*65536)+(d*16777216U));
}

void strtoip(char * s,uint32_t * ip,unsigned char * mask)
{
  int i,coctet,itr;char buf[5][4];
  coctet=0;
  itr=0;
  for(i=0;i<18;i++)
  {
    if(s[i]=='\0') {buf[coctet][itr]='\0';break;}
    if(s[i]=='.' || s[i]=='/') {buf[coctet++][itr]='\0';itr=0;}
    else
    {
       buf[coctet][itr++] = s[i];
    }
  }
  if (coctet <4){buf[4][0]='3';buf[4][1]='2';buf[4][2]='\0';}
  *ip =  QUADIP(atoi(buf[0]),atoi(buf[1]),atoi(buf[2]),atoi(buf[3]));

  *mask = atoi(buf[4]);
  if(atoi(buf[4])>32) *mask = 32;  //check if invalid mask(>32) provided
}

int main (int argc, char *argv[])
{
  int i,j;
  unsigned short rangestart,rangeend,temp;
  uint32_t ipholder;
  unsigned char maskholder;
  size_t len = 0;
  ssize_t read;
  char * line = NULL;
  int lineargc;
  char * lineargv[MAXALLIPS + 5];
  mapcontainerdtype cont;
  FILE *fp,*fin;
  bool clearwritten = true;

  for(j=0;j<argc;j++){
    if(argv[j][0] == '-' && argv[j][1] == 'c') {
        if(argc<j+3) {d("ERROR: -c option should be followed by two parameters RANGE_START RANGE_END\n");return;}
        rangestart = atoi(argv[j+1]);
        rangeend = atoi(argv[j+2]);
        if(rangeend < rangestart) {temp = rangestart;rangestart = rangeend;rangeend=temp;}

        clearwritten=false;
    }
  }

  if(argc < 2) {d("Provide Input File\n");return 0;}
  if((fin=fopen(argv[1],"r")) == NULL)
      d("Unable to Read Input File %s\n",argv[1]);
  else
  {
     while ((read = getline(&line, &len, fin)) != -1) {
       if(len<5) {d("Corrupt Line..Ignoring\n");continue;}
       lineargc=1;
       lineargv[0] = line;
       j=0;
       while(line[j] != '\0'){if(line[j]==' '){line[j]=0;lineargv[lineargc++]=&line[j+1];}j++;}
	   fp=fopen("/proc/pktab","wb");
       if(fp!=NULL){
           memset(&cont,0,sizeof(mapcontainerdtype));
           if(!clearwritten){cont.cmd=255;cont.r1 = rangestart;cont.r2=rangeend;clearwritten = true;}
           cont.port = atoi(lineargv[0]);
           strtoip(lineargv[1],&ipholder,&maskholder);
           cont.map.dip = ipholder;
           cont.map.dport = atoi(lineargv[2]);
           cont.map.maxconn = atoi(lineargv[3]);
		   if(lineargc> (MAXALLIPS+5)){printf("FATAL ERROR: Port %u has more than %d IPs allowed\n",cont.port,MAXALLIPS);}
           if(lineargc>5){
                for (i=5; i< lineargc; i++) {
                    strtoip(lineargv[i],&ipholder,&maskholder);
                    cont.map.allowedips[i-5].ip = ipholder;
                    cont.map.allowedips[i-5].mask = maskholder;
                }
           }
           fwrite(&cont,sizeof(mapcontainerdtype),1,fp);
           fclose(fp);
       }else{d("Unable to write on /proc/pktab \n");fclose(fin);return -1;}
     }
     fclose(fin);
  }

  return 0;
}
