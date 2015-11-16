typedef struct ipmaskset
{
uint32_t ip;
unsigned char mask;
} ipmask;
typedef struct map
{
	uint32_t dip;
	unsigned short dport;
	unsigned char maxconn;
	bool allowall;
	ipmask allowedips[MAXALLIPS];
} mapdtype;

typedef struct mapcontainer
{
        unsigned char cmd;
        unsigned short r1;
        unsigned short r2;
	unsigned short port;
	mapdtype map;
} mapcontainerdtype;
