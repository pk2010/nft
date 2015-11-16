#define NIPQUAD(addr) ((unsigned char *)&addr)[0],((unsigned char *)&addr)[1],((unsigned char *)&addr)[2],((unsigned char *)&addr)[3]
#define LBOUND 1001  //Servers can listen on ports 1 to LBOUND
#define UBOUND 65000 // Write Everything else i.e. 65001 to 65535 as ephemeral port range in /proc/sys/net/ipv4/ip_local_port_range.Used for outgoing conxn
#define TOTALPORTS 65536 //TCP has 1-65535 but our array is larger to ignore member[0]use member[1-65535] for corresponding ports
#define MAXALLIPS 100
#define PROCFS_NAME "pktab"
#define KERNBUFSIZE 1024
#define USABLEPORTS (UBOUND-LBOUND+1)
