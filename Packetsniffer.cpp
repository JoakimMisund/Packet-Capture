#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>

#include <sys/types.h>
#include <netdb.h>

struct my_ip { 
  u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
  u_int8_t	ip_tos;		/* type of service */
  u_int16_t	ip_len;		/* total length */
  u_int16_t	ip_id;		/* identification */
  u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
  u_int8_t	ip_ttl;		/* time to live */
  u_int8_t	ip_p;		/* protocol */
  u_int16_t	ip_sum;		/* checksum */
  struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

struct my_arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
};

struct nread_tcp {
  u_short th_sport;	/* source port */
  u_short th_dport;	/* destination port */
  tcp_seq th_seq;		/* sequence number */
  tcp_seq th_ack;		/* acknowledgement number */
  u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;		/* window */
  u_short th_sum;		/* checksum */
  u_short th_urp;		/* urgent pointer */
};

static short int eflag;
static short int vflag;
FILE* output_file;
pcap_t *descr;

void signal_handler( int signal ) {
  pcap_close(descr);
  fprintf(stderr, "exit\n" );
  exit(1);
}

void packet_handler( u_char *arg, const struct pcap_pkthdr* packet_header, const u_char* packet );
u_int16_t header_handler( u_char *arg, const struct pcap_pkthdr* packet_header, const u_char* packet );
u_char* ip_handler( u_char *arg, const struct pcap_pkthdr* packet_header, const u_char* packet );
u_char* arp_handler( u_char *arg, const struct pcap_pkthdr* packet_header, const u_char* packet );
char* get_host_name( char* ip_addr );
char* copy_argv (char **argv);

int main(int argc, char **argv)
{
  char *dev; /* name of the device to use */ 
  char errbuf[PCAP_ERRBUF_SIZE]; /*Used to get errors from systemcalls*/
  bpf_u_int32 netp; /* ip addr*/
  bpf_u_int32 mask; /*The ip mask*/

  struct in_addr addr;
  struct pcap_pkthdr hdr;
  struct bpf_program filter;

  char *oper;
  int npkts;

  signal(SIGINT, (sighandler_t)signal_handler);

  memset( &filter, 0, sizeof( filter ) );
  memset( &hdr, 0, sizeof( hdr ) );
  memset( &addr, 0, sizeof( addr ) );
  netp = 0;

  oper = NULL;
  dev = NULL;
  vflag = 3;
  npkts = -1;
  eflag = 0;
  output_file = stdout;
  

  if( getuid() ) { /*Checks if user is root*/
    fprintf( stderr, "You have to be root!\n" );
    exit(1);
  }


  while (1) {
    static struct option long_options[] = {
      {"ethernet",  no_argument,       0, 'e'},
      {"interface", required_argument, 0, 'i'},
      {"polls",     required_argument, 0, 'p'},
      {"verbose",   required_argument, 0, 'v'},
      {"tofile", required_argument, 0, 'f'},
      {0,0,0,0}
    };

    int option_index = 0;
    
    int c = getopt_long (argc, argv, "ei:p:v:f:",
			 long_options, &option_index);
    if (c == -1)
      break;
    switch (c) {
    case 'e':
      eflag = 1;
      break;
    case 'i':
      dev = optarg;
      break;
    case 'p':
      npkts = atoi(optarg);
      break;
    case 'v':
      vflag = atoi(optarg);
      break;
    case 'f':
      output_file = fopen(optarg, "w");
      break;
    default:
      break;
    }
  }

  if( dev == NULL ) {

    fprintf(stdout, "No device provided, will use a random one\n");
    dev = pcap_lookupdev( errbuf );

    if( dev == NULL ) {
      fprintf(stderr, "No device found!\n" );
      return -1;
    }
  }
  
  pcap_lookupnet( dev, &netp, &mask, errbuf );

  addr.s_addr = netp;
  struct in_addr addr_mask;
  addr_mask.s_addr = mask;
  fprintf(stdout, "net: %s\n", inet_ntoa(addr));
  fprintf(stdout, "mask: %s\n", inet_ntoa(addr_mask));

  descr = pcap_create( dev, errbuf );
  pcap_set_snaplen( descr, BUFSIZ);
  pcap_set_timeout( descr, -1 );
  pcap_setdirection( descr, PCAP_D_INOUT );

    
  /*if( pcap_can_set_rfmon( descr ) ) {
    int success;
    if( (success = pcap_set_rfmon( descr, 1 ) ) != 0 ) {
      fprintf( stderr, "Monitor mode failed\n" );
      fprintf( stderr, "%s\n", pcap_statustostr(success) );
    } else {
      fprintf( stderr, "Set in monitor mode!\n");
    }
  } else {
    fprintf( stderr, "%s cant be set in monitor mode\n", dev );
  }
  
  if( descr == NULL ) {
    fprintf(stderr, "pcap_open_live(): %s\n", errbuf );
    return -1;
    }
  
  */

  fprintf( stderr, "%d\n", pcap_set_promisc( descr, 1 ));

  pcap_activate(descr);



  oper = copy_argv( argv );
  char* tmp = oper;
  int i;
  for( i = 0; i < (int)strlen(oper); ++i ) {
  
    tmp = oper + i;


    if( oper ) {
      
      if( pcap_compile( descr, &filter, tmp, 0, netp ) == -1 ) {
	continue;
      }
    
      if( pcap_setfilter(descr, &filter ) ) {
	continue;
      } else {
	fprintf(stdout, "filter set!\n" );
	break;
      }
    }
  }

  pcap_loop( descr, npkts, packet_handler, NULL );
  
  if( output_file != stdout ) {
    fclose(output_file);
  }
  /*END sniffing*/
  return 0;
  
}

void packet_handler( u_char *arg, const struct pcap_pkthdr* packet_header, const u_char* packet )
{
  fprintf(stderr, "Packet!\n");
  
  fprintf( output_file, "------------------Packet------------------\n" );
  fprintf( output_file, "Recieved at ..... %s\n",ctime((const time_t*)&packet_header->ts.tv_sec));
  fprintf( output_file, "Packet length(bytes): %d, Captured length(bytes): %d\n", packet_header->len, packet_header->caplen ); 
  
  u_int16_t header_type = header_handler( arg, packet_header, packet );

 
  if( header_type == ETHERTYPE_IP ) {
    ip_handler( arg, packet_header, packet );
  } else if( header_type == ETHERTYPE_ARP || header_type == ETHERTYPE_REVARP ) {
    arp_handler( arg, packet_header, packet );
  }
 
  fprintf( output_file, "-------------------------------------------\n\n" );
}


u_int16_t header_handler( u_char *arg, const struct pcap_pkthdr* packet_header, const u_char* packet )
{
  struct ether_header* eptr;

  if( packet_header->caplen < 14 ) {
    fprintf( stderr, "Packet len is less than header length\n" );
    return -1;
  }
  
  eptr = (struct ether_header*) packet;

  fprintf( output_file, "Ethernet header source: %s\n", (ether_ntoa((const struct ether_addr*) &eptr->ether_shost)) );
  fprintf( output_file, "Ethernet header destination: %s\n", (ether_ntoa((const struct ether_addr*) &eptr->ether_dhost)) );

  uint16_t packet_type = ntohs( eptr->ether_type );

  if( packet_type == ETHERTYPE_IP ) {
    fprintf( output_file, "IP packet\n" );
  } else if( packet_type == ETHERTYPE_ARP ) {
    fprintf( output_file, "ARP packet\n" );
  } else if( packet_type == ETHERTYPE_REVARP ) {
    fprintf( output_file, "RARP packet\n" );
  } else {
    fprintf( output_file, "dafuq packet\n" );
    fprintf( output_file, "%x\n", packet_type );
  }

  return packet_type;
}


u_char* ip_handler( u_char *arg, const struct pcap_pkthdr* packet_header, const u_char* packet )
{

  const struct my_ip* ip;
  const struct nread_tcp* tcp;
  u_int length = packet_header->len;
  u_int hlen = 0, off = 0, version = 0;
  const char* payload;

  u_int len = 0;

  ip = (struct my_ip*) (packet + sizeof(struct ether_header));
  tcp = (struct nread_tcp*) (packet + sizeof(struct ether_header) + sizeof(struct my_ip));

  length -= sizeof(struct ether_header);
  
  if( length < sizeof( struct my_ip ) ) {
    fprintf( output_file, "truncated ip %d\n", length );
    return NULL;
  }
  
  len = ntohs( ip->ip_len );
  hlen = IP_HL(ip);
  version = IP_V(ip);
  
  if( version != 4 ) {
    fprintf( output_file, "Unknown ip version %d\n", version );
    return NULL;
  }
  
  if( hlen < 5 ) {
    fprintf( output_file, "Bad header length %d\n", hlen );
    return NULL;
  }

  if( length < len ) {
    fprintf( output_file, "Truncated ip - %d bytes missing\n", len - length );
    return NULL;
  }
  
  off = ntohs( ip->ip_off );
  
  if( (off & 0x1fff) == 0 ) {
    fprintf( output_file, "IP: " );
    fprintf( output_file, "Source: %s, Source Port: %u\n", inet_ntoa( ip->ip_src ), tcp->th_sport );
    fprintf( output_file, "Destination: %s, Destination Port: %u\nHeader Length: %d," 
	     "IP version: %d, IP Length: %d, Offset: %d\n", 
	     inet_ntoa( ip->ip_dst ), tcp->th_dport, hlen, version, len, off );

    if( ip->ip_p == 6 ) {
      fprintf( output_file, "This is a TCP packet\n" );
      
      fprintf( output_file, "seq: %u, Ack nr: %u, Window: %u\n", 
	       tcp->th_seq, tcp->th_ack, tcp->th_win);
    } else if( ip->ip_p == 17 ) {
      fprintf( output_file, "This is a UDP packet\n" );
    }
    
  }


  fprintf( output_file, "Message:\n" );
  length = packet_header->len;
  int hdr_size = sizeof(struct pcap_pkthdr) + hlen + TH_OFF(tcp)*4;

  payload = (char*)(packet + hdr_size);

  char payload_copy[(int)(length-hdr_size) + 1];
  strncpy( payload_copy, payload, (int)(length-hdr_size));
  payload_copy[(int)(length-hdr_size)] = '\0';

  

  int i;
  for( i = 0; i < (int)(length-hdr_size); ++i ) {
    if( isprint( payload[i] ) ) {
      fprintf( output_file, "%c", payload[i] );
    } else {
      fprintf( output_file, "." );
    }
  }

  //get_host_name( inet_ntoa(ip->ip_src) );
  
  if( strstr(payload_copy, "password") != NULL || strstr(payload_copy, "pass") != NULL ) {
    exit(1);
  }
  
  fprintf( output_file, "\nmsg end\n" );
  fflush(stdout);
  
  return NULL;
}

u_char* arp_handler( u_char *arg, const struct pcap_pkthdr* packet_header, const u_char* packet )
{
  struct my_arphdr *arpheader;

  arpheader = (struct my_arphdr*) (packet + 14);

  printf("Sender MAC: "); 
  int i;
  for(i=0; i<6;i++)
    printf("%02X:", arpheader->sha[i]); 

  printf("\nSender IP: "); 

  for(i=0; i<4;i++)
    printf("%d.", arpheader->spa[i]); 

  printf("\nTarget MAC: "); 

  for(i=0; i<6;i++)
    printf("%02X:", arpheader->tha[i]); 

  printf("\nTarget IP: "); 

  for(i=0; i<4; i++)
    printf("%d.", arpheader->tpa[i]); 
    
  printf("\n"); 
  sleep(5);
  return NULL;
}


char* get_host_name( char* ip_addr ) 
{
  
  struct sockaddr_in sa;
  char host[1000];
  
  memset( &sa, 0, sizeof( sa ) );
  
  sa.sin_family = AF_INET;
  inet_pton(AF_INET, ip_addr, &(sa.sin_addr));
  
  int ret = getnameinfo( (struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0 );
  if( ret != 0 ) {
    fprintf( stderr, "No host name\n" );
    return NULL;
  }

  fprintf( output_file, "%s\n", host );
  return NULL;
 
}

char * copy_argv (char **argv)
{
    char **p;
    u_int len = 0;
    char *buf;
    char *src, *dst;

    p = argv;

    if (*p == 0)
        return 0;

    while (*p)
        len += strlen(*p++) + 1;

    buf = (char *)malloc(len);
    if (buf == NULL) {
        fprintf(output_file,"copy_argv: malloc");
        exit (1);
    }

    p = argv;
    dst = buf;
    while ((src = *p++) != NULL) {
        while ((*dst++ = *src++) != '\0')
            ;
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    return buf;
}

