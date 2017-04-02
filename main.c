#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <ctype.h>

#define LINE_SIZE 256
#define ALLOC_INIT 256

void analyze(char *line);
void analyze2(const char *line, unsigned char *bytes, size_t max_count, size_t *real_count);

/*
todo:
- tcp options
- ethernet frame structure
- modularity - ethernet contains ip contains tcp contains ssl/http/etc.
*/


typedef struct ethernet_frame
{ 
  unsigned char mac_dest[6];
  unsigned char mac_src[6];
  unsigned short ethertype; // IP = 0x0800, ARP = 0x0806
  //unsigned char payload[];
  // payload 46-1500 octets
  // frane check seq 32 bit
} ethernet_frame;

typedef struct ip_header
{
  unsigned char version_ihl;
  unsigned char dscp_ecn;
  unsigned short int total_length;
  unsigned short int identification;
  unsigned short int flagsFOffset;
  unsigned char ttl;unsigned char protocol;
  unsigned short int header_chsum;
  unsigned int source_ip;
  unsigned int dest_ip;
} ip_header;

typedef struct tcp_header
{
  unsigned short source_port;
  unsigned short dest_port;
  unsigned int seq_num;
  unsigned int ack_num;
  unsigned char dataoffset_000_ns;
  unsigned char flags;
  unsigned short window_size;
  unsigned short checksum;
  unsigned short urgent_ptr;
} tcp_header;

typedef struct tcp_option
{
  unsigned char type;  
} tcp_option;

typedef struct tcp_packet
{
  tcp_header header;
  // options
  
  // payload
  // payload type
} tcp_packet;

typedef enum
  {
    ETHERTYPE_IP = 0x0800,
    ETHERTYPE_ARP = 0x0806
  } Ethertype;

typedef enum
  {
IP_TCP = 0x06
  } IpProtocol;
unsigned int flip_endian32(unsigned int x)
{
  unsigned char a=x >> 24,b = 0xff & (x >> 16),c = 0xff&(x >>8),d = x & 0xff;
  return (a)|(b<<8)|(c<<16)|(d<<24);
  
}

unsigned short int flip_endian16(unsigned short int x)
{
  return (x << 8) | (x >> 8);
}

void load(const void *src, size_t src_size, ethernet_frame *dst, void **l3, void **l4, void **l5)
{
printf("Loading Ethernet frame (L2) ...\n");
  memcpy(dst, src, sizeof(ethernet_frame));
  dst->ethertype = flip_endian16(dst->ethertype);

  void *l3_start = src + sizeof(ethernet_frame);
  printf("L3 start at offset 0x%02x\n", (l3_start - src));
  
  if(dst->ethertype == ETHERTYPE_IP)
    {
printf("IP ethernet frame, loading IP header...\n");
      
      *l3 = malloc(sizeof(ip_header));
      memcpy(*l3, l3_start, sizeof(ip_header));
      ip_header*ptr=(ip_header*)l3_start;
      printf("ver_ihl = %x\n", ptr->version_ihl);
            printf("proto = %x\n", ptr->protocol);      


      void *l4_start = l3_start + sizeof(ip_header);
      printf("L4 start at offset 0x%02x\n", (l4_start - src));

      if(ptr->protocol == IP_TCP)
	{
	  *l4=malloc(sizeof(tcp_header));
	  memcpy(*l4, l4_start, sizeof(tcp_header));
	  tcp_header*ptr4=(tcp_header*)l4_start;

	  ptr4->source_port = flip_endian16(ptr4->source_port);
	  ptr4->dest_port = flip_endian16(ptr4->dest_port);

	  printf("TCP ports: source = %d, dest = %d\n", ptr4->source_port, ptr4->dest_port);
	  printf("TCP dataoffset: 0x%x\n", ptr4->dataoffset_000_ns >> 4);

	  printf("Estimated payload start at offset 0x%02x\n",
		 (l4_start - src) + ((ptr4->dataoffset_000_ns & 0xf0) >> 2));


	  void *l5_start = l4_start + ((ptr4->dataoffset_000_ns & 0xf0) >> 2);
	  // SSL/TLS
	  if(ptr4->source_port == 443 || ptr4->dest_port==443)
	    {
	      if(l5_start - src >= src_size)
		return;
	      

	      
	      unsigned char *tmp =(unsigned char*)l5_start; // Record Protocol
	      printf("(SSL/TLS) rec_type = %d (0x%x), version = %04x, length = %d\n",
		     tmp[0], tmp[0], *((unsigned short*)(tmp+1)),  flip_endian16(*((unsigned short*)(tmp+3))));

	      void *subproto = tmp + 5;

	      if(tmp[0] == 0x16) // handshake
		{
		  unsigned char handshake_type = *(unsigned char*)subproto;
		  printf("Handshake type = 0x%02x\n", handshake_type);
		}
	      
	      //	      if()
	    }

	}   

      

	}
}

void load_tcp_packet(void *src, tcp_packet *dst)
{
  memcpy(&dst->header, src, sizeof(tcp_header));
  int data_offset = dst->header.dataoffset_000_ns >> 4;
  printf("--- LTP %d \n", data_offset);
  //if(data_offset > 5)
}


int main(int argc, char **argv)
{
  printf("Packet analyzer\n");
  printf("passing throu stdin for now...\n\n");
  
  char *buf = (char*)malloc(LINE_SIZE);
  size_t len;
  unsigned char bytes[24];
  int pl = 0;
  void *raw = 0;
  size_t allocation_size = ALLOC_INIT;
  raw = malloc(allocation_size);
  size_t raw_size = 0;

  while(getline(&buf, &len, stdin)!=-1)
  {    

    size_t loaded = 0;

    memset(bytes, 0, 24);
    analyze2(buf, bytes,24,&loaded);

    if(loaded > 0)
      {pl=1;
	unsigned short int seq = bytes[0] << 8 | bytes[1];

	if(seq == 0)
	  {
	    memset(raw, 0, 256);
	    raw_size = 0;

	  }

	if(seq + loaded - 2 < allocation_size)
	  {memcpy(raw + seq, bytes + 2, loaded - 2);
	    raw_size = seq + loaded - 2;}
	else{
	  printf("Reallocating to %d\n", allocation_size * 2);
	  allocation_size *= 2;
	  raw = realloc(raw, allocation_size);
	}
	
	//printf("\tMATCH; seq %04x, %d bytes loaded\n", seq, loaded);
	//for(int i = 0; i <loaded; i++)
	//  printf(" %02x", bytes[i]);
	//printf("\n");
      }
    else if(pl)
      {
pl=0;
 printf("\n\tPACKET END, %d (0x%02x) bytes should be interpreted\n ", raw_size, raw_size);

	
	ethernet_frame ef;
	void *l3=0, *l4=0, *l5=0;
	load(raw, raw_size, &ef, &l3, &l4, &l5);
	if(l3)
	  free(l3);
	
	if(l4)
	  free(l4);

	if(l5)
	  free(l5);
	
	
	/*unsigned char *ethernet = (unsigned char*)raw;
	ethernet_frame *eth_frame = (ethernet_frame *)raw;
	printf("\tdst MAC = %02x:%02x:%02x:%02x:%02x:%02x; src MAC = %02x:%02x:%02x:%02x:%02x:%02x\n",
	       ethernet[0], ethernet[1], ethernet[2], ethernet[3], ethernet[4], ethernet[5],
	       ethernet[6], ethernet[7], ethernet[8], ethernet[9], ethernet[10], ethernet[11]);

	printf("\tethertype (or length) = 0x%04x\n", flip_endian16(eth_frame->ethertype));

	ip_header* iph = (ip_header*)(ethernet + 14);
	printf("\tipver = %d; ihl = %d; protocol = %d; total_length = %d; src_IP = %08x; dst_IP = %08x\n",
	       iph->version_ihl >> 4, iph->version_ihl & 0x0f, iph->protocol, iph->total_length, flip_endian32(iph->source_ip), flip_endian32(iph->dest_ip));

	if(iph->protocol == 6)
	  {
	    tcp_packet layer4p;
	    load_tcp_packet(iph + 1, &layer4p);

	    
	    tcp_header* tcph = (tcp_header*)(iph + 1);

	    unsigned char *payload = (unsigned char*)(tcph + 1);
	    printf("\tsrc port = %d; dest port = %d\n; data_offset = %d",
		   flip_endian16(tcph->source_port), flip_endian16(tcph->dest_port), tcph->dataoffset_000_ns >> 4);

	    printf("\nTODO - options!\n");
	    printf("\thandshake type? = %02x\n", payload[0]);
	    

	    }*/
      }

    
    printf("%s", buf);
    // todo: analyze line for structure: \s* 0x[0-9a-f]+:\s([0-9a-f]{4}\s)+\s*$
    
  }
  free(raw);
  free(buf);
  return 0;
}

void analyze(char *line)
{
  regex_t regex;
  int reti;
  reti = regcomp(&regex, "^\\s*0x\\([0-9a-f]\\+\\):\\s*\\(\\([0-9a-f]\\+\\)\\s\\+\\)\\{8\\}.*$", 0);
  if(reti){printf("Regex compilation fail\n");return;}

  regmatch_t extraction[10];
  reti = regexec(&regex, line, 10, extraction, 0);
  if(!reti)
    {
      printf("\tMATCH: ");
      for(int i = 0; i < 10 ; i++){
		char tmp[16];char *wr=tmp;memset(tmp,0,16);
	//	for(int j = extraction[i].rm_so; j < extraction[i].rm_eo; j++)
	//	  *(wr++)=line[j];
	printf("(%d, %d; %s), ", extraction[i].rm_so, extraction[i].rm_eo,tmp /*line + extraction[i].rm_so*/);
      }
      printf("\n");
    }else {}
    regfree(&regex);
}

unsigned char nib(char x)
{
  if('0' <= x && x <= '9') return x - '0';
  if('A' <= x && x <= 'F') return (x - 'A')+10;
  if('a' <= x && x <= 'f') return (x - 'a')+10;
}

unsigned char convert(char h, char l)
{
  return (nib(h) << 4) | nib(l);
}

void analyze2(const char *line, unsigned char *bytes, size_t max_count, size_t *real_count)
{
  const char *p = line;
  *real_count = 0; 
  while(*p)
    {
      if(isspace(*p))
	{p++;continue;}

      if(*p != '0' || !p[1] || p[1]!='x')return;
      else {p+=2;break;};
    }
 
  while(*p && *real_count < max_count)
    {
      if(isspace(*p) || *p == ':'){p++;continue;}
      
      if(isxdigit(*p) && isxdigit(p[1]))
	{	  
	  //	  printf("-%c%c-", p[0], p[1]);
	  bytes[*real_count] = convert(p[0], p[1]);
	  (*real_count)++;
	  p+=2;
	}
      else return;
    }

  
}
