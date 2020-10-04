#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

// network libs
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <net/altq/altq.h>
#include <sys/sysctl.h>
#include <netdb.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include "pf_nattrack.h"
#include "hash.h"

u_long   pf_hashmask;
static u_long  pf_hashsize;
static uint32_t  pf_hashseed;

struct pf_nattrack_hash *pfnt_hash;

/*
 * hashkey()
 *
 * create an hash to index the pf states represeting NAT connections
 */
uint32_t hashkey(struct pf_nattrack *nt) {
  uint32_t h;
  
  h = jenkins_hash32((uint32_t *)&nt->c, sizeof(struct conn)/sizeof(uint32_t), pf_hashseed);
  
  return (h & pf_hashmask);
}


/* initialize()
 *
 * function used to initialize some data structures of the program
 */
void initialize() {
  //TUNABLE_ULONG_FETCH("net.pf.states_hashsize", &pf_hashsize);
  if (pf_hashsize == 0 || !powerof2(pf_hashsize))
    pf_hashsize = 32768;
  pf_hashmask = pf_hashsize - 1;
  
  pf_hashseed = arc4random();
  
  pfnt_hash = (struct pf_nattrack_hash *)calloc(sizeof(struct pf_nattrack_hash), pf_hashsize);
}

/*
 * print_error()
 *
 * function used to print out an error message
 */
static void
print_error(char *s)
{
  char *msg;
  msg = strerror(errno);
  fprintf(stderr, "ERROR: %s: %s\n", s, msg);
  fflush(stderr);
  return;
}

/*
 * get_mac
 *
 * get arp entry
 * from: https://github.com/freebsd/freebsd/blob/releng/12.1/usr.sbin/arp/arp.c
 */
static int get_mac(struct pf_addr *host, char *mac)
{
  int mib[6];
  size_t needed;
  char *lim, *buf, *next, *rifname = NULL;
  struct rt_msghdr *rtm;
  struct sockaddr_in *sin2;
  struct sockaddr_dl *sdl;
  char ifname[IF_NAMESIZE];
  int st, found_entry = 0;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_FLAGS;
  mib[5] = 0;

  if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
    print_error("route-sysctl-estimate");

  if (needed == 0) /* empty table */
    return(1);

  buf = NULL;

  for (;;) {
    buf = reallocf(buf, needed);
    if (buf == NULL)
      print_error("could not reallocate memory");
    st = sysctl(mib, 6, buf, &needed, NULL, 0);
    if (st == 0 || errno != ENOMEM)
      break;
    needed += needed / 8;
  }

  if (st == -1)
    print_error("actual retrieval of routing table");

  lim = buf + needed;

  for (next = buf; next < lim; next += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)next;
    sin2 = (struct sockaddr_in *)(rtm + 1);
    sdl = (struct sockaddr_dl *)((char *)sin2 + SA_SIZE(sin2));

    if (rifname && if_indextoname(sdl->sdl_index, ifname) && strcmp(ifname, rifname))
      continue;

    if (host->v4.s_addr != sin2->sin_addr.s_addr)
      continue;

    found_entry = 1;
    
    if (sdl->sdl_alen) {
      if ((sdl->sdl_type == IFT_ETHER ||
	   sdl->sdl_type == IFT_L2VLAN ||
	   sdl->sdl_type == IFT_BRIDGE) &&
	  sdl->sdl_alen == ETHER_ADDR_LEN) {
	strcpy(mac, ether_ntoa((struct ether_addr *)LLADDR(sdl)));
      } else {
	int n = sdl->sdl_nlen > 0 ? sdl->sdl_nlen + 1 : 0;
	strcpy(mac, link_ntoa(sdl) + n);
      }
    } else {
      strcpy(mac, "00:.incomplete:00");
    }
  }
  free(buf);
  
  if (found_entry == 0) {
    strcpy(mac, "00:...unknow..:00");
  }

  return(found_entry == 0);
    
}
/*
 * is_private_address
 *
 * check if IP is private 
 * assumes ip is in HOST order. Use ntohl() to convert as approrpriate
 */
bool is_private_address(uint32_t ip)
{
  uint8_t b1, b2, b3, b4;
  b1 = (uint8_t)(ip >> 24);
  b2 = (uint8_t)((ip >> 16) & 0x0ff);
  b3 = (uint8_t)((ip >> 8) & 0x0ff);
  b4 = (uint8_t)(ip & 0x0ff);
  
  // 10.x.y.z
  if (b1 == 10)
    return true;
  
    // 172.16.0.0 - 172.31.255.255
  if ((b1 == 172) && (b2 >= 16) && (b2 <= 31))
    return true;
  
  // 192.168.0.0 - 192.168.255.255
  if ((b1 == 192) && (b2 == 168))
    return true;
  
  return false;
}

/*
 * print_nattrack()
 *
 * print out the NAT tuple
 */
void print_nattrack(FILE *file, struct pf_nattrack *nt) {
  time_t rawtime;
  struct tm * timeinfo;
  char fmttime[30];
  struct protoent *p;
  char mac[18];
    
  time (&rawtime);
  timeinfo = gmtime (&rawtime);
  strftime(fmttime, 30, "%Y-%m-%d %H:%M:%S UTC", timeinfo);
  
  if (!nt) return;

  switch (nt->af) {
  case AF_INET:
    // print date time
    fprintf(file, "%s", fmttime);

    // print proto
    if ((p = getprotobynumber(nt->proto)) != NULL)
      fprintf(file, " %s", p->p_name);
    else
      fprintf(file, " %u", nt->proto);
    
    // print original source address and port
    char buf[INET_ADDRSTRLEN];
    fprintf(file, " osrc=");
    if (inet_ntop(nt->af, &nt->c.osrc, buf, sizeof(buf)) == NULL)
      fprintf(file, "? unknown!");
    else
      fprintf(file, "%s", buf);
    fprintf(file, ":%u", nt->c.osport);

    // print MAC original source if the IP is private
    if (is_private_address(ntohl(nt->c.osrc.v4.s_addr))) {
      if (get_mac(&nt->c.osrc, mac))
	print_error("No MAC ADDRESS host offline? ");
      fprintf(file, " (%s)", mac);
    }
    
    // print original destination address and port
    fprintf(file, " odst=");
    if (inet_ntop(nt->af, &nt->c.odst, buf, sizeof(buf)) == NULL)
      fprintf(file, "? unknown!");
    else
      fprintf(file, "%s", buf);
    fprintf(file, ":%u", nt->c.odport);
    
    // print translated source address and port
    fprintf(file, " tsrc=");
    if (inet_ntop(nt->af, &nt->c.tsrc, buf, sizeof(buf)) == NULL)
      fprintf(file, "? unknown!");
    else
      fprintf(file, "%s", buf);
    fprintf(file, ":%u", nt->c.tsport);
    
    // print translated destination address and port
    fprintf(file, " tdst=");
    if (inet_ntop(nt->af, &nt->c.tdst, buf, sizeof(buf)) == NULL)
      fprintf(file, "? unknown!");
    else
      fprintf(file, "%s", buf);
    fprintf(file, ":%u", nt->c.tdport);
    
    // print MAC translated destination if the IP is private
    if (is_private_address(ntohl(nt->c.tdst.v4.s_addr))) {
      if (get_mac(&nt->c.tdst, mac))
	print_error("No MAC ADDRESS host offline? ");
      fprintf(file, " (%s)", mac);
    }
    // print duration time 
    fprintf(file, " duration=%u", nt->duration);
    
    // TODO: should store interface?
    
    // newline 
    fprintf(file, "\n");
    
    break;

  default:
    fprintf(file, "ERROR: unknown or unsupportted address family! (IPV6?)\n");
  }
}

/*
 * Create a directory if not exist 
 */
int rek_mkdir(char *path)
{
  char *sep = strrchr(path, '/');
  if (sep != NULL) {
    *sep = 0;
    rek_mkdir(path);
    *sep = '/';
  }
  
  if (mkdir(path, 0777) && errno != EEXIST) {
    char *str;
    // allocate memory
    int size = 33 + strlen(path);
    str = malloc(size);
    snprintf(str, size, "Error while trying to create '%s'\n", path);
    print_error(str);
    return (1);
  } else
    return (0);
}

/*
 * print_and_free_list
 *
 * call func to print out the NAT tuple and free the list
 */
void print_and_free_list(struct pf_nattrack_list **l, char *odir)
{
  struct pf_nattrack_list *item;
  struct pf_nattrack_hash *pfnth;

  char *filename, *path, localpath[10], today[15];
  FILE *file;
  struct stat st;
  time_t rawtime;
  struct tm *timeinfo;

  // check dir
  if (odir == NULL) {
    // print to STDOUT
    file = stdout;
  } else {
    // print in files in dirs, YEAR/MONTH/DAY.log
    // check if dir exist
    if (stat(odir, &st) == 0) {
      // dir exist, open the file
      time (&rawtime);
      timeinfo = gmtime (&rawtime);
      strftime(localpath, 10, "%Y/%m", timeinfo);
      strftime(today, 15, "%Y-%m-%d.log", timeinfo);
      // compose path 
      int size = (strlen(odir) + strlen("/") + strlen(localpath) + 1); // +1 for the null-terminator
      path = malloc(size);
      snprintf(path, size, "%s/%s", odir, localpath);
      /* if cannot make the dir print on stdout */
      if (rek_mkdir(path)) {
	print_error(path);
	file = stdout;
      } else {
	// compose filename 
	// allocate memory
	int size = (strlen(path) + strlen("/") + strlen(today) + 1); // +1 for the null-terminator
	filename = malloc(size);
	snprintf(filename, size, "%s/%s", path, today);
	file = fopen(filename, "a");
	if (file == NULL) {
	  print_error(filename);
	  file = stdout;
	}
      }
    } else {
      // compose error
      char *error;
      int size = (38 + strlen(odir) + 1); // +1 for the null-terminator
      error = malloc(size);
      snprintf(error, size, "Path not exist or cannot write into: %s", odir);
      print_error(error);
      file = stdout;   
    }
    fflush(stdout);
  }
  
  // provess all list
  while (*l) {
    item = *l;
    print_nattrack(file, item->nt);
    pfnth = &pfnt_hash[hashkey(item->nt)];
    ldel(&pfnth->list, item->ref);
    ldel(l, item);
    free(item->ref);
    free(item->nt);
    free(item);
  }

  // flush and close file
  if (file != stdout) {
    fflush(file);
    fclose(file);
  }
  
}

/*
 *
 *
 *
 */
uint8_t convert_state(struct pfsync_state *state, struct pf_nattrack *node) {
  struct pfsync_state_key *orig, *trans;
  uint8_t src, dst;
  
  if (state->direction == PF_OUT) {
    src = 1; dst = 0;
    orig  = &state->key[PF_SK_STACK];
    trans = &state->key[PF_SK_WIRE];
  } else {
    src = 0; dst = 1;
    orig = &state->key[PF_SK_WIRE];
    trans = &state->key[PF_SK_STACK];
  }
  
  // check if it is a NAT:
  //   key_wire == key_stack  --> NO NAT
  //   key_wire != key_stack  --> NAT
  if (state->af != AF_INET ||
      (PF_AEQ(&orig->addr[src], &trans->addr[src], state->af) &&
       PF_AEQ(&orig->addr[dst], &trans->addr[dst], state->af) &&
       orig->port[src] == trans->port[src] &&
       orig->port[dst] == trans->port[dst])) {
    //printf("NO_NAT!\n");
    return(0);
  }
  
  memset(node, 0, sizeof(struct pf_nattrack));
  
  node->c.osrc.v4 = orig->addr[src].v4;
  node->c.tsrc.v4 = trans->addr[src].v4;
  node->c.odst.v4 = orig->addr[dst].v4;
  node->c.tdst.v4 = trans->addr[dst].v4;
  node->c.osport = ntohs(orig->port[src]);
  node->c.tsport = ntohs(trans->port[src]);
  node->c.odport = ntohs(orig->port[dst]);
  node->c.tdport = ntohs(trans->port[dst]);
  node->af = state->af;
  node->proto = state->proto;
  node->duration = ntohl(state->creation) + ntohl(state->expire);
  
  return(1);
}

/*
 * main()
 */
int main(int argc, char *argv[ ])
{
  struct pf_nattrack_hash *pfnth = NULL;
  struct pf_nattrack_list *item, *item2;
  struct pf_nattrack_list *lastlist = NULL, *freelist;
  struct pf_nattrack node, *nodep;
  int i, dev;

  int c, errflg = 0;
  extern char *optarg;
  extern int optind, optopt, opterr;
  char *odir = NULL;
  
  while ((c = getopt(argc, argv, ":d:")) != -1) {
    switch(c) {
    case 'd':
      odir = optarg;
      break;
    case ':':   /* -d without operand */
      fprintf(stderr, "Option -%c requires an existing DIRECTORY where save the logs!\n", optopt);
      errflg++;
      break;
    case '?':
      fprintf(stderr, "Unrecognized option: -%c\n", optopt);
      errflg++;
    }
  }
  if (errflg) {
    fprintf(stderr, "usage: %s [-d DIR]\n", argv[0]);
    exit(2);
  }

  // initialize
  initialize();

  // open device 
  dev = open("/dev/pf", O_RDWR);
  if (dev < 0) {
    print_error("open(/dev/pf)");
    exit(1);
  }
  
  // process 
  do {
    freelist = lastlist;
    lastlist = NULL;
    
    struct pfioc_states ps;
    struct pfsync_state *p;
    char *inbuf = NULL, *newinbuf = NULL;
    unsigned int len = 0;
    int i, opts = 0;
    
    memset(&ps, 0, sizeof(ps));
    for (;;) {
      ps.ps_len = len;
      if (len) {
	newinbuf = realloc(inbuf, len);
	if (newinbuf == NULL) {
	  print_error("error realloc - out of memory?");
	  goto done;
	}
	ps.ps_buf = inbuf = newinbuf;
      }
      if (ioctl(dev, DIOCGETSTATES, &ps) < 0) {
	print_error("failed to get states from PF device");
	goto done;
      }
      if (ps.ps_len + sizeof(struct pfioc_states) < len)
	break;
      if (len == 0 && ps.ps_len == 0)
	goto done;
      if (len == 0 && ps.ps_len != 0)
	len = ps.ps_len;
      if (ps.ps_len == 0)
	goto done;	/* no states */
      len *= 2;
    }

    p = ps.ps_states;
    for (i = 0; i < ps.ps_len; i += sizeof(*p), p++) {
      if (!convert_state(p, &node)) continue;
      
      pfnth = &pfnt_hash[hashkey(&node)];
      item = lfind(pfnth->list, &node);
      
      if (item) {
	//printf("Item found! Deleting from freelist\n");
	item2 = item->ref;
	*(item2->nt) = node;
	ldel(&freelist, item2);
      } else {
	//printf("Not found. Inserting...\n");
	nodep = (struct pf_nattrack *)malloc(sizeof(struct pf_nattrack));
	*nodep = node;
	item = (struct pf_nattrack_list *)malloc(sizeof(struct pf_nattrack_list));
	item->nt = nodep;
	item2 = (struct pf_nattrack_list *)malloc(sizeof(struct pf_nattrack_list));
	item2->nt = nodep;
	ladd(&pfnth->list, item);
	item->ref = item2;
      }
      
      ladd(&lastlist, item2);
      item2->ref = item;
    }
  done:
    free(inbuf);
    print_and_free_list(&freelist, odir);
    
    sleep(PFTM_INTERVAL);
  } while(1);
  
  print_and_free_list(&lastlist, odir);
  free(pfnt_hash);
  
  exit(0);
}
