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
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <net/altq/altq.h>
#include <sys/sysctl.h>
#include <netdb.h>

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
  return;
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
  
  time (&rawtime);
  timeinfo = gmtime (&rawtime);
  strftime(fmttime, 30, "%Y-%m-%d %H:%M:%S UTC", timeinfo);
  
  if (!nt) return;

  switch (nt->af) {
  case AF_INET:
    // date/time and protocol
    fprintf(file, "%s proto=%u", fmttime, nt->proto);
    
    // original source address and port
    char buf[INET_ADDRSTRLEN];
    fprintf(file, " osrc=");
    if (inet_ntop(nt->af, &nt->c.osrc, buf, sizeof(buf)) == NULL)
      fprintf(file, "? unknown!");
    else
      fprintf(file, "%s", buf);
    fprintf(file, ":%u", nt->c.osport);
    
    // original destination address and port
    fprintf(file, " odst=");
    if (inet_ntop(nt->af, &nt->c.odst, buf, sizeof(buf)) == NULL)
      fprintf(file, "? unknown!");
    else
      fprintf(file, "%s", buf);
    fprintf(file, ":%u", nt->c.odport);
    
    // translated source address and port
    fprintf(file, " tsrc=");
    if (inet_ntop(nt->af, &nt->c.tsrc, buf, sizeof(buf)) == NULL)
      fprintf(file, "? unknown!");
    else
      fprintf(file, "%s", buf);
    fprintf(file, ":%u", nt->c.tsport);
    
    // translated destination address and port
    fprintf(file, " tdst=");
    if (inet_ntop(nt->af, &nt->c.tdst, buf, sizeof(buf)) == NULL)
      fprintf(file, "? unknown!");
    else
      fprintf(file, "%s", buf);
    fprintf(file, ":%u", nt->c.tdport);
    
    fprintf(file, " duration=%u", nt->duration);
    // TODO: should store interface?
    
    fprintf(file, "\n");
    break;
  default:
    fprintf(file, "ERROR: unknown or unsupportted address family! (IPV6?)\n");
  }
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

  char *filename, today[12];
  FILE *file;
  struct stat st;
  time_t rawtime;
  struct tm *timeinfo;

  // check dir
  if (odir == NULL) {
    // print to STDOUT
    file = stdout;
  } else {
    // print in files in dir
    // check if dir exist
    if (stat(odir, &st) == 0) {
      // dir exist, open the file
      // extract the date of today
      time (&rawtime);
      timeinfo = gmtime (&rawtime);
      strftime(today, 12, "%Y-%m-%d", timeinfo);
      // allocate memory
      int size = (strlen(odir) + strlen("/") + strlen(today) + 1); // +1 for the null-terminator
      filename = malloc(size);
      snprintf(filename, size, "%s/%s", odir, today);
      
      file = fopen(filename, "a");
      if (file == NULL) {
	print_error(filename);
	file = stdout;
      }
    } else {
      print_error(filename);
      file = stdout;   
    }
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
