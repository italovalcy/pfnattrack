#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/ioctl.h>

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

   h = jenkins_hash32((uint32_t *)&nt->c,
                sizeof(struct conn)/sizeof(uint32_t),
                pf_hashseed);

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
 * printerror()
 *
 * function used to print out an error message
 */
static void
printerror(char *s)
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
void print_nattrack(struct pf_nattrack *nt, int opts) {
   char buf[INET_ADDRSTRLEN];
   time_t rawtime;
   struct tm * timeinfo;
   char fmttime[80];

   time (&rawtime);
   timeinfo = localtime (&rawtime);
   strftime(fmttime,80,"%Y-%m-%d,%H:%M:%S",timeinfo);

   if (!nt) return;
   switch (nt->af) {
   case AF_INET:
      // date/time and protocol
      printf("%s proto=%u", fmttime, nt->proto);

      // original source address and port
      printf(" osrc=");
      if (inet_ntop(nt->af, &nt->c.osrc, buf, sizeof(buf)) == NULL)
         printf("?");
      else
         printf("%s", buf);
      printf(":%u", nt->c.osport);

      // translated source address and port
      printf(" tsrc=");
      if (inet_ntop(nt->af, &nt->c.tsrc, buf, sizeof(buf)) == NULL)
         printf("?");
      else
         printf("%s", buf);
      printf(":%u", nt->c.tsport);

      // original destination address and port
      printf(" odst=");
      if (inet_ntop(nt->af, &nt->c.odst, buf, sizeof(buf)) == NULL)
         printf("?");
      else
         printf("%s", buf);
      printf(":%u", nt->c.odport);

      // translated destination address and port
      printf(" tdst=");
      if (inet_ntop(nt->af, &nt->c.tdst, buf, sizeof(buf)) == NULL)
         printf("?");
      else
         printf("%s", buf);
      printf(":%u", nt->c.tdport);

      printf(" duration=%u", nt->duration);
      // TODO: should store interface?

      printf("\n");
      break;
   default:
      printf("ERROR: unknown or unsupportted address family\n");
   }
}

void free_list(struct pf_nattrack_list **l) {
   struct pf_nattrack_list *item;
   struct pf_nattrack_hash *pfnth;

   while(*l) {
      item = *l;
      print_nattrack(item->nt, 0);
      pfnth = &pfnt_hash[hashkey(item->nt)];
      ldel(&pfnth->list, item->ref);
      ldel(l, item);
      free(item->ref);
      free(item->nt);
      free(item);
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
      return 0;
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

   return 1;
}

/*
uint8_t pf_getstates(struct pf_nattrack *node) {
}
*/

struct pf_nattrack * read_input(struct pf_nattrack *node) {
   char osrc[30], tsrc[30], dst[30], dir[10];
   int o_sport, t_sport, dport;

   scanf("\n%[^:]:%d (%[^:]:%d) %s %[^:]:%d",osrc, &o_sport, tsrc, &t_sport, dir, dst, &dport);
   //printf("osrc=%s o_sport=%d tsrc=%s t_sport=%d dst=%s dport=%d\n", osrc, o_sport, tsrc, t_sport, dst, dport);

   memset(node, 0, sizeof(struct pf_nattrack));

   // original source address and port
   if (!inet_pton(AF_INET, osrc, &node->c.osrc.v4)) {
      printf("ERROR: invalid v4 addr (osrc=%s)\n", osrc);
      return NULL;
   }
   node->c.osport = o_sport;

   // translated source address and port
   if (!inet_pton(AF_INET, tsrc, &node->c.tsrc.v4)) {
      printf("ERROR: invalid v4 addr (osrc=%s)\n", tsrc);
      return NULL;
   }
   node->c.tsport = t_sport;

   // original destination address and port
   // TODO: change to odst
   if (!inet_pton(AF_INET, dst, &node->c.odst.v4)) {
      printf("ERROR: invalid v4 addr (odst=%s)\n", dst);
      return NULL;
   }
   node->c.odport = dport;

   // translated destination address and port
   // TODO: change to tdst
   if (!inet_pton(AF_INET, dst, &node->c.tdst.v4)) {
      printf("ERROR: invalid v4 addr (odst=%s)\n", dst);
      return NULL;
   }
   node->c.tdport = dport;

   node->af = AF_INET;

   return node;
}


int main() {
   struct pf_nattrack_hash *pfnth = NULL;
   struct pf_nattrack_list *item, *item2;
   struct pf_nattrack_list *lastlist = NULL, *freelist;
   struct pf_nattrack node, *nodep;
   int i, dev;

   initialize();

   dev = open("/dev/pf", O_RDWR);
   if (dev < 0) {
      printerror("open(/dev/pf)");
      return 1;
   }

   do {
      //printf("\n\n===================================\n");
      //printf("Nova rodada\n");
      //printf("===================================\n");

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
               printerror("error realloc - out of memory?");
               goto done;
            }
            ps.ps_buf = inbuf = newinbuf;
         }
         if (ioctl(dev, DIOCGETSTATES, &ps) < 0) {
            printerror("failed to get states from PF device");
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
            item = (struct pf_nattrack_list *)malloc(
                  sizeof(struct pf_nattrack_list));
            item->nt = nodep;
            item2 = (struct pf_nattrack_list *)malloc(
                  sizeof(struct pf_nattrack_list));
            item2->nt = nodep;
            ladd(&pfnth->list, item);
            item->ref = item2;
         }
         ladd(&lastlist, item2);
         item2->ref = item;
      }
done:
      free(inbuf);
      free_list(&freelist);

      sleep(PFTM_INTERVAL);
   } while(1);
      /* comentando para trabalhar com o get_states
      while ( scanf("\n%d", &i) != EOF && i != 0) {
         if (!read_input(&node)) continue;

         pfnth = &pfnt_hash[hashkey(&node)];

         item = lfind(pfnth->list, &node);

         if (item) {
            //printf("Item found! Deleting from freelist\n");
            item2 = item->ref;
            ldel(&freelist, item2);
         } else {
            //printf("Not found. Inserting...\n");
            nodep = (struct pf_nattrack *)malloc(sizeof(struct pf_nattrack));
            *nodep = node;
            item = (struct pf_nattrack_list *)malloc(
                  sizeof(struct pf_nattrack_list));
            item->nt = nodep;
            item2 = (struct pf_nattrack_list *)malloc(
                  sizeof(struct pf_nattrack_list));
            item2->nt = nodep;
            ladd(&pfnth->list, item);
            item->ref = item2;
         }
         ladd(&lastlist, item2);
         item2->ref = item;
      }
      //printf("done\n");
      //printf("-> removendo itens da freelist\n");
      free_list(&freelist);
      //printf("-> items armazenados:\n");
      //for(i=0; i <= pf_hashmask; i++) {
      //   for(item=pfnt_hash[i].list; item; item=item->next) {
      //      print_nattrack(item->nt, 0);
      //   }
      //}

      //printf("Nova rodada? (1 = sim) ");
   } while(scanf("\n%d", &i) != EOF && i != 0);
   */ // comentando para get_states

   free_list(&lastlist);
   free(pfnt_hash);

   return 0;
}
