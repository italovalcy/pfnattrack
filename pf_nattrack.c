#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <sys/socket.h>

// network libs
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <altq/altq.h>
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

   h = jenkins_hash32((uint32_t *)nt,
                sizeof(struct pf_nattrack)/sizeof(uint32_t),
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
 * print_nattrack()
 *
 * print out the NAT tuple
 */
void print_nattrack(struct pf_nattrack *nt, int opts) {
   char buf[INET_ADDRSTRLEN];

   if (!nt) return;
   switch (nt->af) {
   case AF_INET:

      // original source address and port
      printf("osrc=");
      if (inet_ntop(nt->af, &nt->osrc, buf, sizeof(buf)) == NULL)
         printf("?");
      else
         printf("%s", buf);
      printf(":%u", ntohs(nt->osport));

      // translated source address and port
      printf(" tdst=");
      if (inet_ntop(nt->af, &nt->tsrc, buf, sizeof(buf)) == NULL)
         printf("?");
      else
         printf("%s", buf);
      printf(":%u", ntohs(nt->tsport));

      // original destination address and port
      printf(" odst=");
      if (inet_ntop(nt->af, &nt->odst, buf, sizeof(buf)) == NULL)
         printf("?");
      else
         printf("%s", buf);
      printf(":%u", ntohs(nt->odport));

      // translated destination address and port
      printf(" tdst=");
      if (inet_ntop(nt->af, &nt->tdst, buf, sizeof(buf)) == NULL)
         printf("?");
      else
         printf("%s", buf);
      printf(":%u", ntohs(nt->tdport));

      // TODO: print duration
      // TODO: print protocol
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

struct pf_nattrack * read_input(struct pf_nattrack *node) {
   char osrc[30], tsrc[30], dst[30], dir[10];
   int o_sport, t_sport, dport;

   scanf("\n%[^:]:%d (%[^:]:%d) %s %[^:]:%d",osrc, &o_sport, tsrc, &t_sport, dir, dst, &dport);
   printf("osrc=%s o_sport=%d tsrc=%s t_sport=%d dst=%s dport=%d\n", osrc, o_sport, tsrc, t_sport, dst, dport);

   memset(node, 0, sizeof(struct pf_nattrack));

   // original source address and port
   if (!inet_pton(AF_INET, osrc, &node->osrc.v4)) {
      printf("ERROR: invalid v4 addr (osrc=%s)\n", osrc);
      return NULL;
   }
   node->osport = htons(o_sport);

   // translated source address and port
   if (!inet_pton(AF_INET, tsrc, &node->tsrc.v4)) {
      printf("ERROR: invalid v4 addr (osrc=%s)\n", tsrc);
      return NULL;
   }
   node->tsport = htons(t_sport);

   // original destination address and port
   // TODO: change to odst
   if (!inet_pton(AF_INET, dst, &node->odst.v4)) {
      printf("ERROR: invalid v4 addr (odst=%s)\n", dst);
      return NULL;
   }
   node->odport = htons(dport);

   // translated destination address and port
   // TODO: change to tdst
   if (!inet_pton(AF_INET, dst, &node->tdst.v4)) {
      printf("ERROR: invalid v4 addr (odst=%s)\n", dst);
      return NULL;
   }
   node->tdport = htons(dport);

   node->af = AF_INET;

   return node;
}


int main() {
   struct pf_nattrack_hash *pfnth = NULL;
   struct pf_nattrack_list *item, *item2;
   struct pf_nattrack_list *lastlist = NULL, *freelist;
   struct pf_nattrack node, *nodep;
   int i;

   initialize();

   do {
      printf("\n\n===================================\n");
      printf("Nova rodada\n");
      printf("===================================\n");

      freelist = lastlist;
      lastlist = NULL;
      
      while ( scanf("\n%d", &i) != EOF && i != 0) {
         if (!read_input(&node)) continue;

         pfnth = &pfnt_hash[hashkey(&node)];

         item = lfind(pfnth->list, &node);

         if (item) {
            printf("Item found! Deleting from freelist\n");
            item2 = item->ref;
            ldel(&freelist, item2);
         } else {
            printf("Not found. Inserting...\n");
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
      printf("done\n");
      printf("-> removendo itens da freelist\n");
      free_list(&freelist);
      printf("-> items armazenados:\n");
      for(i=0; i <= pf_hashmask; i++) {
         for(item=pfnt_hash[i].list; item; item=item->next) {
            print_nattrack(item->nt, 0);
         }
      }

      printf("Nova rodada? (1 = sim) ");
   } while(scanf("\n%d", &i) != EOF && i != 0);

   free_list(&lastlist);
   free(pfnt_hash);

   return 0;
}
