#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

// network libs
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <altq/altq.h>
#include <sys/sysctl.h>
#include <netdb.h>



#include "pf_nattrack.h"


u_long   pf_hashmask;
static u_long  pf_hashsize;
static uint32_t  pf_hashseed;

struct pf_nattrack_list *pfnt_hash;

/*
 * hashkey()
 *
 * create an hash to index the pf states represeting NAT connections
 */
uint32_t hashkey(struct pf_nattrack *nt) {
   uint32_t h;

   h = jenkins_hash32((uint32_t *)c,
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

   pfnt_hash = malloc(pf_hashsize * sizeof(struct pf_nattrack_list));
}


/*
 * print_nattrack()
 *
 * print out the NAT tuple
 */
void print_nattrack(struct pf_nattrack *nt, int opts) {
   printf("TODO: print_nattrack()\n");
}


int main() {
   char osrc[30], tsrc[30], dst[30], dir[10];
   struct pf_nattrack_list *pfnt = NULL, *item, item2;
   struct pf_nattrack_list *lastlist = NULL, *freelist;
   struct pf_nattrack node, *nodep;
   int i, found,o_sport,t_sport,dport;

   do {
      printf("\n\n===================================\n");
      printf("Nova rodada\n");
      printf("===================================\n");

      freelist = lastlist;
      lastlist = NULL;
      
      while (scanf("%[^:]:%d (%[^:]:%d) %s %[^:]:%d",osrc, &o_sport, tsrc, &t_sport, dir, dst, &dport) != EOF) {
         printf("osrc=%s o_sport=%d tsrc=%s t_sport=%d dst=%s dport=%d\n", osrc, o_sport, tsrc, t_sport, dst, dport);

         memset(&node, 0, sizeof(node));
         
         // original source address and port
         if (!inet_pton(AF_INET, osrc, &node.osrc.v4)) {
            printf("ERROR: invalid v4 addr (osrc=%s)\n", osrc);
            continue;
         }
         node.osport = hston(o_sport);

         // translated source address and port
         if (!inet_pton(AF_INET, tsrc, &node.tsrc.v4)) {
            printf("ERROR: invalid v4 addr (osrc=%s)\n", tsrc);
            continue;
         }
         node.tsport = hston(t_sport);
         
         // original destination address and port
         // TODO: change to odst
         if (!inet_pton(AF_INET, dst, &node.odst.v4)) {
            printf("ERROR: invalid v4 addr (odst=%s)\n", dst);
            continue;
         }
         node.odport = hston(dport);

         // translated destination address and port
         // TODO: change to tdst
         if (!inet_pton(AF_INET, dst, &node.tdst.v4)) {
            printf("ERROR: invalid v4 addr (odst=%s)\n", dst);
            continue;
         }
         node.tdport = hston(dport);

         pfnt = &pfnt_hash[hashkey(&node)];

         //found = 0;
         //printf("novo item %d\n", i);
         //for(item=head; item != NULL ; item=item->next) {
         //   novo = (struct meutipo *)item->data;
         //   if (novo->val == i) {
         //      found = 1;
         //      break;
         //   }
         //}
         item = lfind(pfnt, &node);


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
            ladd(&pfnt, item);
            item->ref = item2;
         }
         ladd(&lastlist, item2);
         item2->ref = item;
      }
      printf("done\n");
      printf("-> removendo itens da freelist\n");
      while(freelist) {
         item = freelist;
         print_nattrack(item->nt, 0);
         list_del(&pfnt_hash[hashkey(item->nt)], item->ref);
         list_del(&freelist, item);
         free(item->ref);
         free(item->nt);
         free(item);
      }
      printf("-> items armazenados:\n");
      for(i=0; i <= pf_hashmask; i++) {
         for(item=&pfnt_hash[i]; item; item=item->next) {
            print_nattrack(item->nt, 0);
         }
      }

      printf("Nova rodada? (1 = sim) ");
   } while(scanf("%d", &i) != EOF);

   return 0;
}
