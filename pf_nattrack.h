#ifndef _PF_NATTRACK_H_
#define _PF_NATTRACK_H_

#include <stdlib.h>
#include <net/if.h>
#include <net/pfvar.h>

struct pf_nattrack {
   struct pf_addr osrc,odst,tsrc,tdst; // original/translated source/dest.
   u_int16_t      osport,tsport,odport,tdport; // original/translated ports
   sa_family_t    af;
   u_int8_t       proto;
   u_int32_t      duration;
   u_int8_t       pad[2];  // needed to be 32bits mutiple
};

struct pf_nattrack_list {
   struct pf_nattrack_list *prev, *next;
   struct pf_nattrack_list *ref;  // a reverse reference to other 
                                  // lists (used to free list)
   struct pf_nattrack *nt;
};

struct pf_nattrack_hash {
   struct pf_nattrack_list *list;
};

void ladd(struct pf_nattrack_list **head, struct pf_nattrack_list *no);
void laddref(struct pf_nattrack_list **head, struct pf_nattrack_list *no, 
      struct pf_nattrack_list *ref);
void ldel(struct pf_nattrack_list **head, struct pf_nattrack_list *no);
struct pf_nattrack_list *lfind(struct pf_nattrack_list *head, 
      struct pf_nattrack *nt);

#endif
