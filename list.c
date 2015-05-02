#include <stdlib.h>
#include <string.h>

#include "pf_nattrack.h"

void laddref(struct pf_nattrack_list **head, 
      struct pf_nattrack_list *no, struct pf_nattrack_list *ref) {
   ladd(head, no);
   no->ref = ref;
}

void ladd(struct pf_nattrack_list **head, struct pf_nattrack_list *no) {
   if (*head) {
      (*head)->prev = no;
   }
   no->next = *head;
   no->prev = NULL;
   *head = no;
}

void ldel(struct pf_nattrack_list **head, struct pf_nattrack_list *no) {
   if (!(*head) || !no) {
      return;
   }

   if (no->prev) no->prev->next = no->next;
   if (no->next) no->next->prev = no->prev;

   if (*head == no) {
      *head = (*head)->next;
      if (*head) (*head)->prev = NULL;
   }
}

struct pf_nattrack_list *lfind(struct pf_nattrack_list *head, 
      struct pf_nattrack *nt) {
   struct pf_nattrack_list *it;

   it = head;
   if (!it)
      return NULL;

   do {
      if (memcmp(it->nt, nt, sizeof(struct pf_nattrack)) == 0)
         return it;
      it = it->next;
   } while (it!=head);

   return NULL;
}
