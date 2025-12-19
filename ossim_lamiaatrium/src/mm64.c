/*
 * Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* LamiaAtrium release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

/*
 * PAGING based Memory Management
 * Memory management unit mm/mm.c
 */

#include "mm64.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include "string.h" //include to use memset and calloc

extern pthread_mutex_t mmvm_lock;

#if defined(MM64)

/*
 * init_pte - Initialize PTE entry
 */
int init_pte(addr_t *pte,
             int pre,    // present
             addr_t fpn,    // FPN
             int drt,    // dirty
             int swp,    // swap
             int swptyp, // swap type
             addr_t swpoff) // swap offset
{
  if (pre != 0) {
    if (swp == 0) { // Non swap ~ page online
      if (fpn == 0)
        return -1;  // Invalid setting

      /* Valid setting with FPN */
      SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
      CLRBIT(*pte, PAGING_PTE_SWAPPED_MASK);
      CLRBIT(*pte, PAGING_PTE_DIRTY_MASK);

      SETVAL(*pte, fpn, PAGING_PTE_FPN_MASK, PAGING_PTE_FPN_LOBIT);
    }
    else
    { // page swapped
      SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
      SETBIT(*pte, PAGING_PTE_SWAPPED_MASK);
      CLRBIT(*pte, PAGING_PTE_DIRTY_MASK);

      SETVAL(*pte, swptyp, PAGING_PTE_SWPTYP_MASK, PAGING_PTE_SWPTYP_LOBIT);
      SETVAL(*pte, swpoff, PAGING_PTE_SWPOFF_MASK, PAGING_PTE_SWPOFF_LOBIT);
    }
  }

  return 0;
}


/*
 * get_pd_from_pagenum - Parse address to 5 page directory level
 * @pgn   : pagenumer
 * @pgd   : page global directory
 * @p4d   : page level directory
 * @pud   : page upper directory
 * @pmd   : page middle directory
 * @pt    : page table 
 */
int get_pd_from_address(addr_t addr, addr_t* pgd, addr_t* p4d, addr_t* pud, addr_t* pmd, addr_t* pt)
{
	/* Extract page direactories */
	*pgd = (addr&PAGING64_ADDR_PGD_MASK)>>PAGING64_ADDR_PGD_LOBIT;
	*p4d = (addr&PAGING64_ADDR_P4D_MASK)>>PAGING64_ADDR_P4D_LOBIT;
	*pud = (addr&PAGING64_ADDR_PUD_MASK)>>PAGING64_ADDR_PUD_LOBIT;
	*pmd = (addr&PAGING64_ADDR_PMD_MASK)>>PAGING64_ADDR_PMD_LOBIT;
	*pt = (addr&PAGING64_ADDR_PT_MASK)>>PAGING64_ADDR_PT_LOBIT;

	/* TODO: implement the page direactories mapping */

	return 0;
}

/*
 * get_pd_from_pagenum - Parse page number to 5 page directory level
 * @pgn   : pagenumer
 * @pgd   : page global directory
 * @p4d   : page level directory
 * @pud   : page upper directory
 * @pmd   : page middle directory
 * @pt    : page table 
 */
int get_pd_from_pagenum(addr_t pgn, addr_t* pgd, addr_t* p4d, addr_t* pud, addr_t* pmd, addr_t* pt)
{
	/* Shift the address to get page num and perform the mapping*/
	return get_pd_from_address(pgn << PAGING64_ADDR_PT_SHIFT,
                         pgd,p4d,pud,pmd,pt);
}


/*
 * pte_set_swap - Set PTE entry for swapped page
 * @pte    : target page table entry (PTE)
 * @swptyp : swap type
 * @swpoff : swap offset
 */
int pte_set_swap(struct pcb_t *caller, addr_t pgn, int swptyp, addr_t swpoff)
{
  struct krnl_t *krnl = caller->krnl; //uncomment

  addr_t *pte;
  addr_t pgd=0;
  addr_t p4d=0;
  addr_t pud=0;
  addr_t pmd=0;
  addr_t pt=0;
	
  // dummy pte alloc to avoid runtime error
  // pte = malloc(sizeof(addr_t));
#ifdef MM64	
  /* Get value from the system */
  /* TODO Perform multi-level page mapping */
  get_pd_from_pagenum(pgn, &pgd, &p4d, &pud, &pmd, &pt);
  //... krnl->mm->pgd
  //... krnl->mm->pt
  //pte = &krnl->mm->pt;
  //my implementation
/* helper pattern: allocate table if missing, and store pointer (addr_t) */
addr_t *p4d_table, *pud_table, *pmd_table, *pt_table;

/* allocate/get P4D from PGD */
if (krnl->mm->pgd[pgd] == 0) {
    p4d_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    krnl->mm->pgd[pgd] = (addr_t)p4d_table;
} else {
    p4d_table = (addr_t*)krnl->mm->pgd[pgd];
}

/* allocate/get PUD from P4D */
if (p4d_table[p4d] == 0) {
    pud_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    p4d_table[p4d] = (addr_t)pud_table;
} else {
    pud_table = (addr_t*)p4d_table[p4d];
}

/* allocate/get PMD from PUD */
if (pud_table[pud] == 0) {
    pmd_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    pud_table[pud] = (addr_t)pmd_table;
} else {
    pmd_table = (addr_t*)pud_table[pud];
}

/* allocate/get PT from PMD */
if (pmd_table[pmd] == 0) {
    pt_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    pmd_table[pmd] = (addr_t)pt_table;
} else {
    pt_table = (addr_t*)pmd_table[pmd];
}

/* PTE is then &pt_table[pt] */
  pte = &pt_table[pt];
  // end my implementation
#else
  pte = &krnl->mm->pgd[pgn];
#endif
	
  SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
  SETBIT(*pte, PAGING_PTE_SWAPPED_MASK);

  SETVAL(*pte, swptyp, PAGING_PTE_SWPTYP_MASK, PAGING_PTE_SWPTYP_LOBIT);
  SETVAL(*pte, swpoff, PAGING_PTE_SWPOFF_MASK, PAGING_PTE_SWPOFF_LOBIT);

  return 0;
}

/*
 * pte_set_fpn - Set PTE entry for on-line page
 * @pte   : target page table entry (PTE)
 * @fpn   : frame page number (FPN)
 */
int pte_set_fpn(struct pcb_t *caller, addr_t pgn, addr_t fpn)
{
  struct krnl_t *krnl = caller->krnl; //uncomment

  addr_t *pte;
  addr_t pgd=0;
  addr_t p4d=0;
  addr_t pud=0;
  addr_t pmd=0;
  addr_t pt=0;
	
  // dummy pte alloc to avoid runtime error
  // pte = malloc(sizeof(addr_t));
#ifdef MM64	
  /* Get value from the system */
  /* TODO Perform multi-level page mapping */
  get_pd_from_pagenum(pgn, &pgd, &p4d, &pud, &pmd, &pt);
  //... krnl->mm->pgd
  //... krnl->mm->pt
  //pte = &krnl->mm->pt;
  // my implementation
/* helper pattern: allocate table if missing, and store pointer (addr_t) */
  addr_t *p4d_table, *pud_table, *pmd_table, *pt_table;

/* allocate/get P4D from PGD */
  if (krnl->mm->pgd[pgd] == 0) {
    p4d_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    krnl->mm->pgd[pgd] = (addr_t)p4d_table;
  } else {
    p4d_table = (addr_t*)krnl->mm->pgd[pgd];
  }

/* allocate/get PUD from P4D */
  if (p4d_table[p4d] == 0) {
    pud_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    p4d_table[p4d] = (addr_t)pud_table;
  } else {
    pud_table = (addr_t*)p4d_table[p4d];
  } 

/* allocate/get PMD from PUD */
  if (pud_table[pud] == 0) {
    pmd_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    pud_table[pud] = (addr_t)pmd_table;
  } else {
    pmd_table = (addr_t*)pud_table[pud];
  }

/* allocate/get PT from PMD */
  if (pmd_table[pmd] == 0) {
    pt_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    pmd_table[pmd] = (addr_t)pt_table;
  } else {
    pt_table = (addr_t*)pmd_table[pmd];
  }

/* PTE is then &pt_table[pt] */
  pte = &pt_table[pt];
#else
  pte = &krnl->mm->pgd[pgn];
#endif

  SETBIT(*pte, PAGING_PTE_PRESENT_MASK);
  CLRBIT(*pte, PAGING_PTE_SWAPPED_MASK);

  SETVAL(*pte, fpn, PAGING_PTE_FPN_MASK, PAGING_PTE_FPN_LOBIT);

  return 0;
}


/* Get PTE page table entry
 * @caller : caller
 * @pgn    : page number
 * @ret    : page table entry
 **/
uint32_t pte_get_entry(struct pcb_t *caller, addr_t pgn)
{
  // printf("DEBUG: [pte_set_fpn] PID %d, mm->pgd: %p\n", 
  //          caller->pid, caller->krnl->mm->pgd);
  struct krnl_t *krnl = caller->krnl; //uncomment
  uint32_t pte = 0;
  addr_t pgd=0;
  addr_t p4d=0;
  addr_t pud=0;
  addr_t pmd=0;
  addr_t	pt=0;
	
  /* TODO Perform multi-level page mapping */
  get_pd_from_pagenum(pgn, &pgd, &p4d, &pud, &pmd, &pt);
  //... krnl->mm->pgd
  //... krnl->mm->pt
  //pte = &krnl->mm->pt;	
  //my implementation
#ifdef MM64
  addr_t *p4d_table, *pud_table, *pmd_table, *pt_table;
  
  // take P4D
  p4d_table = (addr_t*)krnl->mm->pgd[pgd];
  if (p4d_table == NULL) return 0;
  
  // take PUD
  pud_table = (addr_t*)p4d_table[p4d];
  if (pud_table == NULL) return 0;
  
  // take PMD
  pmd_table = (addr_t*)pud_table[pud];
  if (pmd_table == NULL) return 0;
  
  // take PT
  pt_table = (addr_t*)pmd_table[pmd];
  if (pt_table == NULL) return 0;
  
  // take PTE value
  pte = pt_table[pt];
#else
  pte = krnl->mm->pgd[pgn];
#endif
  return pte;
}

/* Set PTE page table entry
 * @caller : caller
 * @pgn    : page number
 * @ret    : page table entry
 **/
int pte_set_entry(struct pcb_t *caller, addr_t pgn, uint32_t pte_val)
{
	// struct krnl_t *krnl = caller->krnl;
	// krnl->mm->pgd[pgn]=pte_val;
	//my implementation
  // printf("DEBUG: [pte_set_fpn] PID %d, mm->pgd: %p\n", 
  //          caller->pid, caller->krnl->mm->pgd);
#ifdef MM64
  //implement 64 bit similar to pte_set_fpn/swap function but assign directly
  struct krnl_t *krnl = caller->krnl;
  addr_t *pte;
  addr_t pgd=0, p4d=0, pud=0, pmd=0, pt=0;
    
  get_pd_from_pagenum(pgn, &pgd, &p4d, &pud, &pmd, &pt);

/* helper pattern: allocate table if missing, and store pointer (addr_t) */
  addr_t *p4d_table, *pud_table, *pmd_table, *pt_table;

/* allocate/get P4D from PGD */
  if (krnl->mm->pgd[pgd] == 0) {
    p4d_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    krnl->mm->pgd[pgd] = (addr_t)p4d_table;
  } else {
    p4d_table = (addr_t*)krnl->mm->pgd[pgd];
  }

/* allocate/get PUD from P4D */
  if (p4d_table[p4d] == 0) {
    pud_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    p4d_table[p4d] = (addr_t)pud_table;
  } else {
    pud_table = (addr_t*)p4d_table[p4d];
  }

/* allocate/get PMD from PUD */
  if (pud_table[pud] == 0) {
    pmd_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    pud_table[pud] = (addr_t)pmd_table;
  } else {
    pmd_table = (addr_t*)pud_table[pud];
  }

/* allocate/get PT from PMD */
  if (pmd_table[pmd] == 0) {
    pt_table = calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
    pmd_table[pmd] = (addr_t)pt_table;
  } else {
    pt_table = (addr_t*)pmd_table[pmd];
  }

/* PTE is then &pt_table[pt] */
  pte = &pt_table[pt];
  *pte = pte_val;
#else
	struct krnl_t *krnl = caller->krnl;
	krnl->mm->pgd[pgn]=pte_val;
#endif
	return 0;
}


/*
 * vmap_pgd_memset - map a range of page at aligned address
 */
int vmap_pgd_memset(struct pcb_t *caller,           // process call
                    addr_t addr,                       // start address which is aligned to pagesz
                    int pgnum)                      // num of mapping page
{
  int pgit = 0;
  addr_t pgn;
  uint64_t pattern = 0xdeadbeef;
  addr_t pgn_start = addr >> PAGING64_ADDR_PT_SHIFT; //add variable
  /* TODO memset the page table with given pattern
   */
  //MY IMPLEMENTATION
  for (pgit = 0; pgit < pgnum; pgit++){
    pgn = pgn_start + pgit;
    //call pte_set_fpn with fpn dummy to create level page table
    pte_set_fpn(caller,pgn, pattern);
  }
  return 0;
}

/*
 * vmap_page_range - map a range of page at aligned address
 */
addr_t vmap_page_range(struct pcb_t *caller,           // process call
                    addr_t addr,                       // start address which is aligned to pagesz
                    int pgnum,                      // num of mapping page
                    struct framephy_struct *frames, // list of the mapped frames
                    struct vm_rg_struct *ret_rg)    // return mapped region, the real mapped fp
{                                                   // no guarantee all given pages are mapped
  struct framephy_struct *fpit = frames;
  int pgit = 0;
  addr_t pgn = addr >> PAGING64_ADDR_PT_SHIFT;

  /* TODO: update the rg_end and rg_start of ret_rg 
  //ret_rg->rg_end =  ....
  //ret_rg->rg_start = ...
  //ret_rg->vmaid = ...
  */

  /* TODO map range of frame to address space
   *      [addr to addr + pgnum*PAGING_PAGESZ
   *      in page table caller->krnl->mm->pgd,
   *                    caller->krnl->mm->pud...
   *                    ...
   */

  /* Tracking for later page replacement activities (if needed)
   * Enqueue new usage page */
  //enlist_pgn_node(&caller->krnl->mm->fifo_pgn, pgn64 + pgit);
  // my implementation
  //update rg_end and rg_start of ret_rg
  // ret_rg->rg_start = addr;
  // ret_rg->rg_end = addr; //will be updated later
  if (ret_rg != NULL) {
    ret_rg->rg_start = addr;
    ret_rg->rg_end = addr; //will be updated later
  }
  //map range of frame to address space
  for (pgit = 0; pgit < pgnum && fpit != NULL; pgit++){
    //map page (pgn + pgit) to frame (fpit -> fpn)
    pte_set_fpn(caller, pgn + pgit, fpit->fpn);
    enlist_pgn_node(&caller->krnl->mm->fifo_pgn, pgn + pgit);
    fpit = fpit ->fp_next;
  }
  // free used frames list 
  fpit = frames; // Reset pointer to head of the list
  while (fpit != NULL) {
    struct framephy_struct *tmp = fpit;
    fpit = fpit->fp_next;
    free(tmp);
  }
  //update rg_end base on real pages mapped
  if (ret_rg != NULL){
    ret_rg->rg_end = addr + (pgit * PAGING64_PAGESZ);
  }
  return 0;
}

/*
 * alloc_pages_range - allocate req_pgnum of frame in ram
 * @caller    : caller
 * @req_pgnum : request page num
 * @frm_lst   : frame list
 */

addr_t alloc_pages_range(struct pcb_t *caller, int req_pgnum, struct framephy_struct **frm_lst)
{
  addr_t fpn;
  int pgit;
  struct framephy_struct *newfp_str = NULL;
  struct framephy_struct *head = NULL; // pointer from head

  /* TODO: allocate the page 
  //caller-> ...
  //frm_lst-> ...
  */
  //my implementation
  pthread_mutex_lock(&mmvm_lock);
  if (caller->krnl->mram == NULL)
  {
    *frm_lst = NULL;
    pthread_mutex_unlock(&mmvm_lock);
    return -1; // error: mram's been initialized
  }
  for (pgit = 0; pgit < req_pgnum; pgit++){
    if (MEMPHY_get_freefp(caller->krnl->mram, &fpn) == 0){
      newfp_str = (struct framephy_struct*)malloc(sizeof(struct framephy_struct));
      if (newfp_str == NULL){
        //malloc error, free all frame allocated and send error
        while (head != NULL){
          struct framephy_struct *tmp = head;
          MEMPHY_put_freefp(caller->krnl->mram, tmp->fpn);
          head = head->fp_next;
          free(tmp);
        }
        *frm_lst = NULL;
        pthread_mutex_unlock(&mmvm_lock);
        return -1; //allocating memory error
      }
      newfp_str->fpn = fpn;
      newfp_str->fp_next = head; //add to top of the list
      head = newfp_str;
    } else {
      //error: not enough frame 
      //free frames allocated because not enought
      while (head != NULL){
        struct framephy_struct *tmp = head;
        MEMPHY_put_freefp(caller->krnl->mram, tmp->fpn);
        head = head->fp_next;
        free(tmp);
      }
      *frm_lst = NULL;
      pthread_mutex_unlock(&mmvm_lock);
      return -3000; //error out of memory
    }
  }
  *frm_lst = head; //return list of allocated frames

/*
  for (pgit = 0; pgit < req_pgnum; pgit++)
  {
    // TODO: allocate the page 
    if (MEMPHY_get_freefp(caller->mram, &fpn) == 0)
    {
      newfp_str->fpn = fpn;
    }
    else
    { // TODO: ERROR CODE of obtaining somes but not enough frames
    }
  }
*/


  /* End TODO */

  pthread_mutex_unlock(&mmvm_lock);
  return 0;
}

/*
 * vm_map_ram - do the mapping all vm are to ram storage device
 * @caller    : caller
 * @astart    : vm area start
 * @aend      : vm area end
 * @mapstart  : start mapping point
 * @incpgnum  : number of mapped page
 * @ret_rg    : returned region
 */
addr_t vm_map_ram(struct pcb_t *caller, addr_t astart, addr_t aend, addr_t mapstart, int incpgnum, struct vm_rg_struct *ret_rg)
{
  struct framephy_struct *frm_lst = NULL;
  addr_t ret_alloc = 0;
//  int pgnum = incpgnum;

  /*@bksysnet: author provides a feasible solution of getting frames
   *FATAL logic in here, wrong behaviour if we have not enough page
   *i.e. we request 1000 frames meanwhile our RAM has size of 3 frames
   *Don't try to perform that case in this simple work, it will result
   *in endless procedure of swap-off to get frame and we have not provide
   *duplicate control mechanism, keep it simple
   */
  ret_alloc = alloc_pages_range(caller, incpgnum, &frm_lst);
  //my implementation
  if (ret_alloc < 0 && ret_alloc != -3000)
    return -1; // failed

  /* Out of memory */
  if (ret_alloc == -3000){
    return -1;
  }
  /* it leaves the case of memory is enough but half in ram, half in swap
   * do the swaping all to swapper to get the all in ram */
  vmap_page_range(caller, mapstart, incpgnum, frm_lst, ret_rg);
  return 0;
}

/* Swap copy content page from source frame to destination frame
 * @mpsrc  : source memphy
 * @srcfpn : source physical page number (FPN)
 * @mpdst  : destination memphy
 * @dstfpn : destination physical page number (FPN)
 **/
int __swap_cp_page(struct memphy_struct *mpsrc, addr_t srcfpn,
                   struct memphy_struct *mpdst, addr_t dstfpn)
{
  int cellidx;
  addr_t addrsrc, addrdst;
  for (cellidx = 0; cellidx < PAGING_PAGESZ; cellidx++)
  {
    addrsrc = srcfpn * PAGING_PAGESZ + cellidx;
    addrdst = dstfpn * PAGING_PAGESZ + cellidx;

    BYTE data;
    MEMPHY_read(mpsrc, addrsrc, &data);
    MEMPHY_write(mpdst, addrdst, data);
  }

  return 0;
}

/*
 *Initialize a empty Memory Management instance
 * @mm:     self mm
 * @caller: mm owner
 */
int init_mm(struct mm_struct *mm, struct pcb_t *caller)
{
//   struct vm_area_struct *vma0 = malloc(sizeof(struct vm_area_struct));
//   printf("DEBUG: [init_mm] Initializing for PID %d...\n", caller->pid);
//   /* TODO init page table directory */
//    //mm->pgd = ...
//    //mm->p4d = ...
//    //mm->pud = ...
//    //mm->pmd = ...
//    //mm->pt = ...
//   //my implementation
// #ifdef MM64
//    //allocate PGD (level 5 page table), 512 entries (4096 bytes/ 8 bytes/entry)
//    mm->pgd = (uint64_t *)calloc(PAGING64_PAGESZ / sizeof(uint64_t), sizeof(uint64_t));
//    printf("DEBUG: [init_mm] PID %d mm->pgd allocated at %p\n",caller->pid, mm->pgd);
//    // others will be allocated on demand
//    mm->p4d = NULL;
//    mm->pud = NULL;
//    mm->pmd = NULL;
//    mm->pt = NULL;
// #else
//    mm->pgd = (uint32_t *)calloc(PAGING_MAX_PGN, sizeof(uint32_t));
// #endif
//   /* By default the owner comes with at least one vma */
//   vma0->vm_id = 0;
//   vma0->vm_start = 0;
//   vma0->vm_end = vma0->vm_start;
//   vma0->sbrk = vma0->vm_start;
//   struct vm_rg_struct *first_rg = init_vm_rg(vma0->vm_start, vma0->vm_end);
//   enlist_vm_rg_node(&vma0->vm_freerg_list, first_rg);

//   // /* TODO update VMA0 next */
//   // // vma0->next = ...
//   vma0->vm_next = NULL;
//   // /* Point vma owner backward */
//   // //vma0->vm_mm = mm; 
//   vma0->vm_mm = mm;
//   // /* TODO: update mmap */
//   // //mm->mmap = ...
//   // //mm->symrgtbl = ...
//   memset(mm->symrgtbl, 0, sizeof(struct vm_rg_struct) * PAGING_MAX_SYMTBL_SZ);
//   //init empty fifo list
//   mm->fifo_pgn = NULL;
//   return 0;
  //my implementation
  // allocate and init vma0
  struct vm_area_struct *vma0 = malloc(sizeof(struct vm_area_struct));

  vma0->vm_id = 0;
  vma0->vm_start = 0;
  vma0->vm_end = PAGING_MEMRAMSZ; // Supposing vma0 can be large equal to RAM
  vma0->sbrk = vma0->vm_start;
  vma0->vm_next = NULL;
  vma0->vm_mm = mm; // backward pointer mm
  vma0->vm_freerg_list = NULL; // init freelist

  /* TODO init page table directory */
#ifdef MM64
   /* Allocate PGD (level 5 talbe) */
  mm->pgd = (uint64_t *)calloc(PAGING64_PAGESZ / sizeof(uint64_t), sizeof(uint64_t));
   
  //2. pre-allocate first pathway ([0][0][0][0])
  addr_t *p4d_table = (addr_t *)calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
  mm->pgd[0] = (addr_t)p4d_table;

  addr_t *pud_table = (addr_t *)calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
  p4d_table[0] = (addr_t)pud_table;
   
  addr_t *pmd_table = (addr_t *)calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
  pud_table[0] = (addr_t)pmd_table;
   
  addr_t *pt_table = (addr_t *)calloc(PAGING64_PAGESZ / sizeof(addr_t), sizeof(addr_t));
  pmd_table[0] = (addr_t)pt_table;
   
   // Assign NULL for all base pointers
   mm->p4d = NULL; //
   mm->pud = NULL; //
   mm->pmd = NULL; //
   mm->pt = NULL;  //
#else
   mm->pgd = (uint32_t *)calloc(PAGING_MAX_PGN, sizeof(uint32_t));
#endif

  //assign VMA (mmap)
  mm->mmap = vma0;

  //init symbol table (variables list) to 0
  memset(mm->symrgtbl, 0, sizeof(struct vm_rg_struct) * PAGING_MAX_SYMTBL_SZ);

  // init fifo_pgn to NULL (for page replacement)
  mm->fifo_pgn = NULL;

  return 0;
}

struct vm_rg_struct *init_vm_rg(addr_t rg_start, addr_t rg_end)
{
  struct vm_rg_struct *rgnode = malloc(sizeof(struct vm_rg_struct));

  rgnode->rg_start = rg_start;
  rgnode->rg_end = rg_end;
  rgnode->rg_next = NULL;

  return rgnode;
}

int enlist_vm_rg_node(struct vm_rg_struct **rglist, struct vm_rg_struct *rgnode)
{
  rgnode->rg_next = *rglist;
  *rglist = rgnode;

  return 0;
}

int enlist_pgn_node(struct pgn_t **plist, addr_t pgn)
{
  struct pgn_t *pnode = malloc(sizeof(struct pgn_t));

  pnode->pgn = pgn;
  pnode->pg_next = *plist;
  *plist = pnode;

  return 0;
}

int print_list_fp(struct framephy_struct *ifp)
{
  struct framephy_struct *fp = ifp;

  printf("print_list_fp: ");
  if (fp == NULL) { printf("NULL list\n"); return -1;}
  printf("\n");
  while (fp != NULL)
  {
    printf("fp[" FORMAT_ADDR "]\n", fp->fpn);
    fp = fp->fp_next;
  }
  printf("\n");
  return 0;
}

int print_list_rg(struct vm_rg_struct *irg)
{
  struct vm_rg_struct *rg = irg;

  printf("print_list_rg: ");
  if (rg == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (rg != NULL)
  {
    printf("rg[" FORMAT_ADDR "->"  FORMAT_ADDR "]\n", rg->rg_start, rg->rg_end);
    rg = rg->rg_next;
  }
  printf("\n");
  return 0;
}

int print_list_vma(struct vm_area_struct *ivma)
{
  struct vm_area_struct *vma = ivma;

  printf("print_list_vma: ");
  if (vma == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (vma != NULL)
  {
    printf("va[" FORMAT_ADDR "->" FORMAT_ADDR "]\n", vma->vm_start, vma->vm_end);
    vma = vma->vm_next;
  }
  printf("\n");
  return 0;
}

int print_list_pgn(struct pgn_t *ip)
{
  printf("print_list_pgn: ");
  if (ip == NULL) { printf("NULL list\n"); return -1; }
  printf("\n");
  while (ip != NULL)
  {
    printf("va[" FORMAT_ADDR "]-\n", ip->pgn);
    ip = ip->pg_next;
  }
  printf("n");
  return 0;
}

int print_pgtbl(struct pcb_t *caller, addr_t start, addr_t end)
{
//  addr_t pgn_start;//, pgn_end;
//  addr_t pgit;
//  struct krnl_t *krnl = caller->krnl;

  // addr_t pgd=0;
  // addr_t p4d=0;
  // addr_t pud=0;
  // addr_t pmd=0;
  // addr_t pt=0;

  // get_pd_from_address(start, &pgd, &p4d, &pud, &pmd, &pt);

  // /* TODO traverse the page map and dump the page directory entries */

  // return 0;
  //my implementation
  addr_t pgn_start, pgd_idx, p4d_idx, pud_idx, pmd_idx, pt_idx;

  /* CHECK SAFE (level 1) */
  if (caller == NULL || caller->krnl == NULL || caller->krnl->mm == NULL || caller->krnl->mm->pgd == NULL){
    printf("print_pgtbl: Error - PCB, kernel, MM, or PGD is NULL.\n");
    return -1;
  }
  struct krnl_t *krnl = caller->krnl;
  pgn_start = start >> PAGING64_ADDR_PT_SHIFT;
  get_pd_from_pagenum(pgn_start, &pgd_idx, &p4d_idx, &pud_idx, &pmd_idx, &pt_idx);
  /* Check safe (Level 2) - Must check all levels*/
  addr_t *p4d_table = (addr_t*)krnl->mm->pgd[pgd_idx];
  if (p4d_table == NULL) {
    printf("print_pgtbl:\n PDG=%p P4g=NULL\n", krnl->mm->pgd);
    return 0;
  }
  addr_t *pud_table = (addr_t*)p4d_table[p4d_idx];
  if (pud_table == NULL) {
    printf("print_pgtbl:\n PDG=%p P4g=%p PUD=NULL\n", krnl->mm->pgd, p4d_table);
    return 0;
  } 
  addr_t *pmd_table = (addr_t*)pud_table[pud_idx];
  if (pmd_table == NULL) {
    printf("print_pgtbl:\n PDG=%p P4g=%p PUD=%p PMD=NULL\n", krnl->mm->pgd, p4d_table, pud_table);
    return 0;
  }
  printf("print_pgtbl:\n PDG=%p P4g=%p PUD=%p PMD=%p\n", krnl->mm->pgd, p4d_table, pud_table, pmd_table);     
  return 0;
}

#endif  //def MM64
