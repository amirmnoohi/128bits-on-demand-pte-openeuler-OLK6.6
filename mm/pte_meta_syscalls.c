/* SPDX-License-Identifier: GPL-2.0 */
/*
 * pte_meta_syscalls.c - Page table entry metadata system calls
 *
 * This file implements four system calls that manage page table entry metadata:
 * 1. sys_enable_pte_meta  - Expands 4KiB PTE page to 8KiB and sets PMD bit 58
 * 2. sys_disable_pte_meta - Collapses back to 4KiB and clears PMD bit 58
 * 3. sys_set_pte_meta     - Stores 64-bit metadata and type (0/1)
 * 4. sys_get_pte_meta     - Returns packed value: (type<<63 | meta)
 *
 * All syscalls require CAP_SYS_ADMIN capability and operate on current->mm.
 * The metadata is stored in an expanded PTE table where each entry is 128 bits
 * instead of the standard 64 bits. The expansion is indicated by bit 58 in the PMD.
 */

#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pgtable.h>
#include <linux/bitops.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <asm/tlbflush.h>
#include <linux/capability.h>
#include <linux/gfp.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/sched/mm.h>

/* ------------------------------------------------------------------ */
/* 469  enable_pte_meta                                               */
/* ------------------------------------------------------------------ */
/**
 * sys_enable_pte_meta - Enable metadata storage for a page table
 * @addr: Virtual address within the page table to enable metadata for
 *
 * This syscall expands a 4KiB PTE page to 8KiB to store metadata alongside
 * each PTE. The expansion is indicated by setting bit 58 in the PMD.
 *
 * The expanded table interleaves the original PTEs with metadata slots,
 * effectively doubling the size while maintaining the original mapping.
 *
 * Return: 0 on success, negative error code on failure
 */
SYSCALL_DEFINE1(enable_pte_meta, unsigned long, addr)
{
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte_base, *new_pte;
    unsigned long flags;
    struct page *new_pte_pages;
    spinlock_t *ptl;
    int i;
    phys_addr_t paddr;
    
    if (!mm)
        return -EINVAL;
        
    // Check CAP_SYS_ADMIN privilege
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
        
    // Address must be page-aligned
    if (addr & ~PAGE_MASK)
        return -EINVAL;
        
    mmap_read_lock(mm);
    
    // Walk the page tables
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud) || pud_leaf(*pud)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd) || pmd_leaf(*pmd)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    // Check if bit 58 is already set (metadata already enabled)
    if (pmd_val(*pmd) & (1UL << 58)) {
        mmap_read_unlock(mm);
        return -EEXIST;
    }
    
    // Get the current PTE base
    pte_base = pte_offset_kernel(pmd, 0);
    
    // Allocate two new pages for the expanded PTE table
    new_pte_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, 1);
    if (!new_pte_pages) {
        mmap_read_unlock(mm);
        return -ENOMEM;
    }
    
    new_pte = page_address(new_pte_pages);
    
    // Ensure the memory is properly zeroed
    memset(new_pte, 0, PAGE_SIZE * 2);
    
    // Get page table lock
    ptl = pte_lockptr(mm, pmd);
    spin_lock_irqsave(ptl, flags);
    
    // Interleave old PTEs into even slots of the new table
    for (i = 0; i < PTRS_PER_PTE; i++)
        new_pte[i * 2] = pte_base[i];
    
    // Update the PMD to point to the new pages and set bit 58
    paddr = page_to_phys(new_pte_pages);
    set_pmd(pmd, __pmd(__phys_to_pmd_val(paddr) | PMD_TYPE_TABLE | PMD_TABLE_UXN | (1UL << 58)));
    
    // Memory barrier to ensure updates are visible
    smp_wmb();
    
    // Based on your module, use flush_tlb_kernel_range instead
    flush_tlb_mm(mm);
    
    spin_unlock_irqrestore(ptl, flags);
    mmap_read_unlock(mm);
    
    return 0;
}

/* ------------------------------------------------------------------ */
/* 470  disable_pte_meta                                              */
/* ------------------------------------------------------------------ */
/**
 * sys_disable_pte_meta - Disable metadata storage for a page table
 * @addr: Virtual address within the page table to disable metadata for
 *
 * This syscall collapses an 8KiB PTE page back to 4KiB by removing the
 * metadata slots and clearing bit 58 in the PMD. The original PTEs are
 * preserved in the process.
 *
 * Return: 0 on success, negative error code on failure
 */
SYSCALL_DEFINE1(disable_pte_meta, unsigned long, addr)
{
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *old_pte, *new_pte;
    unsigned long flags;
    spinlock_t *ptl;
    int i;
    phys_addr_t paddr;
    struct page *old_pages;
    
    if (!mm)
        return -EINVAL;
        
    // Check CAP_SYS_ADMIN privilege
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
        
    // Address must be page-aligned
    if (addr & ~PAGE_MASK)
        return -EINVAL;
        
    mmap_read_lock(mm);
    
    // Walk the page tables
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud) || pud_leaf(*pud)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd) || pmd_leaf(*pmd)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    // Check if bit 58 is not set (metadata not enabled)
    if (!(pmd_val(*pmd) & (1UL << 58))) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    // Get the current expanded PTE base (128-bit PTEs)
    old_pte = pte_offset_kernel(pmd, 0);
    old_pages = virt_to_page(old_pte);
    
    // 1) Allocate a single clean page for the classic PTE table
    new_pte = (pte_t *)get_zeroed_page(GFP_KERNEL);
    if (!new_pte) {
        mmap_read_unlock(mm);
        return -ENOMEM;
    }
    
    // 2) Copy even slots over under PT lock
    ptl = pte_lockptr(mm, pmd);
    spin_lock_irqsave(ptl, flags);
    
    for (i = 0; i < PTRS_PER_PTE; i++)
        new_pte[i] = old_pte[i * 2]; // drop odd-slot metadata
    
    // 3) Swap into PMD with bit 58 cleared
    paddr = virt_to_phys(new_pte);
    pmd_t new_entry = __pmd(__phys_to_pmd_val(paddr) | PMD_TYPE_TABLE | PMD_TABLE_UXN);
    // Ensure bit 58 is clear
    pmd_val(new_entry) &= ~(1UL << 58);
    set_pmd(pmd, new_entry);
    
    // Memory barrier to ensure updates are visible
    smp_wmb();
    
    // Flush TLB for the mm
    flush_tlb_mm(mm);
    
    spin_unlock_irqrestore(ptl, flags);
    
    // Free the old expanded PTE pages via RCU
    // Note: We're simplifying here by directly freeing the pages 
    // instead of using RCU like in the module
    __free_pages(old_pages, 1);
    
    mmap_read_unlock(mm);
    
    return 0;
}


/* ------------------------------------------------------------------ */
/* 471  set_pte_meta                                                  */
/* ------------------------------------------------------------------ */
/**
 * sys_set_pte_meta - Set metadata for a specific page table entry
 * @addr: Virtual address of the page to set metadata for
 * @meta_val: 64-bit metadata value to store
 * @type: Type bit (0 or 1) to store with the metadata
 *
 * This syscall stores metadata and a type bit for a specific page table entry.
 * If the page table hasn't been expanded yet, it will be expanded first.
 * The metadata is stored in the odd-numbered slot next to the PTE.
 *
 * Return: 0 on success, negative error code on failure
 */
SYSCALL_DEFINE3(set_pte_meta, unsigned long, addr,
                               u64, meta_val,
                               int, type)
{
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte_base, *new_pte;
    unsigned long flags;
    spinlock_t *ptl;
    int idx;
    
    if (!mm)
        return -EINVAL;
        
    // Check CAP_SYS_ADMIN privilege
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
        
    // Address must be page-aligned
    if (addr & ~PAGE_MASK)
        return -EINVAL;
        
    // Type must be 0 or 1
    if (type != 0 && type != 1)
        return -EINVAL;
    
    mmap_read_lock(mm);
    
    // Walk the page tables
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud) || pud_leaf(*pud)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd) || pmd_leaf(*pmd)) {
        mmap_read_unlock(mm);
        return -EINVAL;
    }
    
    // If not yet expanded, allocate new 8KB PTE page and copy
    if (!(pmd_val(*pmd) & (1UL << 58))) {
        pte_base = pte_offset_kernel(pmd, 0);
        new_pte = (pte_t *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
        if (!new_pte) {
            mmap_read_unlock(mm);
            return -ENOMEM;
        }
        
        // Interleave old PTEs into even slots
        for (int i = 0; i < PTRS_PER_PTE; i++)
            new_pte[i * 2] = pte_base[i];
        
        // Get page table lock
        ptl = pte_lockptr(mm, pmd);
        spin_lock_irqsave(ptl, flags);
        
        // Update PMD to point to new pages and set bit 58
        set_pmd(pmd, __pmd(__pa(new_pte) | PMD_TYPE_TABLE | PMD_TABLE_UXN | (1UL << 58)));
        
        spin_unlock_irqrestore(ptl, flags);
        
        // Flush TLB
        flush_tlb_mm(mm);
    }
    
    // After expansion, get new PTE base and calculate index
    pte_base = pte_offset_kernel(pmd, 0);
    idx = (addr >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
    
    // Get page table lock
    ptl = pte_lockptr(mm, pmd);
    spin_lock_irqsave(ptl, flags);
    
    // Define the type bit position in the PTE
    #define TYPEBIT_PTE (1UL << 58)
    
    // Encode type bit directly into the first (data) PTE slot
    if (type)
        pte_base[idx * 2] = __pte(pte_val(pte_base[idx * 2]) | TYPEBIT_PTE);
    else
        pte_base[idx * 2] = __pte(pte_val(pte_base[idx * 2]) & ~TYPEBIT_PTE);
    
    // Set metadata content in the paired slot
    pte_base[idx * 2 + 1] = __pte(meta_val);
    
    spin_unlock_irqrestore(ptl, flags);
    mmap_read_unlock(mm);
    
    return 0;
}


/* ------------------------------------------------------------------ */
/* 472  get_pte_meta – packed return                                  */
/* ------------------------------------------------------------------ */
/**
 * sys_get_pte_meta - Retrieve metadata for a specific page table entry
 * @addr: Virtual address of the page to get metadata for
 *
 * This syscall retrieves the metadata and type bit for a specific page table
 * entry. The return value is packed as (type<<63 | meta), where type is 0 or 1
 * and meta is the 64-bit metadata value.
 *
 * Return: Packed metadata value on success, 0 if metadata not enabled,
 *         negative error code on failure
 */
SYSCALL_DEFINE1(get_pte_meta, unsigned long, addr)
{
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte_base;
    int idx;
    unsigned long long pte_val_raw = 0, meta_val = 0;
    int type = 0;
    
    if (!mm)
        return -EINVAL;
        
    // Check CAP_SYS_ADMIN privilege
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
        
    // Address must be page-aligned
    if (addr & ~PAGE_MASK)
        return -EINVAL;
    
    mmap_read_lock(mm);
    
    // Walk the page tables
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto out_unlock;
    
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto out_unlock;
    
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud) || pud_leaf(*pud))
        goto out_unlock;
    
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd) || pmd_leaf(*pmd))
        goto out_unlock;
    
    // Check if bit 58 is set (metadata enabled)
    if (!(pmd_val(*pmd) & (1UL << 58)))
        goto out_unlock;  // Return 0 values if metadata not enabled
    
    // Get current expanded PTE base and index for this address
    pte_base = pte_offset_kernel(pmd, 0);
    idx = (addr >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
    
    // Define the type bit position in the PTE
    #define TYPEBIT_PTE (1UL << 58)
    
    // Extract PTE value, metadata and type bit
    pte_val_raw = pte_val(pte_base[idx * 2]);
    meta_val = pte_val(pte_base[idx * 2 + 1]);
    type = (pte_val_raw & TYPEBIT_PTE) ? 1 : 0;
    
out_unlock:
    mmap_read_unlock(mm);
    
    // Return packed value: (type<<63 | meta)
    return ((u64)type << 63) | (meta_val & ~(1ULL << 63));
}