/* SPDX-License-Identifier: GPL-2.0 */
/*
 * pte_meta_syscalls.c - Page table entry metadata system calls
 *
 * This file implements four system calls that manage page table entry metadata:
 * 1. sys_enable_pte_meta  - Expands 4KiB PTE page to 8KiB and sets PMD PEN bit
 * 2. sys_disable_pte_meta - Collapses back to 4KiB and clears PMD PEN bit
 * 3. sys_set_pte_meta     - Stores 64-bit metadata and MDP bit (0/1)
 * 4. sys_get_pte_meta     - Returns packed value: (MDP<<63 | meta)
 *
 * All syscalls require CAP_SYS_ADMIN capability and operate on current->mm.
 * The metadata is stored in an expanded PTE table where each entry is 128 bits
 * instead of the standard 64 bits. The expansion is indicated by PEN bit (bit 58) in the PMD.
 * The MDP bit (bit 58) in PTE indicates metadata presence.
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

#ifdef CONFIG_128BITS_PTE

/* Structure for MDP=1 buffer header */
struct metadata_header {
    u16 version;
    u16 type;
    u32 length;
} __packed;

/* ------------------------------------------------------------------ */
/* 469  enable_pte_meta                                               */
/* ------------------------------------------------------------------ */
/**
 * sys_enable_pte_meta - Enable metadata storage for a page table
 * @addr: Virtual address within the page table to enable metadata for
 *
 * This syscall expands a 4KiB PTE page to 8KiB to store metadata alongside
 * each PTE. The expansion is indicated by setting the PEN bit (bit 58) in the PMD.
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
    
    // Check if PEN bit is already set (metadata already enabled)
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
    
    // Update the PMD to point to the new pages and set PEN bit
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
 * metadata slots and clearing the PEN bit (bit 58) in the PMD. The original PTEs are
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
    
    // Check if PEN bit is not set (metadata not enabled)
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
    
    // 2) Free any MDP=1 allocations before collapsing
    for (i = 0; i < PTRS_PER_PTE; i++) {
        pte_t data_pte = old_pte[i * 2];
        u64 meta_val = pte_val(old_pte[i * 2 + 1]);
        if (pte_val(data_pte) & (1UL << 58)) {
            // Validate physical address before converting and freeing
            if (meta_val && pfn_valid(__phys_to_pfn(meta_val))) {
                void *kptr = __va(meta_val);
                kfree(kptr);
            }
        }
    }

    // 3) Copy even slots over under PT lock and install 4KiB table
    ptl = pte_lockptr(mm, pmd);
    spin_lock_irqsave(ptl, flags);

    for (i = 0; i < PTRS_PER_PTE; i++)
        new_pte[i] = old_pte[i * 2]; // drop odd-slot metadata

    paddr = virt_to_phys(new_pte);
    pmd_t new_entry = __pmd(__phys_to_pmd_val(paddr) | PMD_TYPE_TABLE | PMD_TABLE_UXN);
    pmd_val(new_entry) &= ~(1UL << 58);
    set_pmd(pmd, new_entry);



    smp_wmb();
    flush_tlb_mm(mm);

    spin_unlock_irqrestore(ptl, flags);

    // 4) Free old expanded PTE pages
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
 * @mdp: MDP bit (0 or 1) indicating metadata format
 * @meta_data: User space buffer containing metadata
 *
 * This syscall stores metadata for a specific page table entry with behavior
 * depending on the MDP bit:
 * - MDP=0: meta_data contains single u64, stored directly in metadata slot
 * - MDP=1: meta_data contains structured buffer (version, type, length, payload),
 *          kernel memory is allocated and physical address stored in metadata slot
 *
 * If the page table hasn't been expanded yet, it will be expanded first.
 * The metadata is stored in the odd-numbered slot next to the PTE.
 *
 * Return: 0 on success, negative error code on failure
 */
SYSCALL_DEFINE3(set_pte_meta, unsigned long, addr,
                               int, mdp,
                               void __user *, meta_data)
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
    u64 metadata_value = 0;
    void *allocated_mem = NULL;
    
    if (!mm)
        return -EINVAL;
        
    // Check CAP_SYS_ADMIN privilege
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
        
    // Address must be page-aligned
    if (addr & ~PAGE_MASK)
        return -EINVAL;
        
    // MDP bit must be 0 or 1
    if (mdp != 0 && mdp != 1)
        return -EINVAL;
        
    if (!meta_data)
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
    
    // Handle metadata based on MDP bit
    if (mdp == 0) {
        // MDP=0: Copy single u64 directly from user space
        if (copy_from_user(&metadata_value, meta_data, sizeof(u64))) {
            mmap_read_unlock(mm);
            return -EFAULT;
        }
    } else {
        // MDP=1: Parse structured buffer and allocate memory
        struct metadata_header header;
        
        // Copy header from user space
        if (copy_from_user(&header, meta_data, sizeof(header))) {
            mmap_read_unlock(mm);
            return -EFAULT;
        }
        
        // Validate length (prevent excessive allocations and integer overflow)
        if (header.length > PAGE_SIZE * 4) {  // Limit to 4 pages
            mmap_read_unlock(mm);
            return -EINVAL;
        }
        
        // Check for integer overflow in size calculation
        size_t total_size;
        if (check_add_overflow(sizeof(header), (size_t)header.length, &total_size)) {
            mmap_read_unlock(mm);
            return -EINVAL;
        }
        allocated_mem = kmalloc(total_size, GFP_KERNEL);
        if (!allocated_mem) {
            mmap_read_unlock(mm);
            return -ENOMEM;
        }
        
        // Copy entire buffer (header + payload) from user space
        if (copy_from_user(allocated_mem, meta_data, total_size)) {
            kfree(allocated_mem);
            mmap_read_unlock(mm);
            return -EFAULT;
        }
        
        // Store physical address of allocated memory
        metadata_value = __pa(allocated_mem);
    }
    
    // Get page table lock first to prevent races
    ptl = pte_lockptr(mm, pmd);
    spin_lock_irqsave(ptl, flags);
    
    // Re-check if expansion is needed under lock
    if (!(pmd_val(*pmd) & (1UL << 58))) {
        pte_base = pte_offset_kernel(pmd, 0);
        
        // Release lock temporarily for allocation
        spin_unlock_irqrestore(ptl, flags);
        
        new_pte = (pte_t *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
        if (!new_pte) {
            if (allocated_mem)
                kfree(allocated_mem);
            mmap_read_unlock(mm);
            return -ENOMEM;
        }
        
        // Interleave old PTEs into even slots
        for (int i = 0; i < PTRS_PER_PTE; i++)
            new_pte[i * 2] = pte_base[i];
        
        // Re-acquire lock and check again
        spin_lock_irqsave(ptl, flags);
        
        // Final check - another thread might have expanded it
        if (!(pmd_val(*pmd) & (1UL << 58))) {
            // Update PMD to point to new pages and set PEN bit
            set_pmd(pmd, __pmd(__pa(new_pte) | PMD_TYPE_TABLE | PMD_TABLE_UXN | (1UL << 58)));
            spin_unlock_irqrestore(ptl, flags);
            
            // Flush TLB
            flush_tlb_mm(mm);
        } else {
            // Another thread expanded it, free our allocation
            spin_unlock_irqrestore(ptl, flags);
            free_pages((unsigned long)new_pte, 1);
        }
    } else {
        // Already expanded, just release lock
        spin_unlock_irqrestore(ptl, flags);
    }
    
    // After expansion, get new PTE base and calculate index
    pte_base = pte_offset_kernel(pmd, 0);
    idx = (addr >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
    
    // Get page table lock
    ptl = pte_lockptr(mm, pmd);
    spin_lock_irqsave(ptl, flags);
    
    // Define the MDP bit position in the PTE
    #define MDP_BIT_PTE (1UL << 58)
    
    // Check if we're replacing existing MDP=1 metadata and free it
    pte_t old_data_pte = pte_base[idx * 2];
    u64 old_meta_val = pte_val(pte_base[idx * 2 + 1]);
    if ((pte_val(old_data_pte) & MDP_BIT_PTE) && old_meta_val) {
        // Free old MDP=1 allocation if valid
        if (pfn_valid(__phys_to_pfn(old_meta_val))) {
            void *old_kptr = __va(old_meta_val);
            kfree(old_kptr);
        }
    }
    
    // Encode MDP bit directly into the first (data) PTE slot
    if (mdp)
        pte_base[idx * 2] = __pte(pte_val(pte_base[idx * 2]) | MDP_BIT_PTE);
    else
        pte_base[idx * 2] = __pte(pte_val(pte_base[idx * 2]) & ~MDP_BIT_PTE);
    
    // Set metadata content in the paired (odd) slot
    pte_base[idx * 2 + 1] = __pte(metadata_value);
    
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
 * @buffer: User space buffer to copy metadata into
 *
 * This syscall retrieves metadata for a specific page table entry with behavior
 * depending on the MDP bit:
 * - MDP=0: copies u64 metadata directly to user buffer
 * - MDP=1: reads physical address from metadata slot, then copies the allocated
 *          memory contents (header + payload) to user buffer
 *
 * Return: 0 on success, negative error code on failure
 */
SYSCALL_DEFINE2(get_pte_meta, unsigned long, addr, void __user *, buffer)
{
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte_base;
    int idx;
    unsigned long long pte_val_raw = 0, meta_val = 0;
    int mdp_bit = 0;
    void *kernel_mem;
    struct metadata_header *header;
    size_t copy_size;
    
    if (!mm)
        return -EINVAL;
        
    // Check CAP_SYS_ADMIN privilege
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
        
    // Address must be page-aligned
    if (addr & ~PAGE_MASK)
        return -EINVAL;
        
    if (!buffer)
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
    
    // Check if PEN bit is set (metadata enabled)
    if (!(pmd_val(*pmd) & (1UL << 58))) {
        mmap_read_unlock(mm);
        return -ENODATA; // Metadata not enabled
    }
    
    // Get current expanded PTE base and index for this address
    pte_base = pte_offset_kernel(pmd, 0);
    idx = (addr >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
    
    // Define the MDP bit position in the PTE
    #define MDP_BIT_PTE (1UL << 58)
    
    // Extract PTE value, metadata and MDP bit (data in even, metadata in odd)
    pte_val_raw = pte_val(pte_base[idx * 2]);
    meta_val = pte_val(pte_base[idx * 2 + 1]);
    mdp_bit = (pte_val_raw & MDP_BIT_PTE) ? 1 : 0;
    
    mmap_read_unlock(mm);
    
    // Handle copying based on MDP bit
    if (mdp_bit == 0) {
        // MDP=0: Copy u64 metadata directly to user buffer
        if (copy_to_user(buffer, &meta_val, sizeof(u64))) {
            return -EFAULT;
        }
    } else {
        // MDP=1: meta_val contains physical address of allocated memory
        // Validate physical address before accessing
        if (!meta_val || !pfn_valid(__phys_to_pfn(meta_val))) {
            return -EINVAL;
        }
        
        kernel_mem = __va(meta_val);
        header = (struct metadata_header *)kernel_mem;
        
        // Validate header length to prevent buffer overflow
        if (header->length > PAGE_SIZE * 4) {
            return -EINVAL;
        }
        
        // Calculate total size to copy (header + payload) with overflow check
        if (check_add_overflow(sizeof(struct metadata_header), (size_t)header->length, &copy_size)) {
            return -EINVAL;
        }
        
        // Copy the entire allocated memory (header + payload) to user buffer
        if (copy_to_user(buffer, kernel_mem, copy_size)) {
            return -EFAULT;
        }
    }
    
    return 0;
    
out_unlock:
    mmap_read_unlock(mm);
    return -EINVAL;
}

#endif /* CONFIG_128BITS_PTE */