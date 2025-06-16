// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <linux/kvm_host.h>
#include <asm/virtcca_coda.h>

#include "../drivers/pci/msi/msi.h"

/**
 * virtcca_pci_read_msi_msg - secure dev read msi msg
 * @dev: Pointer to the pci_dev data structure of MSI-X device function
 * @msg: Msg information
 * @base: Msi base address
 *
 **/
void virtcca_pci_read_msi_msg(struct pci_dev *dev, struct msi_msg *msg,
	void __iomem *base)
{
	u64 pbase = mmio_va_to_pa(base);

	msg->address_lo = tmi_mmio_read(pbase + PCI_MSIX_ENTRY_LOWER_ADDR,
		CVM_RW_32_BIT, pci_dev_id(dev));
	msg->address_hi = tmi_mmio_read(pbase + PCI_MSIX_ENTRY_UPPER_ADDR,
		CVM_RW_32_BIT, pci_dev_id(dev));
	msg->data = tmi_mmio_read(pbase + PCI_MSIX_ENTRY_DATA, CVM_RW_32_BIT, pci_dev_id(dev));
}

/**
 * virtcca_pci_write_msi_msg - secure dev write msi msg
 * @desc: MSI-X description
 * @msg: Msg information
 *
 **/
bool virtcca_pci_write_msg_msi(struct msi_desc *desc, struct msi_msg *msg)
{
	if (!is_virtcca_cvm_enable())
		return false;

	void __iomem *base = pci_msix_desc_addr(desc);
	u32 ctrl = desc->pci.msix_ctrl;
	bool unmasked = !(ctrl & PCI_MSIX_ENTRY_CTRL_MASKBIT);
	u64 pbase = mmio_va_to_pa(base);
	struct pci_dev *pdev = (desc->dev != NULL &&
		dev_is_pci(desc->dev)) ? to_pci_dev(desc->dev) : NULL;

	if (!is_cc_dev(pci_dev_id(pdev)))
		return false;

	u64 addr = (u64)msg->address_lo | ((u64)msg->address_hi << 32);

	if (addr) {
		/* Get the offset of the its register of a specific device */
		u64 offset = addr - CVM_MSI_ORIG_IOVA;

		addr = get_g_cc_dev_msi_addr(pci_dev_id(pdev));
		addr += offset;
		if (!addr)
			return true;
	}
	tmi_mmio_write(pbase + PCI_MSIX_ENTRY_LOWER_ADDR,
		lower_32_bits(addr), CVM_RW_32_BIT, pci_dev_id(pdev));
	tmi_mmio_write(pbase + PCI_MSIX_ENTRY_UPPER_ADDR,
		upper_32_bits(addr), CVM_RW_32_BIT, pci_dev_id(pdev));
	tmi_mmio_write(pbase + PCI_MSIX_ENTRY_DATA,
		msg->data, CVM_RW_32_BIT, pci_dev_id(pdev));

	if (unmasked)
		pci_msix_write_vector_ctrl(desc, ctrl);
	tmi_mmio_read(pbase + PCI_MSIX_ENTRY_DATA,
		CVM_RW_32_BIT, pci_dev_id(pdev));

	return true;
}

void virtcca_msix_prepare_msi_desc(struct pci_dev *dev,
	struct msi_desc *desc, void __iomem *addr)
{
	desc->pci.msix_ctrl = tmi_mmio_read(mmio_va_to_pa(addr + PCI_MSIX_ENTRY_VECTOR_CTRL),
		CVM_RW_32_BIT, pci_dev_id(dev));
}

/*
 * If it is a safety device, write vector ctrl need
 * use tmi interface
 */
bool virtcca_pci_msix_write_vector_ctrl(struct msi_desc *desc, u32 ctrl)
{
	if (!is_virtcca_cvm_enable())
		return false;

	void __iomem *desc_addr = pci_msix_desc_addr(desc);
	struct pci_dev *pdev = (desc->dev != NULL &&
		dev_is_pci(desc->dev)) ? to_pci_dev(desc->dev) : NULL;

	if (pdev == NULL || !is_cc_dev(pci_dev_id(pdev)))
		return false;

	if (desc->pci.msi_attrib.can_mask)
		tmi_mmio_write(mmio_va_to_pa(desc_addr + PCI_MSIX_ENTRY_VECTOR_CTRL),
			ctrl, CVM_RW_32_BIT, pci_dev_id(pdev));
	return true;
}

/*
 * If it is a safety device, read msix need
 * use tmi interface
 */
bool virtcca_pci_msix_mask(struct msi_desc *desc)
{
	if (!is_virtcca_cvm_enable())
		return false;

	struct pci_dev *pdev = (desc->dev != NULL &&
		dev_is_pci(desc->dev)) ? to_pci_dev(desc->dev) : NULL;

	if (pdev == NULL || !is_cc_dev(pci_dev_id(pdev)))
		return false;

	/* Flush write to device */
	tmi_mmio_read(mmio_va_to_pa(desc->pci.mask_base), CVM_RW_32_BIT, pci_dev_id(pdev));
	return true;
}

/**
 * virtcca_msix_mask_all_cc - mask all secure dev msix c
 * @dev: Pointer to the pci_dev data structure of MSI-X device function
 * @base: Io address
 * @tsize: Number of entry
 * @dev_num: Dev number
 *
 * Returns:
 * %0 if msix mask all cc device success
 **/
int virtcca_msix_mask_all_cc(struct pci_dev *dev, void __iomem *base, int tsize, u64 dev_num)
{
	int i;
	u16 rw_ctrl;
	u32 ctrl = PCI_MSIX_ENTRY_CTRL_MASKBIT;
	u64 pbase = mmio_va_to_pa(base);

	if (pci_msi_ignore_mask)
		goto out;

	for (i = 0; i < tsize; i++, base += PCI_MSIX_ENTRY_SIZE) {
		tmi_mmio_write(pbase + PCI_MSIX_ENTRY_VECTOR_CTRL,
			ctrl, CVM_RW_32_BIT, dev_num);
	}

out:
	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &rw_ctrl);
	rw_ctrl &= ~PCI_MSIX_FLAGS_MASKALL;
	rw_ctrl |= 0;
	pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, rw_ctrl);

	pcibios_free_irq(dev);
	return 0;
}

/* If device is secure dev, read config need transfer to tmm module */
int virtcca_pci_generic_config_read(void __iomem *addr, unsigned char bus_num,
	unsigned int devfn, int size, u32 *val)
{
	u32 cvm_bit = size == 1 ? CVM_RW_8_BIT : size == 2 ? CVM_RW_16_BIT : CVM_RW_32_BIT;

	*val = tmi_mmio_read(mmio_va_to_pa(addr), cvm_bit, PCI_DEVID(bus_num, devfn));
	return 0;
}

/* If device is secure dev, write config need transfer to tmm module */
int virtcca_pci_generic_config_write(void __iomem *addr, unsigned char bus_num,
	unsigned int devfn, int size, u32 val)
{
	u32 cvm_bit = size == 1 ? CVM_RW_8_BIT : size == 2 ? CVM_RW_16_BIT : CVM_RW_32_BIT;

	tmi_mmio_write(mmio_va_to_pa(addr), val, cvm_bit, PCI_DEVID(bus_num, devfn));
	return 0;
}

/* Judge startup virtcca_cvm_host is enable and device is secure or not */
bool is_virtcca_pci_io_rw(struct vfio_pci_core_device *vdev)
{
	if (!is_virtcca_cvm_enable())
		return false;

	struct pci_dev *pdev = vdev->pdev;
	bool cc_dev = pdev == NULL ? false : is_cc_dev(pci_dev_id(pdev));

	if (cc_dev)
		return true;

	return false;
}
EXPORT_SYMBOL_GPL(is_virtcca_pci_io_rw);

/* Transfer to tmm write io value */
void virtcca_pci_io_write(struct vfio_pci_core_device *vdev, u64 val,
	u64 size, void __iomem *io)
{
	struct pci_dev *pdev = vdev->pdev;

	WARN_ON(tmi_mmio_write(mmio_va_to_pa(io), val, size, pci_dev_id(pdev)));
}
EXPORT_SYMBOL_GPL(virtcca_pci_io_write);

/* Transfer to tmm read io value */
u64 virtcca_pci_io_read(struct vfio_pci_core_device *vdev,
	u64 size, void __iomem *io)
{
	struct pci_dev *pdev = vdev->pdev;

	return tmi_mmio_read(mmio_va_to_pa(io), size, pci_dev_id(pdev));
}
EXPORT_SYMBOL_GPL(virtcca_pci_io_read);

/**
 * virtcca_pci_get_rom_size - obtain the actual size of the ROM image
 * @pdev: target PCI device
 * @rom: kernel virtual pointer to image of ROM
 * @size: size of PCI window
 *  return: size of actual ROM image
 *
 * Determine the actual length of the ROM image.
 * The PCI window size could be much larger than the
 * actual image size.
 */
size_t virtcca_pci_get_rom_size(void *p, void __iomem *rom, size_t size)
{
	void __iomem *image;
	int last_image;
	unsigned int length;
	struct pci_dev *pdev = (struct pci_dev *)p;

	if (!is_cc_dev(pci_dev_id(pdev)))
		return 0;
	image = rom;
	do {
		void __iomem *pds;
		/* Standard PCI ROMs start out with these bytes 55 AA */
		if (virtcca_readw(image, pdev) != 0xAA55) {
			pci_info(pdev, "Invalid PCI ROM header signature: expecting 0xaa55, got %#06x\n",
				 virtcca_readw(image, pdev));
			break;
		}
		/* get the PCI data structure and check its "PCIR" signature */
		pds = image + virtcca_readw(image + 24, pdev);
		/* The PCIR data structure must begin on a 4-byte boundary */
		if (!IS_ALIGNED((unsigned long)pds, 4)) {
			pci_info(pdev, "Invalid PCI ROM header signature: PCIR %#06x\n",
				 virtcca_readw(image + 24, pdev));
			break;
		}
		if (virtcca_readl(pds, pdev) != 0x52494350) {
			pci_info(pdev, "Invalid PCI ROM data signature: expecting 0x52494350, got %#010x\n",
				 virtcca_readl(pds, pdev));
			break;
		}
		last_image = virtcca_readb(pds + 21, pdev) & 0x80;
		length = virtcca_readw(pds + 16, pdev);
		image += length * 512;
		/* Avoid iterating through memory outside the resource window */
		if (image >= rom + size)
			break;
		if (!last_image) {
			if (virtcca_readw(image, pdev) != 0xAA55) {
				pci_info(pdev, "No more image in the PCI ROM\n");
				break;
			}
		}
	} while (length && !last_image);

	/* never return a size larger than the PCI resource window */
	/* there are known ROMs that get the size wrong */
	return min((size_t)(image - rom), size);
}
EXPORT_SYMBOL_GPL(virtcca_pci_get_rom_size);
