// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"
#include "common/driver.h"
#include "common/cq.h"
#include "common/qp.h"
#include "common/xsc_lag.h"
#include "common/xsc_port_ctrl.h"
#include "devlink.h"
#include "eswitch.h"
#include "fw/xsc_counters.h"
#include "xsc_pci_ctrl.h"

unsigned int xsc_debug_mask;
module_param_named(debug_mask, xsc_debug_mask, uint, 0644);
MODULE_PARM_DESC(debug_mask,
		 "debug mask: 1=dump cmd data, 2=dump cmd exec time, 3=both. Default=0");

unsigned int xsc_log_level = XSC_LOG_LEVEL_WARN;
module_param_named(log_level, xsc_log_level, uint, 0644);
MODULE_PARM_DESC(log_level,
		 "lowest log level to print: 0=debug, 1=info, 2=warning, 3=error. Default=1");
EXPORT_SYMBOL(xsc_log_level);

static bool probe_vf = 1;
module_param_named(probe_vf, probe_vf, bool, 0644);
MODULE_PARM_DESC(probe_vf, "probe VFs or not, 0 = not probe, 1 = probe. Default = 1");

static bool xsc_hw_reset;

#define DRIVER_NAME			"xsc_pci"
#define DRIVER_VERSION			"0.1.0"
#define ETH_DRIVER_NAME			"xsc_eth"

static const struct pci_device_id xsc_pci_id_table[] = {
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MC_VF_DEV_ID),
		.driver_data = XSC_PCI_DEV_IS_VF },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MF_HOST_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MF_HOST_VF_DEV_ID),
		.driver_data = XSC_PCI_DEV_IS_VF },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MF_SOC_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MS_VF_DEV_ID),
		.driver_data = XSC_PCI_DEV_IS_VF },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MV_HOST_PF_DEV_ID) },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MV_HOST_VF_DEV_ID),
		.driver_data = XSC_PCI_DEV_IS_VF },
	{ PCI_DEVICE(XSC_PCI_VENDOR_ID, XSC_MV_SOC_PF_DEV_ID) },
	{ 0 }
};

MODULE_DEVICE_TABLE(pci, xsc_pci_id_table);

static const struct xsc_device_product_info xsc_product_list[] = {
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MC_50, "metaConnect-50")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MC_100, "metaConnect-100")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MC_200, "metaConnect-200")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MC_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MC_400S, "metaConnect-400S")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MF_HOST_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MF_50, "metaFusion-50")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MF_HOST_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MF_200, "metaFusion-200")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_50, "metaScale-50")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_100Q, "metaScale-100Q")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_200, "metaScale-200")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_200S, "metaScale-200S")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_400M, "metaScale-400M")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MS_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MS_200_OCP, "metaScale-200-OCP")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MV_HOST_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MV_100, "metaVisor-100")},
	{XSC_DEVICE_PRODUCT_INFO(XSC_PCI_VENDOR_ID, XSC_MV_HOST_PF_DEV_ID,
				 XSC_SUB_DEV_ID_MV_200, "metaVisor-200")},
	{0}
};

#define	IS_VIRT_FUNCTION(id) ((id)->driver_data == XSC_PCI_DEV_IS_VF)

static bool need_write_reg_directly(void *in)
{
	struct xsc_inbox_hdr *hdr;
	struct xsc_ioctl_mbox_in *req;
	struct xsc_ioctl_data_tl *tl;
	char *data;

	hdr = (struct xsc_inbox_hdr *)in;
	if (unlikely(be16_to_cpu(hdr->opcode) == XSC_CMD_OP_IOCTL_FLOW)) {
		req = (struct xsc_ioctl_mbox_in *)in;
		data = (char *)req->data;
		tl = (struct xsc_ioctl_data_tl *)data;
		if (tl->opmod == XSC_IOCTL_OP_ADD) {
			if (unlikely(tl->table == XSC_FLOW_DMA_WR || tl->table == XSC_FLOW_DMA_RD))
				return true;
		}
	}
	return false;
}

int xsc_cmd_exec(struct xsc_core_device *dev, void *in, int in_size, void *out,
		 int out_size)
{
	struct xsc_inbox_hdr *hdr = (struct xsc_inbox_hdr *)in;

	hdr->ver = 0;
	if (hdr->ver != 0) {
		xsc_core_warn(dev, "recv an unexpected cmd ver = %d, opcode = %d\n",
			      be16_to_cpu(hdr->ver), be16_to_cpu(hdr->opcode));
		WARN_ON(hdr->ver != 0);
	}

	if (need_write_reg_directly(in))
		return xsc_cmd_write_reg_directly(dev, in, in_size, out,
						  out_size, dev->glb_func_id);
	return _xsc_cmd_exec(dev, in, in_size, out, out_size);
}
EXPORT_SYMBOL(xsc_cmd_exec);

static int set_dma_caps(struct pci_dev *pdev)
{
	int err = 0;

	err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (err)
		err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	else
		err = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));

	if (!err)
		dma_set_max_seg_size(&pdev->dev, 2u * 1024 * 1024 * 1024);

	return err;
}

static int xsc_pci_enable_device(struct xsc_core_device *dev)
{
	struct pci_dev *pdev = dev->pdev;
	int err = 0;

	mutex_lock(&dev->pci_status_mutex);
	if (dev->pci_status == XSC_PCI_STATUS_DISABLED) {
		err = pci_enable_device(pdev);
		if (!err)
			dev->pci_status = XSC_PCI_STATUS_ENABLED;
	}
	mutex_unlock(&dev->pci_status_mutex);

	return err;
}

static void xsc_pci_disable_device(struct xsc_core_device *dev)
{
	struct pci_dev *pdev = dev->pdev;

	mutex_lock(&dev->pci_status_mutex);
	if (dev->pci_status == XSC_PCI_STATUS_ENABLED) {
		pci_disable_device(pdev);
		dev->pci_status = XSC_PCI_STATUS_DISABLED;
	}
	mutex_unlock(&dev->pci_status_mutex);
}

int xsc_priv_init(struct xsc_core_device *dev)
{
	struct xsc_priv *priv = &dev->priv;

	strscpy(priv->name, dev_name(&dev->pdev->dev), XSC_MAX_NAME_LEN);
	priv->name[XSC_MAX_NAME_LEN - 1] = 0;

	INIT_LIST_HEAD(&priv->ctx_list);
	spin_lock_init(&priv->ctx_lock);
	mutex_init(&dev->intf_state_mutex);

	return 0;
}

int xsc_dev_res_init(struct xsc_core_device *dev)
{
	struct xsc_dev_resource *dev_res = NULL;

	dev_res = kvzalloc(sizeof(*dev_res), GFP_KERNEL);
	if (!dev_res)
		return -ENOMEM;

	dev->dev_res = dev_res;
	/* init access lock */
	spin_lock_init(&dev->reg_access_lock.lock);
	mutex_init(&dev_res->alloc_mutex);
	mutex_init(&dev_res->pgdir_mutex);
	INIT_LIST_HEAD(&dev_res->pgdir_list);
	spin_lock_init(&dev_res->mkey_lock);

	return 0;
}

void xsc_dev_res_cleanup(struct xsc_core_device *dev)
{
	kfree(dev->dev_res);
	dev->dev_res = NULL;
}

void xsc_init_reg_addr(struct xsc_core_device *dev)
{
	if (xsc_core_is_pf(dev)) {
		dev->regs.cpm_get_lock = HIF_CPM_LOCK_GET_REG_ADDR;
		dev->regs.cpm_put_lock = HIF_CPM_LOCK_PUT_REG_ADDR;
		dev->regs.cpm_lock_avail = HIF_CPM_LOCK_AVAIL_REG_ADDR;
		dev->regs.cpm_data_mem = HIF_CPM_IDA_DATA_MEM_ADDR;
		dev->regs.cpm_cmd = HIF_CPM_IDA_CMD_REG_ADDR;
		dev->regs.cpm_addr = HIF_CPM_IDA_ADDR_REG_ADDR;
		dev->regs.cpm_busy = HIF_CPM_IDA_BUSY_REG_ADDR;
	} else {
		dev->regs.tx_db = TX_DB_FUNC_MEM_ADDR;
		dev->regs.rx_db = RX_DB_FUNC_MEM_ADDR;
		dev->regs.complete_db = DB_CQ_FUNC_MEM_ADDR;
		dev->regs.complete_reg = DB_CQ_CID_DIRECT_MEM_ADDR;
		dev->regs.event_db = DB_EQ_FUNC_MEM_ADDR;
		dev->regs.cpm_get_lock = CPM_LOCK_GET_REG_ADDR;
		dev->regs.cpm_put_lock = CPM_LOCK_PUT_REG_ADDR;
		dev->regs.cpm_lock_avail = CPM_LOCK_AVAIL_REG_ADDR;
		dev->regs.cpm_data_mem = CPM_IDA_DATA_MEM_ADDR;
		dev->regs.cpm_cmd = CPM_IDA_CMD_REG_ADDR;
		dev->regs.cpm_addr = CPM_IDA_ADDR_REG_ADDR;
		dev->regs.cpm_busy = CPM_IDA_BUSY_REG_ADDR;
	}
}

int xsc_dev_init(struct xsc_core_device *dev)
{
	int err = 0;

	xsc_priv_init(dev);

	err = xsc_dev_res_init(dev);
	if (err) {
		xsc_core_err(dev, "xsc dev res init failed %d\n", err);
		goto err_res_init;
	}

	/* create debugfs */
	err = xsc_debugfs_init(dev);
	if (err) {
		xsc_core_err(dev, "xsc_debugfs_init failed %d\n", err);
		goto err_debugfs_init;
	}

	return 0;

err_debugfs_init:
	xsc_dev_res_cleanup(dev);
err_res_init:
	return err;
}

void xsc_dev_cleanup(struct xsc_core_device *dev)
{
//	iounmap(dev->iseg);
	xsc_debugfs_fini(dev);
	xsc_dev_res_cleanup(dev);
}

static void xsc_product_info(struct pci_dev *pdev)
{
	const struct xsc_device_product_info *p_info = xsc_product_list;

	while (p_info->vendor) {
		if (pdev->device == p_info->device && pdev->subsystem_device == p_info->subdevice) {
			pr_info("Product: %s, Vendor: Yunsilicon\n", p_info->product_name);
			break;
		}
		p_info++;
	}
}

static int xsc_pci_init(struct xsc_core_device *dev, const struct pci_device_id *id)
{
	struct pci_dev *pdev = dev->pdev;
	int err = 0;
	int bar_num = 0;
	void __iomem *bar_base = NULL;

	mutex_init(&dev->pci_status_mutex);
	dev->priv.numa_node = dev_to_node(&pdev->dev);
	if (dev->priv.numa_node == -1)
		dev->priv.numa_node = 0;

	/* enable the device */
	err = xsc_pci_enable_device(dev);
	if (err) {
		xsc_core_err(dev, "failed to enable PCI device: err=%d\n", err);
		goto err_ret;
	}

	err = pci_request_region(pdev, bar_num, KBUILD_MODNAME);
	if (err) {
		xsc_core_err(dev, "failed to request %s pci_region=%d: err=%d\n",
			     KBUILD_MODNAME, bar_num, err);
		goto err_disable;
	}

	pci_set_master(pdev);

	err = set_dma_caps(pdev);
	if (err) {
		xsc_core_err(dev, "failed to set DMA capabilities mask: err=%d\n", err);
		goto err_clr_master;
	}

	bar_base = pci_ioremap_bar(pdev, bar_num);
	if (!bar_base) {
		xsc_core_err(dev, "failed to ioremap %s bar%d\n", KBUILD_MODNAME, bar_num);
		goto err_clr_master;
	}

	err = pci_save_state(pdev);
	if (err) {
		xsc_core_err(dev, "pci_save_state failed: err=%d\n", err);
		goto err_io_unmap;
	}

	dev->bar_num = bar_num;
	dev->bar = bar_base;

	xsc_init_reg_addr(dev);

	return 0;

err_io_unmap:
	pci_iounmap(pdev, bar_base);
err_clr_master:
	pci_clear_master(pdev);
	pci_release_region(pdev, bar_num);
err_disable:
	xsc_pci_disable_device(dev);
err_ret:
	return err;
}

static void xsc_pci_fini(struct xsc_core_device *dev)
{
	struct pci_dev *pdev = dev->pdev;

	if (dev->bar)
		pci_iounmap(pdev, dev->bar);
	pci_clear_master(pdev);
	pci_release_region(pdev, dev->bar_num);
	xsc_pci_disable_device(dev);
}

static int xsc_check_cmdq_version(struct xsc_core_device *dev)
{
	struct xsc_cmd_query_cmdq_ver_mbox_out *out;
	struct xsc_cmd_query_cmdq_ver_mbox_in in;

	int err;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out) {
		err = -ENOMEM;
		goto no_mem_out;
	}

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_CMDQ_VERSION);

	err = xsc_cmd_exec(dev, &in, sizeof(in), out, sizeof(*out));
	if (err)
		goto out_out;

	if (out->hdr.status) {
		err = xsc_cmd_status_to_err(&out->hdr);
		goto out_out;
	}

	if (be16_to_cpu(out->cmdq_ver) != CMDQ_VERSION) {
		xsc_core_err(dev, "cmdq version check failed, expecting version %d, actual version %d\n",
			     CMDQ_VERSION, be16_to_cpu(out->cmdq_ver));
		err = -EINVAL;
		goto out_out;
	}
	dev->cmdq_ver = CMDQ_VERSION;

out_out:
	kfree(out);
no_mem_out:
	return err;
}

int xsc_reset_function_resource(struct xsc_core_device *dev)
{
	struct xsc_function_reset_mbox_in in;
	struct xsc_function_reset_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_FUNCTION_RESET);
	in.glb_func_id = cpu_to_be16(dev->glb_func_id);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status)
		return -EINVAL;

	return 0;
}

static int xsc_fpga_not_supported(struct xsc_core_device *dev)
{
#define FPGA_VERSION_H 0x100
#define ASIC_VERSION_H 0x20230423
	u32 ver_h;

	if (!xsc_core_is_pf(dev))
		return 0;

	ver_h = REG_RD32(dev, HIF_CPM_CHIP_VERSION_H_REG_ADDR);
	if (ver_h != FPGA_VERSION_H && ver_h != ASIC_VERSION_H) {
		xsc_core_err(dev, "fpga version 0x%x not supported\n", ver_h);
		return 1;
	}

	return 0;
}

int xsc_chip_type(struct xsc_core_device *dev)
{
	switch (dev->pdev->device) {
	case XSC_MC_PF_DEV_ID:
	case XSC_MC_VF_DEV_ID:
		return XSC_CHIP_MC;
	case XSC_MF_HOST_PF_DEV_ID:
	case XSC_MF_HOST_VF_DEV_ID:
	case XSC_MF_SOC_PF_DEV_ID:
		return XSC_CHIP_MF;
	case XSC_MS_PF_DEV_ID:
	case XSC_MS_VF_DEV_ID:
		return XSC_CHIP_MS;
	case XSC_MV_HOST_PF_DEV_ID:
	case XSC_MV_HOST_VF_DEV_ID:
	case XSC_MV_SOC_PF_DEV_ID:
		return XSC_CHIP_MV;
	default:
		return XSC_CHIP_UNKNOWN;
	}
}
EXPORT_SYMBOL(xsc_chip_type);

#if defined(__sw_64__)
static void xsc_enable_relaxed_order(struct xsc_core_device *dev)
{
	struct xsc_cmd_enable_relaxed_order_in in;
	struct xsc_cmd_enable_relaxed_order_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ENABLE_RELAXED_ORDER);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		goto err_out;

	if (out.hdr.status) {
		err = xsc_cmd_status_to_err(&out.hdr);
		goto err_out;
	}

	return;
err_out:
	xsc_core_warn(dev, "Failed to enable relaxed order %d\n", err);
}
#endif

static int xsc_cmd_activate_hw_config(struct xsc_core_device *dev)
{
	struct xsc_cmd_activate_hw_config_mbox_in in;
	struct xsc_cmd_activate_hw_config_mbox_out out;
	int err = 0;

	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ACTIVATE_HW_CONFIG);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;
	if (out.hdr.status)
		return xsc_cmd_status_to_err(&out.hdr);
	dev->board_info->hw_config_activated = 1;
	return 0;
}

static int xsc_activate_hw_config(struct xsc_core_device *dev)
{
	if (dev->board_info->hw_config_activated)
		return 0;

	return xsc_cmd_activate_hw_config(dev);
}

static int xsc_init_once(struct xsc_core_device *dev)
{
	int err;

	err = xsc_cmd_init(dev);
	if (err) {
		xsc_core_err(dev, "Failed initializing command interface, aborting\n");
		goto err_cmd_init;
	}

	err = xsc_check_cmdq_version(dev);
	if (err) {
		xsc_core_err(dev, "Failed to check cmdq version\n");
		goto err_cmdq_ver_chk;
	}

	err = xsc_cmd_query_hca_cap(dev, &dev->caps);
	if (err) {
		xsc_core_err(dev, "Failed to query hca, err=%d\n", err);
		goto err_cmdq_ver_chk;
	}

	err = xsc_query_guid(dev);
	if (err) {
		xsc_core_err(dev, "failed to query guid, err=%d\n", err);
		goto err_cmdq_ver_chk;
	}

	err = xsc_activate_hw_config(dev);
	if (err) {
		xsc_core_err(dev, "failed to activate hw config, err=%d\n", err);
		goto err_cmdq_ver_chk;
	}

	err = xsc_reset_function_resource(dev);
	if (err) {
		xsc_core_err(dev, "Failed to reset function resource\n");
		goto err_cmdq_ver_chk;
	}

	funcid_to_pf_vf_index(&dev->caps, dev->glb_func_id, &dev->pcie_no,
			      &dev->pf_id, &dev->vf_id);
	xsc_init_cq_table(dev);
	xsc_init_qp_table(dev);
	xsc_eq_init(dev);

#ifdef CONFIG_XSC_SRIOV
	err = xsc_sriov_init(dev);
	if (err) {
		xsc_core_err(dev, "Failed to init sriov %d\n", err);
		goto err_sriov_init;
	}
	err = xsc_eswitch_init(dev);
	if (err) {
		xsc_core_err(dev, "Failed to init eswitch %d\n", err);
		goto err_eswitch_init;
	}
#endif

#if defined(__sw_64__)
	xsc_enable_relaxed_order(dev);
#endif
	return 0;

#ifdef CONFIG_XSC_SRIOV
err_eswitch_init:
	xsc_sriov_cleanup(dev);
err_sriov_init:
	xsc_eq_cleanup(dev);
	xsc_cleanup_qp_table(dev);
	xsc_cleanup_cq_table(dev);
#endif
err_cmdq_ver_chk:
	xsc_cmd_cleanup(dev);
err_cmd_init:
	return err;
}

static int xsc_cleanup_once(struct xsc_core_device *dev)
{
#ifdef CONFIG_XSC_SRIOV
	xsc_eswitch_cleanup(dev);
	xsc_sriov_cleanup(dev);
#endif
	xsc_eq_cleanup(dev);
	xsc_cleanup_qp_table(dev);
	xsc_cleanup_cq_table(dev);
	xsc_cmd_cleanup(dev);
	return 0;
}

static int xsc_load(struct xsc_core_device *dev)
{
	int err;

	err = xsc_irq_eq_create(dev);
	if (err) {
		xsc_core_err(dev, "xsc_irq_eq_create failed %d\n", err);
		goto err_irq_eq_create;
	}

#ifdef CONFIG_XSC_SRIOV
	err = xsc_sriov_attach(dev);
	if (err) {
		xsc_core_err(dev, "sriov init failed %d\n", err);
		goto err_sriov;
	}
#endif
	return 0;

#ifdef CONFIG_XSC_SRIOV
err_sriov:
	xsc_irq_eq_destroy(dev);
#endif
err_irq_eq_create:
	return err;
}

static int xsc_unload(struct xsc_core_device *dev)
{
#ifdef CONFIG_XSC_SRIOV
	xsc_sriov_detach(dev);
#endif
	if (xsc_fw_is_available(dev))
		xsc_irq_eq_destroy(dev);

	return 0;
}

int xsc_load_one(struct xsc_core_device *dev, bool boot)
{
	int err = 0;

	mutex_lock(&dev->intf_state_mutex);
	if (test_bit(XSC_INTERFACE_STATE_UP, &dev->intf_state)) {
		xsc_core_warn(dev, "interface is up, NOP\n");
		goto out;
	}

	if (test_bit(XSC_INTERFACE_STATE_TEARDOWN, &dev->intf_state)) {
		xsc_core_warn(dev, "device is being removed, stop load\n");
		err = -ENODEV;
		goto out;
	}

	if (boot) {
		err = xsc_init_once(dev);
		if (err) {
			xsc_core_err(dev, "xsc_init_once failed %d\n", err);
			goto err_dev_init;
		}
	}

	err = xsc_load(dev);
	if (err) {
		xsc_core_err(dev, "xsc_load failed %d\n", err);
		goto err_load;
	}

	if (!dev->reg_mr_via_cmdq && (xsc_core_is_pf(dev) || !dev->pdev->physfn)) {
		err = xsc_create_res(dev);
		if (err) {
			xsc_core_err(dev, "Failed to create resource, err=%d\n", err);
			goto err_create_res;
		}
	}

	if (boot) {
		err = xsc_devlink_register(priv_to_devlink(dev), dev->device);
		if (err)
			goto err_devlink_reg;
	}

	if (xsc_core_is_pf(dev))
		xsc_lag_add_xdev(dev);

	if (xsc_device_registered(dev)) {
		xsc_attach_device(dev);
	} else {
		err = xsc_register_device(dev);
		if (err) {
			xsc_core_err(dev, "register device failed %d\n", err);
			goto err_reg_dev;
		}
	}

	err = xsc_port_ctrl_probe(dev);
	if (err) {
		xsc_core_err(dev, "failed to probe port control node\n");
		goto err_port_ctrl;
	}

	set_bit(XSC_INTERFACE_STATE_UP, &dev->intf_state);
	mutex_unlock(&dev->intf_state_mutex);

	return err;

err_port_ctrl:
	xsc_unregister_device(dev);
err_reg_dev:
	if (xsc_core_is_pf(dev))
		xsc_lag_remove_xdev(dev);
	if (boot)
		xsc_devlink_unregister(priv_to_devlink(dev));
err_devlink_reg:
	if (!dev->reg_mr_via_cmdq && (xsc_core_is_pf(dev) || !dev->pdev->physfn))
		xsc_destroy_res(dev);

err_create_res:
	xsc_unload(dev);

err_load:
	if (boot)
		xsc_cleanup_once(dev);
err_dev_init:
out:
	mutex_unlock(&dev->intf_state_mutex);
	return err;
}

int xsc_unload_one(struct xsc_core_device *dev, bool cleanup)
{
	xsc_port_ctrl_remove(dev);
	xsc_devlink_unregister(priv_to_devlink(dev));
	if (cleanup)
		xsc_unregister_device(dev);
	mutex_lock(&dev->intf_state_mutex);
	if (!test_bit(XSC_INTERFACE_STATE_UP, &dev->intf_state)) {
		xsc_core_warn(dev, "%s: interface is down, NOP\n",
			      __func__);
		if (cleanup)
			xsc_cleanup_once(dev);
		goto out;
	}

	clear_bit(XSC_INTERFACE_STATE_UP, &dev->intf_state);
	if (xsc_device_registered(dev))
		xsc_detach_device(dev);

	if (xsc_core_is_pf(dev))
		xsc_lag_remove_xdev(dev);

	if (!dev->reg_mr_via_cmdq && (xsc_core_is_pf(dev) || !dev->pdev->physfn))
		xsc_destroy_res(dev);

	xsc_unload(dev);

	if (cleanup)
		xsc_cleanup_once(dev);

out:
	mutex_unlock(&dev->intf_state_mutex);

	return 0;
}

static int xsc_pci_probe(struct pci_dev *pci_dev,
			 const struct pci_device_id *id)
{
	struct xsc_core_device *xdev;
	struct xsc_priv *priv;
	int err;
	struct devlink *devlink;

	devlink = xsc_devlink_alloc(&pci_dev->dev);
	if (!devlink) {
		dev_err(&pci_dev->dev, "devlink alloc failed\n");
		return -ENOMEM;
	}
	xdev = devlink_priv(devlink);

	xsc_product_info(pci_dev);
	xdev->pdev = pci_dev;
	xdev->device = &pci_dev->dev;
	priv = &xdev->priv;
	xdev->coredev_type = (IS_VIRT_FUNCTION(id)) ?
				XSC_COREDEV_VF : XSC_COREDEV_PF;
	xsc_core_info(xdev, "dev_type=%d is_vf=%d\n",
		      xdev->coredev_type, pci_dev->is_virtfn);

#ifdef CONFIG_XSC_SRIOV
	priv->sriov.probe_vf = probe_vf;
	if ((IS_VIRT_FUNCTION(id)) && !probe_vf) {
		xsc_core_err(xdev, "VFs are not binded to xsc driver\n");
		return 0;
	}
#endif

	/* init pcie device */
	pci_set_drvdata(pci_dev, xdev);
	err = xsc_pci_init(xdev, id);
	if (err) {
		xsc_core_err(xdev, "xsc_pci_init failed %d\n", err);
		goto err_pci_init;
	}

	err = xsc_dev_init(xdev);
	if (err) {
		xsc_core_err(xdev, "xsc_dev_init failed %d\n", err);
		goto err_dev_init;
	}

	if (xsc_fpga_not_supported(xdev)) {
		err = -EOPNOTSUPP;
		goto err_version_check;
	}

	err = xsc_load_one(xdev, true);
	if (err) {
		xsc_core_err(xdev, "xsc_load_one failed %d\n", err);
		goto err_load;
	}

	request_module_nowait(ETH_DRIVER_NAME);

	return 0;

err_load:
err_version_check:
	xsc_dev_cleanup(xdev);
err_dev_init:
	xsc_pci_fini(xdev);
err_pci_init:
	pci_set_drvdata(pci_dev, NULL);
	xsc_devlink_free(devlink);
	return err;
}

static void xsc_pci_remove(struct pci_dev *pci_dev)
{
	struct xsc_core_device *xdev = pci_get_drvdata(pci_dev);

	set_bit(XSC_INTERFACE_STATE_TEARDOWN, &xdev->intf_state);
	xsc_unload_one(xdev, true);
	xsc_dev_cleanup(xdev);

	xsc_pci_fini(xdev);
	pci_set_drvdata(pci_dev, NULL);
	xsc_devlink_free(priv_to_devlink(xdev));
}

static struct pci_driver xsc_pci_driver = {
	.name		= "xsc-pci",
	.id_table	= xsc_pci_id_table,
	.probe		= xsc_pci_probe,
	.remove		= xsc_pci_remove,

#ifdef CONFIG_XSC_SRIOV
	.sriov_configure   = xsc_core_sriov_configure,
#endif
};

int xsc_pci_reboot_event_handler(struct notifier_block *nb, unsigned long action, void *data)
{
	pr_info("xsc pci driver recv %lu event\n", action);
	if (xsc_get_exit_flag())
		return NOTIFY_OK;
	xsc_pci_exit();

	return NOTIFY_OK;
}

struct notifier_block xsc_pci_nb = {
	.notifier_call = xsc_pci_reboot_event_handler,
	.next = NULL,
	.priority = 0,
};

void xsc_pci_exit(void)
{
	xsc_stop_delayed_release();
	pci_unregister_driver(&xsc_pci_driver);
	xsc_pci_ctrl_fini();
	xsc_port_ctrl_fini();
	xsc_unregister_debugfs();
	qpts_fini();
	xsc_free_board_info();
}

static int __init xsc_init(void)
{
	int err;

	xsc_register_debugfs();

	qpts_init();

	err = xsc_port_ctrl_init();
	if (err) {
		pr_err("failed to initialize port control\n");
		goto err_port_ctrl;
	}

	err = xsc_pci_ctrl_init();
	if (err) {
		pr_err("failed to initialize dpdk ctrl\n");
		goto err_pci_ctrl;
	}

	xsc_hw_reset = false;
	err = pci_register_driver(&xsc_pci_driver);
	if (err) {
		pr_err("failed to register pci driver\n");
		goto err_register;
	}

	xsc_init_delayed_release();
	register_reboot_notifier(&xsc_pci_nb);

	return 0;

err_register:
	xsc_pci_ctrl_fini();
err_pci_ctrl:
	xsc_port_ctrl_fini();
err_port_ctrl:
	xsc_unregister_debugfs();
	qpts_fini();
	return err;
}

static void __exit xsc_fini(void)
{
	unregister_reboot_notifier(&xsc_pci_nb);
	xsc_pci_exit();
}

module_init(xsc_init);
module_exit(xsc_fini);

MODULE_LICENSE("GPL");

