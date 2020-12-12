/**
* Copyright (C) Mellanox Technologies Ltd. 2019.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include <uct/ib/base/ib_iface.h>

void uct_ib_exp_qp_fill_attr(uct_ib_iface_t *iface, uct_ib_qp_attr_t *attr)
{
    /* YQ: need to check this function for RDMA-Core */
    code_path();

#if HAVE_DECL_IBV_EXP_CREATE_QP
    if (!(attr->ibv.comp_mask & IBV_EXP_QP_INIT_ATTR_PD)) {
        attr->ibv.comp_mask       = IBV_EXP_QP_INIT_ATTR_PD;
        attr->ibv.pd              = uct_ib_iface_md(iface)->pd;
    }
#endif

    if (attr->qp_type == IBV_QPT_UD) {
        return;
    }

#if HAVE_IB_EXT_ATOMICS
    attr->ibv.comp_mask          |= IBV_EXP_QP_INIT_ATTR_ATOMICS_ARG;
    attr->ibv.max_atomic_arg      = UCT_IB_MAX_ATOMIC_SIZE;
#endif

#if HAVE_DECL_IBV_EXP_ATOMIC_HCA_REPLY_BE
    if (uct_ib_iface_device(iface)->dev_attr.exp_atomic_cap ==
                                     IBV_EXP_ATOMIC_HCA_REPLY_BE) {
        attr->ibv.comp_mask       |= IBV_EXP_QP_INIT_ATTR_CREATE_FLAGS;
        attr->ibv.exp_create_flags = IBV_EXP_QP_CREATE_ATOMIC_BE_REPLY;
    }
#endif

#if HAVE_STRUCT_IBV_EXP_QP_INIT_ATTR_MAX_INL_RECV
    attr->ibv.comp_mask           |= IBV_EXP_QP_INIT_ATTR_INL_RECV;
    attr->ibv.max_inl_recv         = attr->max_inl_recv;
#endif

#if HAVE_IBV_EXP_QP_CREATE_UMR
    attr->ibv.comp_mask           |= IBV_EXP_QP_INIT_ATTR_CREATE_FLAGS | IBV_EXP_QP_INIT_ATTR_MAX_INL_KLMS;
    attr->ibv.exp_create_flags     = IBV_EXP_QP_CREATE_UMR;
    /* YQ: hardcode this number for now since we seem to be hitting hardware limit */
    //attr->ibv.max_inl_send_klms    = uct_ib_iface_md(iface)->config.max_inline_klm_list;
    attr->ibv.max_inl_send_klms    = 7;
#endif
}

