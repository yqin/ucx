/*
 *  * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 *   * See file LICENSE for terms.
 *    */

#ifndef UCT_RDMACM_H
#define UCT_RDMACM_H

#include <uct/ib/base/ib_iface.h>
#include <uct/api/uct.h>
#include <uct/api/uct_def.h>
#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <ucs/type/class.h>
#include <ucs/time/time.h>
#include <ucs/async/async.h>
#include <rdma/rdma_cma.h>
#include <sys/poll.h>

#define UCT_RDMACM_TL_NAME              "rdmacm"
#define UCT_RDMACM_TCP_PRIV_DATA_LEN    56    /** See rdma_connect(3) */
#define UCT_RDMACM_UDP_PRIV_DATA_LEN    180   /** See rdma_connect(3) */

typedef struct uct_rdmacm_iface   uct_rdmacm_iface_t;
typedef struct uct_rdmacm_ep      uct_rdmacm_ep_t;

typedef struct uct_rdmacm_priv_data_hdr {
    uint8_t length;     /* length of the private data */
} uct_rdmacm_priv_data_hdr_t;

#endif /* UCT_RDMACM_H */
