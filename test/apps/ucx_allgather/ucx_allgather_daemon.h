/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef UCX_ALLGATHER_SERVER_H_
#define UCX_ALLGATHER_SERVER_H_

#include "ucx_allgather_common.h"

int daemon_am_recv_ctrl_callback(struct ucx_am_desc *am_desc);

void daemon_run(void);

void daemon_allgather_complete_client_operation_callback(void *arg, ucs_status_t status);

#endif /** UCX_ALLGATHER_SERVER_H_ */
