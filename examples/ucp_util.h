/**
 * Copyright (C) 2021 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_UTIL_H_
#define UCP_UTIL_H_

#include <ucp/api/ucp.h>


#define DEFAULT_PORT           13337
#define IP_STRING_LEN          50
#define PORT_STRING_LEN        8


extern sa_family_t ai_family;
extern uint16_t server_port;
extern long test_string_length;


/**
 * Close UCP endpoint.
 *
 * @param [in]  worker  Handle to the worker that the endpoint is associated
 *                      with.
 * @param [in]  ep      Handle to the endpoint to close.
 * @param [in]  flags   Close UCP endpoint mode. Please see
 *                      @a ucp_ep_close_flags_t for details.
 */
void ep_close(ucp_worker_h ucp_worker, ucp_ep_h ep, uint64_t flags);


#endif
