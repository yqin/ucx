/**
* Copyright (C) Mellanox Technologies Ltd. 2018.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

/*
 * UCP client - server example utility
 * -----------------------------------------------
 *
 * Server side:
 *
 *    ./ucp_client_server
 *
 * Client side:
 *
 *    ./ucp_client_server -a <server-ip>
 *
 * Notes:
 *
 *    - The server will listen to incoming connection requests on INADDR_ANY.
 *    - The client needs to pass the IP address of the server side to connect to
 *      as an argument to the test.
 *    - Currently, the passed IP needs to be an IPoIB or a RoCE address.
 *    - The port which the server side would listen on can be modified with the
 *      '-p' option and should be used on both sides. The default port to use is
 *      13337.
 */

#include "hello_world_util.h"
#include "ucp_client_server_util.h"

#include <ucp/api/ucp.h>

#include <string.h>    /* memset */
#include <arpa/inet.h> /* inet_addr */
#include <unistd.h>    /* getopt */
#include <stdlib.h>    /* atoi */
#include <assert.h>    /* assert */

#define TAG            0xCAFE
#define PRINT_INTERVAL 2000


static void *prealloc_send_buffer = NULL;
static void *prealloc_recv_buffer = NULL;


struct am_data_desc {
    volatile int completed;
    int          is_rndv;
    void         *desc;
    void         *buf;
    size_t       size;
} am_data_desc = { 0, 0, NULL, NULL, 0 };


typedef struct shared_mem_req {
    uint64_t size;
    uint64_t send_address;
    uint64_t recv_address;
    uint64_t send_shared_mkey_buf_size;
    uint64_t recv_shared_mkey_buf_size;
    /* Shared mkey buffers follow in the order:
     * - send
     * - receive
     */
} shared_mem_req_t;


typedef struct {
    void      *address;
    ucp_mem_h memh;
    void      *shared_mkey_buf;
    size_t    shared_mkey_buf_size;
} shared_mem_t;


typedef struct {
    shared_mem_t     send;
    shared_mem_t     recv;
    shared_mem_req_t *req_buf;
    size_t           req_buf_size;
} shared_mem_info_t;


static int shared_mem_import(ucp_context_h ucp_context, void *address,
                             size_t length, void *shared_mkey_buf,
                             ucp_mem_h *memh_p)
{
    ucp_mem_map_params_t params;
    ucs_status_t status;
    ucp_mem_h memh;

    params.field_mask         = UCP_MEM_MAP_PARAM_FIELD_FLAGS |
                                UCP_MEM_MAP_PARAM_FIELD_SHARED_MKEY_BUFFER |
                                UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                                UCP_MEM_MAP_PARAM_FIELD_LENGTH;
    params.flags              = UCP_MEM_MAP_SHARED;
    params.shared_mkey_buffer = shared_mkey_buf;
    params.address            = address;
    params.length             = length;
    status                    = ucp_mem_map(ucp_context, &params, &memh);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to import memory (%s)\n",
                ucs_status_string(status));
        return -1;
    }

    *memh_p = memh;
    return 0;
}

static void shared_mem_import_release(ucp_context_h ucp_context,
                                      ucp_mem_h memh, int force)
{
    if (force) {
        ucp_mem_unmap_force(ucp_context, memh);
    } else {
        ucp_mem_unmap(ucp_context, memh);
    }
}

static int shared_mem_export(ucp_context_h ucp_context, size_t length,
                             void **address_p, ucp_mem_h *memh_p,
                             void **shared_mkey_buf_p,
                             size_t *shared_mkey_buf_size_p)
{
    ucp_mem_map_params_t mem_map_params;
    ucp_mkey_pack_params_t mkey_pack_params;
    ucs_status_t status;
    ucp_mem_h memh;
    void *shared_mkey_buf;
    size_t shared_mkey_buf_size;
    void *address;

    if (*address_p == NULL) {
        address = malloc(length);
        if (address == NULL) {
            goto err;
        }
    } else {
        address = *address_p;
    }

    mem_map_params.field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                                UCP_MEM_MAP_PARAM_FIELD_LENGTH  |
                                UCP_MEM_MAP_PARAM_FIELD_FLAGS;
    mem_map_params.address    = address;
    mem_map_params.length     = test_string_length;
    mem_map_params.flags      = UCP_MEM_MAP_SHARED;

    status = ucp_mem_map(ucp_context, &mem_map_params, &memh);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to register memory (%s)\n",
                ucs_status_string(status));
        goto err_mem_free;
    }

    mkey_pack_params.field_mask = UCP_MKEY_PACK_PARAM_FIELD_FLAGS;
    mkey_pack_params.flags      = UCP_MKEY_PACK_FLAG_SHARED;
    status                      = ucp_mkey_pack(ucp_context, memh,
                                                &mkey_pack_params,
                                                &shared_mkey_buf,
                                                &shared_mkey_buf_size);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to pack memory handle (%s)\n",
                ucs_status_string(status));
        goto err_mem_unmap;
    }

    *address_p              = address;
    *memh_p                 = memh;
    *shared_mkey_buf_p      = shared_mkey_buf;
    *shared_mkey_buf_size_p = shared_mkey_buf_size;

    return 0;

err_mem_unmap:
    ucp_mem_unmap(ucp_context, memh);
err_mem_free:
    if (*address_p == NULL) {
        free(address);
    }
err:
    return -1;
}

static void shared_mem_export_release(ucp_context_h ucp_context, void *buffer,
                                      ucp_mem_h memh, void *shared_mkey_buf)
{
    ucp_mkey_buffer_release_params_t mkey_release_params;

    mkey_release_params.field_mask = UCP_MKEY_BUFFER_RELEASE_PARAM_FIELD_FLAGS;
    mkey_release_params.flags      = UCP_MKEY_BUFFER_RELEASE_FLAG_SHARED;
    ucp_mkey_buffer_release(&mkey_release_params, shared_mkey_buf);

    ucp_mem_unmap(ucp_context, memh);

    free(buffer);
}

static int client_shared_mem_export(ucp_context_h ucp_context, size_t size,
                                    shared_mem_info_t **info_p)
{
    void *send_address, *recv_address;
    ucp_mem_h send_memh, recv_memh;
    void *send_shared_mkey_buf, *recv_shared_mkey_buf;
    size_t send_shared_mkey_buf_size, recv_shared_mkey_buf_size;
    shared_mem_req_t *shared_mem_req_buf;
    shared_mem_info_t *info;
    size_t shared_mem_req_buf_size;
    int ret;

    info = malloc(sizeof(*info));
    if (info == NULL) {
        fprintf(stderr, "failed to allocate memory to hold info\n");
        goto out;
    }

    if (use_prealloc_buffer) {
        send_address = prealloc_send_buffer;
        recv_address = prealloc_recv_buffer;
    } else {
        send_address = NULL;
        recv_address = NULL;
    }

    ret = shared_mem_export(ucp_context, size, &send_address,
                            &send_memh, &send_shared_mkey_buf,
                            &send_shared_mkey_buf_size);
    if (ret != 0) {
        goto out_shared_mem_info_free;
    }

    generate_test_string(send_address, size);

    ret = shared_mem_export(ucp_context, size, &recv_address,
                            &recv_memh, &recv_shared_mkey_buf,
                            &recv_shared_mkey_buf_size);
    if (ret != 0) {
        goto out_send_shared_mem_export_release;
    }

    memset(recv_address, 0, test_string_length);

    shared_mem_req_buf_size = sizeof(*shared_mem_req_buf) +
                              send_shared_mkey_buf_size +
                              recv_shared_mkey_buf_size;
    shared_mem_req_buf      = malloc(shared_mem_req_buf_size);
    if (shared_mem_req_buf == NULL) {
        fprintf(stderr, "failed to allocate memory to hold AM request\n");
        goto out_recv_shared_mem_export_release;
    }

    shared_mem_req_buf->size                      = test_string_length;
    shared_mem_req_buf->send_address              = (uintptr_t)send_address;
    shared_mem_req_buf->recv_address              = (uintptr_t)recv_address;
    shared_mem_req_buf->send_shared_mkey_buf_size = send_shared_mkey_buf_size;
    shared_mem_req_buf->recv_shared_mkey_buf_size = recv_shared_mkey_buf_size;

    memcpy(shared_mem_req_buf + 1, send_shared_mkey_buf,
           send_shared_mkey_buf_size);
    memcpy((char*)(shared_mem_req_buf + 1) + send_shared_mkey_buf_size,
           recv_shared_mkey_buf, recv_shared_mkey_buf_size);

    info->send.address              = send_address;
    info->send.memh                 = send_memh;
    info->send.shared_mkey_buf      = send_shared_mkey_buf;
    info->send.shared_mkey_buf_size = send_shared_mkey_buf_size;

    info->recv.address              = recv_address;
    info->recv.memh                 = recv_memh;
    info->recv.shared_mkey_buf      = recv_shared_mkey_buf;
    info->recv.shared_mkey_buf_size = recv_shared_mkey_buf_size;

    info->req_buf                   = shared_mem_req_buf;
    info->req_buf_size              = shared_mem_req_buf_size;

    *info_p                         = info;

    return 0;

out_recv_shared_mem_export_release:
    shared_mem_export_release(ucp_context, recv_address, recv_memh,
                              recv_shared_mkey_buf);
out_send_shared_mem_export_release:
    shared_mem_export_release(ucp_context, send_address, send_memh,
                              send_shared_mkey_buf);
out_shared_mem_info_free:
    free(info);
out:
    return ret;
}

static void client_shared_mem_export_release(ucp_context_h ucp_context,
                                             shared_mem_info_t *info)
{
    void *send_buffer, *recv_buffer;

    if (info != NULL) {
        send_buffer = use_prealloc_buffer ? NULL : info->send.address;
        recv_buffer = use_prealloc_buffer ? NULL : info->recv.address;

        free(info->req_buf);
        shared_mem_export_release(ucp_context, recv_buffer, info->recv.memh,
                                  info->recv.shared_mkey_buf);
        shared_mem_export_release(ucp_context, send_buffer, info->send.memh,
                                  info->send.shared_mkey_buf);
        free(info);
    }
}

static void am_request_param_common_init(ucp_request_param_t *params,
                                         ucx_context_t *ctx)
{
    request_init(ctx);

    params->op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                           UCP_OP_ATTR_FIELD_DATATYPE |
                           UCP_OP_ATTR_FIELD_USER_DATA;
    params->datatype     = ucp_dt_make_contig(1);
    params->user_data    = ctx;
}

static int am_send(ucp_ep_h ep, ucp_worker_h ucp_worker, void *buf,
                   size_t buf_size)
{
    ucp_request_param_t params;
    ucx_context_t ctx;
    void *request;
    ucs_status_t status;

    am_request_param_common_init(&params, &ctx);

    params.cb.send = send_cb;
    request        = ucp_am_send_nbx(ep, TEST_AM_ID, NULL, 0ul, buf, buf_size,
                                     &params);

    status = request_wait(ucp_worker, request, &ctx);
    if (status != UCS_OK) {
        fprintf(stderr, "AM send request failed (%s)\n",
                ucs_status_string(status));
        return -1;
    }

    return 0;
}

static int am_recv(ucp_worker_h ucp_worker, ucp_mem_h memh,
                   void **buf_p, size_t *buf_size_p)
{
    ucp_request_param_t params;
    ucx_context_t ctx;
    void *request;
    ucs_status_t status;

    am_request_param_common_init(&params, &ctx);

    /* Waiting for AM callback with  has been called */
    while (!am_data_desc.completed) {
        ucp_worker_progress(ucp_worker);
    }

    am_data_desc.completed = 0;

    if (am_data_desc.is_rndv) {
        /* Rendezvous request has arrived, need to invoke receive operation
         * to confirm data transfer from the sender to the "recv_message"
         * buffer. */
        params.op_attr_mask |= UCP_OP_ATTR_FLAG_NO_IMM_CMPL;
        params.cb.recv_am    = am_recv_cb;

        if (memh != NULL) {
            params.op_attr_mask |= UCP_OP_ATTR_FIELD_MEMH;
            params.memh          = memh;
        }

        request = ucp_am_recv_data_nbx(ucp_worker, am_data_desc.desc,
                                       am_data_desc.buf, am_data_desc.size,
                                       &params);
    } else {
        /* Data has arrived eagerly and is ready for use, no need to
         * initiate receive operation. */
        request = NULL;
    }

    status = request_wait(ucp_worker, request, &ctx);
    if (status != UCS_OK) {
        fprintf(stderr, "AM receive request failed (%s)\n",
                ucs_status_string(status));
        if (memh == NULL) {
            free(am_data_desc.buf);
        }
        return -1;
    }

    *buf_p           = am_data_desc.buf;
    *buf_size_p      = am_data_desc.size;
    am_data_desc.buf = NULL;

    return 0;
}

static int send_recv_am(ucp_worker_h ucp_worker, ucp_ep_h self_ep,
                        shared_mem_req_t *shared_mem_req_buf,
                        ucp_mem_h send_memh, ucp_mem_h recv_memh)
{
    ucp_request_param_t params;
    ucx_context_t send_ctx;
    void *send_request;
    ucs_status_t status;
    void *buf;
    size_t size;
    int ret;

    am_data_desc.completed = 0;
    am_data_desc.buf       = (void*)shared_mem_req_buf->recv_address;

    /* Send */
    am_request_param_common_init(&params, &send_ctx);
    params.op_attr_mask |= UCP_OP_ATTR_FIELD_MEMH;
    params.cb.send       = send_cb;
    params.memh          = send_memh;
    send_request         =
            ucp_am_send_nbx(self_ep, TEST_AM_ID, NULL, 0ul,
                            (void*)shared_mem_req_buf->send_address,
                            shared_mem_req_buf->size, &params);

    /* Receive */
    ret = am_recv(ucp_worker, recv_memh, &buf, &size);

    status = request_wait(ucp_worker, send_request, &send_ctx);
    if (status != UCS_OK) {
        fprintf(stderr, "AM send request failed (%s)\n",
                ucs_status_string(status));
        return -1;
    }

    return ret;
}

static int send_recv_rma(ucp_context_h ucp_context, ucp_worker_h ucp_worker,
                         ucp_ep_h self_ep,
                         shared_mem_req_t *shared_mem_req_buf,
                         ucp_mem_h send_memh, ucp_mem_h recv_memh)
{
    int ret = 0;
    ucp_request_param_t params;
    ucx_context_t ctx;
    void *request;
    void *rkey_buffer;
    size_t rkey_buffer_length;
    ucp_rkey_h rkey;
    ucs_status_t status;

    /* Get RKEY for send buffer */
    status = ucp_rkey_pack(ucp_context, send_memh, &rkey_buffer,
                           &rkey_buffer_length);
    if (status != UCS_OK) {
        fprintf(stderr, "packing rkey of send memory handle failed: %s",
                ucs_status_string(status));
        ret = -1;
        goto out;
    }

    status = ucp_ep_rkey_unpack(self_ep, rkey_buffer, &rkey);
    if (status != UCS_OK) {
        fprintf(stderr, "unpacking rkey of send memory handle failed: %s",
                ucs_status_string(status));
        ret = -1;
        goto out_rkey_buffer_release;
    }

    am_request_param_common_init(&params, &ctx);
    params.op_attr_mask |= UCP_OP_ATTR_FIELD_MEMH |
                           UCP_OP_ATTR_FLAG_NO_IMM_CMPL;
    params.cb.send       = send_cb;
    params.memh          = recv_memh;

    request = ucp_get_nbx(self_ep, (void*)shared_mem_req_buf->recv_address,
                          shared_mem_req_buf->size,
                          shared_mem_req_buf->send_address, rkey, &params);
    status = request_wait(ucp_worker, request, &ctx);
    if (status != UCS_OK) {
        fprintf(stderr, "GET request failed (%s)\n",
                ucs_status_string(status));
        ret = -1;
        goto out_rkey_destroy;
    }

out_rkey_destroy:
    ucp_rkey_destroy(rkey);
out_rkey_buffer_release:
    ucp_rkey_buffer_release(rkey_buffer);
out:
    return ret;
}

static int shared_mem_do_operation(ucp_context_h ucp_context,
                                   ucp_worker_h ucp_worker, ucp_ep_h self_ep,
                                   send_recv_type_t send_recv_type,
                                   shared_mem_req_t *shared_mem_req_buf,
                                   int current_iter)
{
    int force                 = !use_prealloc_buffer ||
                                (current_iter == num_iterations);
    void *send_shared_mem_buf = (void*)(shared_mem_req_buf + 1);
    void *recv_shared_mem_buf =
            (void*)((char*)(shared_mem_req_buf + 1) +
                    shared_mem_req_buf->send_shared_mkey_buf_size);
    ucp_mem_h send_memh, recv_memh;
    int ret;
    
    ret = shared_mem_import(ucp_context,
                            (void*)shared_mem_req_buf->send_address,
                            shared_mem_req_buf->size, send_shared_mem_buf,
                            &send_memh);
    if (ret != 0) {
        goto out;
    }

    ret = shared_mem_import(ucp_context,
                            (void*)shared_mem_req_buf->recv_address,
                            shared_mem_req_buf->size, recv_shared_mem_buf,
                            &recv_memh);
    if (ret != 0) {
        goto out_send_shared_mem_import_release;
    }

    switch (send_recv_type) {
    case CLIENT_SERVER_SEND_RECV_AM:
        ret = send_recv_am(ucp_worker, self_ep, shared_mem_req_buf, send_memh,
                           recv_memh);
        break;
    case CLIENT_SERVER_SEND_RECV_RMA:
        ret = send_recv_rma(ucp_context, ucp_worker, self_ep,
                            shared_mem_req_buf, send_memh, recv_memh);
        break;
    default:
        fprintf(stderr, "send-recv type %d isn't supported\n", send_recv_type);
        break;
    }

    shared_mem_import_release(ucp_context, recv_memh, force);
out_send_shared_mem_import_release:
    shared_mem_import_release(ucp_context, send_memh, force);
out:
    return ret;
}

ucs_status_t ucp_am_data_cb(void *arg, const void *header, size_t header_length,
                            void *data, size_t length,
                            const ucp_am_recv_param_t *param)
{
    ucs_status_t status;

    if (header_length != 0) {
        fprintf(stderr, "received unexpected header, length %ld", header_length);
    }

    assert(am_data_desc.completed == 0);

    am_data_desc.size = length;

    if (am_data_desc.buf == NULL) {
        am_data_desc.buf       = malloc(length);
        if (am_data_desc.buf == NULL) {
            fprintf(stderr, "failed to allocate memory to hold buffer");
            status = UCS_ERR_NO_MEMORY;
            goto out;
        }
    }

    if (param->recv_attr & UCP_AM_RECV_ATTR_FLAG_RNDV) {
        /* Rendezvous request arrived, data contains an internal UCX descriptor,
         * which has to be passed to ucp_am_recv_data_nbx function to confirm
         * data transfer.
         */
        am_data_desc.is_rndv = 1;
        am_data_desc.desc    = data;
        status = UCS_INPROGRESS;
        goto out;
    }

    /* Message delivered with eager protocol, data should be available
     * immediately
     */
    status               = UCS_OK;
    am_data_desc.is_rndv = 0;
    memcpy(am_data_desc.buf, data, length);

out:
    am_data_desc.completed = 1;
    return status;
}

static int
client_server_communication(ucp_context_h ucp_context, ucp_worker_h ucp_worker,
                            ucp_ep_h ep, ucp_ep_h self_ep,
                            send_recv_type_t send_recv_type,
                            shared_mem_info_t *client_shared_mem_info,
                            int current_iter)
{
    int ret                = 0;
    int is_client          = (client_shared_mem_info != NULL);
    void *am_ack_buf       = NULL;
    size_t am_ack_buf_size = 0;
    size_t shared_mem_req_buf_size;
    shared_mem_req_t *shared_mem_req_buf;
    void *send_address, *recv_address;

    if (is_client) {
        shared_mem_req_buf_size = client_shared_mem_info->req_buf_size;
        shared_mem_req_buf      = client_shared_mem_info->req_buf;
        send_address            = client_shared_mem_info->send.address;
        recv_address            = client_shared_mem_info->recv.address;

        ret = am_send(ep, ucp_worker, (void*)shared_mem_req_buf,
                      shared_mem_req_buf_size);
        if (ret != 0) {
            return ret;
        }

        ret = am_recv(ucp_worker, NULL, &am_ack_buf, &am_ack_buf_size);
        if (ret != 0) {
            return ret;
        }

        if (memcmp(send_address, recv_address, test_string_length) != 0) {
            fprintf(stderr, "send and receive buffer are not equal\n");
            fprintf(stderr, "send buffer:\n%s\n", (char*)send_address);
            fprintf(stderr, "receive buffer:\n%s\n", (char*)recv_address);
        }

        assert(am_ack_buf_size == 0);
    } else {
        ret = am_recv(ucp_worker, NULL, (void**)&shared_mem_req_buf,
                      &shared_mem_req_buf_size);
        if (ret != 0) {
            free(shared_mem_req_buf);
            return ret;
        }

        ret = shared_mem_do_operation(ucp_context, ucp_worker, self_ep,
                                      send_recv_type, shared_mem_req_buf,
                                      current_iter);
        if (ret != 0) {
            free(shared_mem_req_buf);
            return ret;
        }

        ret = am_send(ep, ucp_worker, am_ack_buf, am_ack_buf_size);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

static int client_server_do_work(ucp_context_h ucp_context,
                                 ucp_worker_h ucp_worker, ucp_ep_h ep,
                                 ucp_ep_h self_ep,
                                 send_recv_type_t send_recv_type)
{
    int is_client                             = (self_ep == NULL);
    int ret                                   = 0;
    shared_mem_info_t *client_shared_mem_info = NULL;
    int i;

    for (i = 0; i < num_iterations; i++) {
        if (is_client) {
            ret = client_shared_mem_export(ucp_context, test_string_length,
                                           &client_shared_mem_info);
            if (ret != 0) {
                fprintf(stderr, "client failed to export memory on iteration"
                        " #%d\n", i + 1);
                goto out;
            }
        }

        ret = client_server_communication(ucp_context, ucp_worker, ep, self_ep,
                                          send_recv_type,
                                          client_shared_mem_info, i);
        if (ret != 0) {
            client_shared_mem_export_release(ucp_context,
                                             client_shared_mem_info);
            fprintf(stderr, "%s failed on iteration #%d\n",
                    (is_client ? "client": "server"), i + 1);
            goto out;
        }

        client_shared_mem_export_release(ucp_context, client_shared_mem_info);
    }

out:
    return ret;
}

static int create_self_ep(ucp_worker_h ucp_data_worker, ucp_ep_h *self_ep_p)
{
    ucp_ep_params_t ep_params;
    ucs_status_t status;
    ucp_address_t *local_addr;
    size_t local_addr_len;

    status = ucp_worker_get_address(ucp_data_worker, &local_addr, &local_addr_len);
    if (status != UCS_OK) {
        return -1;
    }

    ep_params.field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS |
                           UCP_EP_PARAM_FIELD_FLAGS;
    ep_params.flags      = UCP_EP_PARAMS_FLAGS_SHARED_MKEY;
    ep_params.address    = local_addr;

    status = ucp_ep_create(ucp_data_worker, &ep_params, self_ep_p);
    ucp_worker_release_address(ucp_data_worker, local_addr);

    return (status == UCS_OK) ? 0 : -1;
}

static int run_server(ucp_context_h ucp_context, ucp_worker_h ucp_worker,
                      char *listen_addr, send_recv_type_t send_recv_type)
{
    ucx_server_ctx_t context;
    ucp_worker_h ucp_data_worker;
    ucp_ep_h server_ep, self_ep;
    ucs_status_t status;
    int ret;

    /* Create a data worker (to be used for data exchange between the server
     * and the client after the connection between them was established) */
    ret = init_worker(ucp_context, &ucp_data_worker);
    if (ret != 0) {
        goto err;
    }

    ret = create_self_ep(ucp_data_worker, &self_ep);
    if (ret != 0) {
        goto err_worker;
    }

    ret = set_am_recv_handler(ucp_data_worker, TEST_AM_ID, ucp_am_data_cb);
    if (ret != 0) {
        goto err_self_ep;
    }

    /* Initialize the server's context. */
    context.conn_request = NULL;

    /* Create a listener on the worker created at first. The 'connection
     * worker' - used for connection establishment between client and server.
     * This listener will stay open for listening to incoming connection
     * requests from the client */
    status = start_server(ucp_worker, &context, &context.listener, listen_addr);
    if (status != UCS_OK) {
        ret = -1;
        goto err_self_ep;
    }

    /* Server is always up listening */
    while (1) {
        /* Wait for the server to receive a connection request from the client.
         * If there are multiple clients for which the server's connection request
         * callback is invoked, i.e. several clients are trying to connect in
         * parallel, the server will handle only the first one and reject the rest */
        while (context.conn_request == NULL) {
            ucp_worker_progress(ucp_worker);
        }

        /* Server creates an ep to the client on the data worker.
         * This is not the worker the listener was created on.
         * The client side should have initiated the connection, leading
         * to this ep's creation */
        status = server_create_ep(ucp_data_worker, context.conn_request,
                                  UCP_EP_PARAMS_FLAGS_SHARED_MKEY, &server_ep);
        if (status != UCS_OK) {
            ret = -1;
            goto err_listener;
        }

        /* The server waits for all the iterations to complete before moving on
         * to the next client */
        ret = client_server_do_work(ucp_context, ucp_data_worker, server_ep,
                                    self_ep, send_recv_type);
        if (ret != 0) {
            goto err_ep;
        }

        /* Close the endpoint to the client */
        ep_close(ucp_data_worker, server_ep, UCP_EP_CLOSE_MODE_FORCE);

        /* Reinitialize the server's context to be used for the next client */
        context.conn_request = NULL;

        printf("Waiting for connection...\n");
    }

err_ep:
    ep_close(ucp_data_worker, server_ep, UCP_EP_CLOSE_MODE_FORCE);
err_listener:
    ucp_listener_destroy(context.listener);
err_self_ep:
    ep_close(ucp_data_worker, self_ep, UCP_EP_CLOSE_MODE_FORCE);
err_worker:
    ucp_worker_destroy(ucp_data_worker);
err:
    return ret;
}

static int client_prealloc_buffers(size_t size)
{
    if (!use_prealloc_buffer) {
        return 0;
    }

    prealloc_send_buffer = malloc(size);
    if (prealloc_send_buffer == NULL) {
        fprintf(stderr, "failed to allocate memory for send buffer\n");
        goto out;
    }

    prealloc_recv_buffer = malloc(size);
    if (prealloc_recv_buffer == NULL) {
        fprintf(stderr, "failed to allocate memory for receive buffer\n");
        goto out;
    }

    return 0;

out_prealloc_send_buffer_free:
    free(prealloc_send_buffer);
out:
    return -1;
}

static void client_prealloc_buffers_release()
{
    if (!use_prealloc_buffer) {
        assert(prealloc_send_buffer == NULL);
        assert(prealloc_recv_buffer == NULL);
        return;
    }

    free(prealloc_send_buffer);
    free(prealloc_recv_buffer);
}

static int run_client(ucp_context_h ucp_context, ucp_worker_h ucp_worker,
                      char *server_addr, send_recv_type_t send_recv_type)
{
    ucp_ep_h client_ep;
    ucs_status_t status;
    int ret;

    ret = set_am_recv_handler(ucp_worker, TEST_AM_ID, ucp_am_data_cb);
    if (ret != 0) {
        goto out;
    }

    ret = client_prealloc_buffers(test_string_length);
    if (ret != 0) {
        goto out;
    }

    status = start_client(ucp_worker, server_addr,
                          UCP_EP_PARAMS_FLAGS_SHARED_MKEY, &client_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to start client (%s)\n", ucs_status_string(status));
        ret = -1;
        goto out_client_prealloc_buffers_release;
    }

    ret = client_server_do_work(ucp_context, ucp_worker, client_ep, NULL,
                                send_recv_type);

    /* Close the endpoint to the server */
    ep_close(ucp_worker, client_ep, UCP_EP_CLOSE_MODE_FORCE);

out_client_prealloc_buffers_release:
    client_prealloc_buffers_release();
out:
    return ret;
}

int main(int argc, char **argv)
{
    send_recv_type_t send_recv_type = CLIENT_SERVER_SEND_RECV_DEFAULT;
    char *server_addr = NULL;
    char *listen_addr = NULL;
    int ret;

    /* UCP objects */
    ucp_context_h ucp_context;
    ucp_worker_h  ucp_worker;

    ret = parse_cmd(argc, argv, &server_addr, &listen_addr, &send_recv_type);
    if (ret != 0) {
        goto err;
    }

    /* Initialize the UCX required objects */
    ret = init_context(&ucp_context, &ucp_worker, send_recv_type);
    if (ret != 0) {
        goto err;
    }

    /* Client-Server initialization */
    if (server_addr == NULL) {
        /* Server side */
        ret = run_server(ucp_context, ucp_worker, listen_addr, send_recv_type);
    } else {
        /* Client side */
        ret = run_client(ucp_context, ucp_worker, server_addr, send_recv_type);
    }

    ucp_worker_destroy(ucp_worker);
    ucp_cleanup(ucp_context);
err:
    return ret;
}
