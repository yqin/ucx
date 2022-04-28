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

#define TAG                    0xCAFE
#define COMM_TYPE_DEFAULT      "STREAM"
#define PRINT_INTERVAL         2000


/**
 * Descriptor of the data received with AM API.
 */
static struct {
    volatile int complete;
    int          is_rndv;
    void         *desc;
    void         *recv_buf;
} am_data_desc = {0, 0, NULL, NULL};


void buffer_free(ucp_dt_iov_t *iov)
{
    size_t idx;

    for (idx = 0; idx < iov_cnt; idx++) {
        mem_type_free(iov[idx].buffer);
    }
}

int buffer_malloc(ucp_dt_iov_t *iov)
{
    size_t idx;

    for (idx = 0; idx < iov_cnt; idx++) {
        iov[idx].length = test_string_length;
        iov[idx].buffer = mem_type_malloc(iov[idx].length);
        if (iov[idx].buffer == NULL) {
            buffer_free(iov);
            return -1;
        }
    }

    return 0;
}

int fill_buffer(ucp_dt_iov_t *iov)
{
    int ret = 0;
    size_t idx;

    for (idx = 0; idx < iov_cnt; idx++) {
        ret = generate_test_string(iov[idx].buffer, iov[idx].length);
        if (ret != 0) {
            break;
        }
    }
    CHKERR_ACTION(ret != 0, "generate test string", return -1;);
    return 0;
}

static void tag_recv_cb(void *request, ucs_status_t status,
                        const ucp_tag_recv_info_t *info, void *user_data)
{
    common_cb(user_data, "tag_recv_cb");
}

/**
 * The callback on the receiving side, which is invoked upon receiving the
 * stream message.
 */
static void stream_recv_cb(void *request, ucs_status_t status, size_t length,
                           void *user_data)
{
    common_cb(user_data, "stream_recv_cb");
}

static void print_iov(const ucp_dt_iov_t *iov)
{
    char *msg = alloca(test_string_length);
    size_t idx;

    for (idx = 0; idx < iov_cnt; idx++) {
        /* In case of Non-System memory */
        mem_type_memcpy(msg, iov[idx].buffer, test_string_length);
        printf("%s.\n", msg);
    }
}

/**
 * Print the received message on the server side or the sent data on the client
 * side.
 */
static
void print_result(int is_server, const ucp_dt_iov_t *iov, int current_iter)
{
    if (is_server) {
        printf("Server: iteration #%d\n", (current_iter + 1));
        printf("UCX data message was received\n");
        printf("\n\n----- UCP TEST SUCCESS -------\n\n");
    } else {
        printf("Client: iteration #%d\n", (current_iter + 1));
        printf("\n\n------------------------------\n\n");
    }

    print_iov(iov);

    printf("\n\n------------------------------\n\n");
}

static int request_finalize(ucp_worker_h ucp_worker, ucx_context_t *request,
                            ucx_context_t *ctx, int is_server,
                            ucp_dt_iov_t *iov, int current_iter)
{
    int ret = 0;
    ucs_status_t status;

    status = request_wait(ucp_worker, request, ctx);
    if (status != UCS_OK) {
        fprintf(stderr, "unable to %s UCX message (%s)\n",
                is_server ? "receive": "send", ucs_status_string(status));
        ret = -1;
        goto release_iov;
    }

    /* Print the output of the first, last and every PRINT_INTERVAL iteration */
    if ((current_iter == 0) || (current_iter == (num_iterations - 1)) ||
        !((current_iter + 1) % (PRINT_INTERVAL))) {
        print_result(is_server, iov, current_iter);
    }

release_iov:
    buffer_free(iov);
    return ret;
}

static int
fill_request_param(ucp_dt_iov_t *iov, int is_client,
                   void **msg, size_t *msg_length,
                   ucx_context_t *ctx, ucp_request_param_t *param)
{
    CHKERR_ACTION(buffer_malloc(iov) != 0, "allocate memory", return -1;);

    if (is_client && (fill_buffer(iov) != 0)) {
        buffer_free(iov);
        return -1;
    }

    *msg        = (iov_cnt == 1) ? iov[0].buffer : iov;
    *msg_length = (iov_cnt == 1) ? iov[0].length : iov_cnt;

    ctx->completed      = 0;
    param->op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                          UCP_OP_ATTR_FIELD_DATATYPE |
                          UCP_OP_ATTR_FIELD_USER_DATA;
    param->datatype     = (iov_cnt == 1) ? ucp_dt_make_contig(1) :
                          UCP_DATATYPE_IOV;
    param->user_data    = ctx;

    return 0;
}

/**
 * Send and receive a message using the Stream API.
 * The client sends a message to the server and waits until the send it completed.
 * The server receives a message from the client and waits for its completion.
 */
static int send_recv_stream(ucp_worker_h ucp_worker, ucp_ep_h ep, int is_server,
                            int current_iter)
{
    ucp_dt_iov_t *iov = alloca(iov_cnt * sizeof(ucp_dt_iov_t));
    ucp_request_param_t param;
    ucx_context_t *request, ctx;
    size_t msg_length;
    void *msg;

    memset(iov, 0, iov_cnt * sizeof(*iov));

    if (fill_request_param(iov, !is_server, &msg, &msg_length,
                           &ctx, &param) != 0) {
        return -1;
    }

    if (!is_server) {
        /* Client sends a message to the server using the stream API */
        param.cb.send = send_cb;
        request       = ucp_stream_send_nbx(ep, msg, msg_length, &param);
    } else {
        /* Server receives a message from the client using the stream API */
        param.op_attr_mask  |= UCP_OP_ATTR_FIELD_FLAGS;
        param.flags          = UCP_STREAM_RECV_FLAG_WAITALL;
        param.cb.recv_stream = stream_recv_cb;
        request              = ucp_stream_recv_nbx(ep, msg, msg_length,
                                                   &msg_length, &param);
    }

    return request_finalize(ucp_worker, request, &ctx, is_server, iov,
                            current_iter);
}

/**
 * Send and receive a message using the Tag-Matching API.
 * The client sends a message to the server and waits until the send it completed.
 * The server receives a message from the client and waits for its completion.
 */
static int send_recv_tag(ucp_worker_h ucp_worker, ucp_ep_h ep, int is_server,
                         int current_iter)
{
    ucp_dt_iov_t *iov = alloca(iov_cnt * sizeof(ucp_dt_iov_t));
    ucp_request_param_t param;
    void *request;
    size_t msg_length;
    void *msg;
    ucx_context_t ctx;

    memset(iov, 0, iov_cnt * sizeof(*iov));

    if (fill_request_param(iov, !is_server, &msg, &msg_length,
                           &ctx, &param) != 0) {
        return -1;
    }

    if (!is_server) {
        /* Client sends a message to the server using the Tag-Matching API */
        param.cb.send = send_cb;
        request       = ucp_tag_send_nbx(ep, msg, msg_length, TAG, &param);
    } else {
        /* Server receives a message from the client using the Tag-Matching API */
        param.cb.recv = tag_recv_cb;
        request       = ucp_tag_recv_nbx(ucp_worker, msg, msg_length, TAG, 0,
                                         &param);
    }

    return request_finalize(ucp_worker, request, &ctx, is_server, iov,
                            current_iter);
}

ucs_status_t ucp_am_data_cb(void *arg, const void *header, size_t header_length,
                            void *data, size_t length,
                            const ucp_am_recv_param_t *param)
{
    ucp_dt_iov_t *iov;
    size_t idx;
    size_t offset;

    if (length != iov_cnt * test_string_length) {
        fprintf(stderr, "received wrong data length %ld (expected %ld)",
                length, iov_cnt * test_string_length);
        return UCS_OK;
    }

    if (header_length != 0) {
        fprintf(stderr, "received unexpected header, length %ld", header_length);
    }

    am_data_desc.complete = 1;

    if (param->recv_attr & UCP_AM_RECV_ATTR_FLAG_RNDV) {
        /* Rendezvous request arrived, data contains an internal UCX descriptor,
         * which has to be passed to ucp_am_recv_data_nbx function to confirm
         * data transfer.
         */
        am_data_desc.is_rndv = 1;
        am_data_desc.desc    = data;
        return UCS_INPROGRESS;
    }

    /* Message delivered with eager protocol, data should be available
     * immediately
     */
    am_data_desc.is_rndv = 0;

    iov = am_data_desc.recv_buf;
    offset = 0;
    for (idx = 0; idx < iov_cnt; idx++) {
        mem_type_memcpy(iov[idx].buffer, UCS_PTR_BYTE_OFFSET(data, offset),
                        iov[idx].length);
        offset += iov[idx].length;
    }

    return UCS_OK;
}

/**
 * Send and receive a message using Active Message API.
 * The client sends a message to the server and waits until the send is completed.
 * The server gets a message from the client and if it is rendezvous request,
 * initiates receive operation.
 */
static int send_recv_am(ucp_worker_h ucp_worker, ucp_ep_h ep, int is_server,
                        int current_iter)
{
    ucp_dt_iov_t *iov = alloca(iov_cnt * sizeof(ucp_dt_iov_t));
    ucx_context_t *request, ctx;
    ucp_request_param_t params;
    size_t msg_length;
    void *msg;

    memset(iov, 0, iov_cnt * sizeof(*iov));

    if (fill_request_param(iov, !is_server, &msg, &msg_length,
                           &ctx, &params) != 0) {
        return -1;
    }

    if (is_server) {
        am_data_desc.recv_buf = iov;

        /* waiting for AM callback has called */
        while (!am_data_desc.complete) {
            ucp_worker_progress(ucp_worker);
        }

        am_data_desc.complete = 0;

        if (am_data_desc.is_rndv) {
            /* Rendezvous request has arrived, need to invoke receive operation
             * to confirm data transfer from the sender to the "recv_message"
             * buffer. */
            params.op_attr_mask |= UCP_OP_ATTR_FLAG_NO_IMM_CMPL;
            params.cb.recv_am    = am_recv_cb,
            request              = ucp_am_recv_data_nbx(ucp_worker,
                                                        am_data_desc.desc,
                                                        msg, msg_length,
                                                        &params);
        } else {
            /* Data has arrived eagerly and is ready for use, no need to
             * initiate receive operation. */
            request = NULL;
        }
    } else {
        /* Client sends a message to the server using the AM API */
        params.cb.send = send_cb,
        request        = ucp_am_send_nbx(ep, TEST_AM_ID, NULL, 0ul, msg,
                                         msg_length, &params);
    }

    return request_finalize(ucp_worker, request, &ctx, is_server, iov,
                            current_iter);
}

static int client_server_communication(ucp_worker_h worker, ucp_ep_h ep,
                                       send_recv_type_t send_recv_type,
                                       int is_server, int current_iter)
{
    int ret;

    switch (send_recv_type) {
    case CLIENT_SERVER_SEND_RECV_STREAM:
        /* Client-Server communication via Stream API */
        ret = send_recv_stream(worker, ep, is_server, current_iter);
        break;
    case CLIENT_SERVER_SEND_RECV_TAG:
        /* Client-Server communication via Tag-Matching API */
        ret = send_recv_tag(worker, ep, is_server, current_iter);
        break;
    case CLIENT_SERVER_SEND_RECV_AM:
        /* Client-Server communication via AM API. */
        ret = send_recv_am(worker, ep, is_server, current_iter);
        break;
    default:
        fprintf(stderr, "unknown send-recv type %d\n", send_recv_type);
        return -1;
    }

    return ret;
}

static int client_server_do_work(ucp_worker_h ucp_worker, ucp_ep_h ep,
                                 send_recv_type_t send_recv_type, int is_server)
{
    int i, ret = 0;

    for (i = 0; i < num_iterations; i++) {
        ret = client_server_communication(ucp_worker, ep, send_recv_type,
                                          is_server, i);
        if (ret != 0) {
            fprintf(stderr, "%s failed on iteration #%d\n",
                    (is_server ? "server": "client"), i + 1);
            goto out;
        }
    }

out:
    return ret;
}

static int run_server(ucp_context_h ucp_context, ucp_worker_h ucp_worker,
                      char *listen_addr, send_recv_type_t send_recv_type)
{
    ucx_server_ctx_t context;
    ucp_worker_h     ucp_data_worker;\
    ucp_ep_h         server_ep;
    ucs_status_t     status;
    int              ret;

    /* Create a data worker (to be used for data exchange between the server
     * and the client after the connection between them was established) */
    ret = init_worker(ucp_context, &ucp_data_worker);
    if (ret != 0) {
        goto err;
    }

    if (send_recv_type == CLIENT_SERVER_SEND_RECV_AM) {
        ret = set_am_recv_handler(ucp_data_worker, TEST_AM_ID, ucp_am_data_cb);
        if (ret < 0) {
            goto err_worker;
        }
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
        goto err_worker;
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
        status = server_create_ep(ucp_data_worker, context.conn_request, 0,
                                  &server_ep);
        if (status != UCS_OK) {
            ret = -1;
            goto err_listener;
        }

        /* The server waits for all the iterations to complete before moving on
         * to the next client */
        ret = client_server_do_work(ucp_data_worker, server_ep, send_recv_type,
                                    1);
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
err_worker:
    ucp_worker_destroy(ucp_data_worker);
err:
    return ret;
}

static int run_client(ucp_worker_h ucp_worker, char *server_addr,
                      send_recv_type_t send_recv_type)
{
    ucp_ep_h     client_ep;
    ucs_status_t status;
    int          ret;

    status = start_client(ucp_worker, server_addr, 0, &client_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to start client (%s)\n", ucs_status_string(status));
        ret = -1;
        goto out;
    }

    ret = client_server_do_work(ucp_worker, client_ep, send_recv_type, 0);

    /* Close the endpoint to the server */
    ep_close(ucp_worker, client_ep, UCP_EP_CLOSE_MODE_FORCE);

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
        ret = run_client(ucp_worker, server_addr, send_recv_type);
    }

    ucp_worker_destroy(ucp_worker);
    ucp_cleanup(ucp_context);
err:
    return ret;
}
