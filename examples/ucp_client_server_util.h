#ifndef UCP_CLIENT_SERVER_UTIL_H_
#define UCP_CLIENT_SERVER_UTIL_H_

#include "ucp_util.h"


#define COMM_TYPE_DEFAULT      "STREAM"
#define DEFAULT_NUM_ITERATIONS 1
#define TEST_AM_ID             0


typedef enum {
    CLIENT_SERVER_SEND_RECV_STREAM  = UCS_BIT(0),
    CLIENT_SERVER_SEND_RECV_TAG     = UCS_BIT(1),
    CLIENT_SERVER_SEND_RECV_AM      = UCS_BIT(2),
    CLIENT_SERVER_SEND_RECV_RMA     = UCS_BIT(3),
    CLIENT_SERVER_SEND_RECV_DEFAULT = CLIENT_SERVER_SEND_RECV_STREAM
} send_recv_type_t;


typedef struct ucx_context {
    int completed;
} ucx_context_t;


extern long iov_cnt;
extern int num_iterations;
extern int use_prealloc_buffer;


/**
 * Server's application context to be used in the user's connection request
 * callback.
 * It holds the server's listener and the handle to an incoming connection request.
 */
typedef struct ucx_server_ctx {
    volatile ucp_conn_request_h conn_request;
    ucp_listener_h              listener;
} ucx_server_ctx_t;


/**
 * Print the client-server application's usage help message.
 */
void print_usage();


/**
 * Parse the client-server command line arguments.
 */
int parse_cmd(int argc, char *const argv[], char **server_addr,
              char **listen_addr, send_recv_type_t *send_recv_type);


/**
 * Create a ucp worker on the given ucp context.
 */
int init_worker(ucp_context_h ucp_context, ucp_worker_h *ucp_worker);


/**
 * Initialize request.
 * 
 */
void request_init(void *request);


/**
 * Initialize the UCP context and worker.
 */
int init_context(ucp_context_h *ucp_context, ucp_worker_h *ucp_worker,
                 send_recv_type_t send_recv_type);


/**
 * Progress the request until it completes.
 */
ucs_status_t request_wait(ucp_worker_h ucp_worker, void *request,
                          ucx_context_t *ctx);


/**
 * Common callback for send and receive operations.
 */
void common_cb(void *user_data, const char *type_str);


/**
 * The callback on the sending side, which is invoked after finishing sending
 * the message.
 */
void send_cb(void *request, ucs_status_t status, void *user_data);


/**
 * The callback on the receiving side, which is invoked upon receiving the
 * active message.
 */
void am_recv_cb(void *request, ucs_status_t status, size_t length,
                void *user_data);


/**
 * Set AM receive handler.
 */
int set_am_recv_handler(ucp_worker_h ucp_worker, unsigned id,
                        ucp_am_recv_callback_t cb);


/**
 * Initialize the client side. Create an endpoint from the client side to be
 * connected to the remote server (to the given IP).
 */
ucs_status_t start_client(ucp_worker_h ucp_worker, const char *address_str,
                          unsigned flags, ucp_ep_h *client_ep);


/**
 * Initialize the server side. The server starts listening on the set address.
 */
ucs_status_t start_server(ucp_worker_h ucp_worker, ucx_server_ctx_t *context,
                          ucp_listener_h *listener_p, const char *address_str);


ucs_status_t server_create_ep(ucp_worker_h data_worker,
                              ucp_conn_request_h conn_request,
                              unsigned flags, ucp_ep_h *server_ep);

#endif
