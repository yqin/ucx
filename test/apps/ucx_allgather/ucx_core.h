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



#ifndef UCX_CORE_H_
#define UCX_CORE_H_

#include <ucp/api/ucp.h>

#include <sys/queue.h>

extern int doca_print_enable;

#ifndef STAILQ_FOREACH_SAFE
#define STAILQ_FOREACH_SAFE(_node, _list, _name, _temp_node) \
	for (_node = STAILQ_FIRST(_list), \
		_temp_node = ((_node) != NULL) ? STAILQ_NEXT(_node, _name) : NULL; \
		(_node) != NULL; \
		_node = _temp_node, \
		_temp_node = ((_node) != NULL) ? STAILQ_NEXT(_node, _name) : NULL)

#endif

#define DOCA_LOG_REGISTER(_name)

#define DOCA_LOG_ERR(_fmt, ...) \
	if (doca_print_enable) { \
		fprintf(stderr, "ERROR "_fmt"\n", ## __VA_ARGS__); \
		exit(0); \
	}

#define DOCA_LOG_DBG(_fmt, ...) \
	if (doca_print_enable) { \
		fprintf(stderr, "DEBUG " _fmt"\n", ## __VA_ARGS__); \
	}

#define DOCA_LOG_INFO(_fmt, ...) \
	if (1) { \
		fprintf(stderr, "INFO  " _fmt"\n", ## __VA_ARGS__); \
	}

#define APP_EXIT(_fmt, ...) \
	do { \
		fprintf(stderr, "EXIT  " _fmt"\n", ## __VA_ARGS__); \
		exit(-1); \
	} while (0)

struct ucx_context;
struct ucx_connection;
struct ucx_request;
struct ucx_am_desc;

struct ucx_memh {
	ucp_mem_h memh;
	ucp_rkey_h rkey;
	void *address;
	size_t length;
};


struct ucx_am_desc {
	STAILQ_ENTRY(ucx_am_desc) entry;
	struct ucx_connection *connection; /*< Pointer to the connection on which this AM operation was received */
	const void *header; /*< Header got from AM callback */
	size_t header_length; /*< Length of the header got from AM callback */
	void *data_desc; /*< Pointer to the descriptor got from AM callback. In case of Rendezvous, it is not the actual data, but only a data descriptor */
	size_t length; /*< Length of the received data */
	uint64_t flags; /*< AM operation flags */
};

typedef void (*ucx_callback)(void *arg, ucs_status_t status);
typedef int (*ucx_am_callback)(struct ucx_am_desc *am_desc);

/***** Requests Processing *****/

int ucx_request_wait(int ret, struct ucx_request *request);

void ucx_request_release(struct ucx_request *request);

/***** Active Message send operation *****/

int ucx_am_send(struct ucx_connection *connection, unsigned int am_id, const void *header, size_t header_length,
		const void *buffer, size_t length, struct ucx_memh *memh, ucx_callback callback, void *arg,
		struct ucx_request **request_p);

/***** Active Message receive operation *****/

int ucx_am_recv(struct ucx_am_desc *am_desc, void *buffer, size_t length, struct ucx_memh *memh, ucx_callback callback, void *arg,
		struct ucx_request **request_p);

void ucx_am_desc_query(struct ucx_am_desc *am_desc, struct ucx_connection **connection, const void **header,
			size_t *header_length, size_t *length);

void ucx_am_set_recv_handler(struct ucx_context *context, unsigned int am_id, ucx_am_callback callback);

/***** Connection establishment *****/

int ucx_connect(struct ucx_context *context, const char *dest_ip_str, uint16_t dest_port,
		struct ucx_connection **connection_p);

void ucx_disconnect(struct ucx_connection *connection);

/***** Main UCX operations *****/

int ucx_init(struct ucx_context **context_p, unsigned int max_am_id);

void ucx_destroy(struct ucx_context *context);

int ucx_listen(struct ucx_context *context, uint16_t port);

void ucx_progress(struct ucx_context *context);

struct ucx_memh* ucx_mem_map(struct ucx_context *context, void *address, size_t length, void *rkey_buffer, uint32_t peer_id, int shared);

void ucx_mem_unmap(struct ucx_context *context, struct ucx_memh *memh);

void* ucx_rkey_pack(struct ucx_context *context, struct ucx_memh *memh, size_t *length);

void ucx_rkey_buffer_release(void *rkey_buffer);

#endif /** UCX_CORE_H_ */
