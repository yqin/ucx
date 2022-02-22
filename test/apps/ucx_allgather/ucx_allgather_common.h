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

#ifndef UCX_ALLGATHER_COMMON_H_
#define UCX_ALLGATHER_COMMON_H_

/** Define _GNU_SOURCE which is required to use GNU hash from glib.h */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include </usr/include/glib-2.0/glib.h>
#include <assert.h>
#include <sys/queue.h>

#include "ucx_core.h"

enum ucx_allgather_role {
	/*< allgather client (available for non-offloaded and offloaded modes) */
	UCX_ALLGATHER_CLIENT,
	/*< allgather daemon (available for offloaded mode only) */
	UCX_ALLGATHER_DAEMON
};

enum ucx_allgather_mode {
	/*< Non-offloaded allgather algorithm, requires connection between clients only */
	UCX_ALLGATHER_NON_OFFLOADED_MODE,
	/*< Offloaded allgather algorithm, requires connection between clients and daemons */
	UCX_ALLGATHER_OFFLOADED_MODE,
	UCX_ALLGATHER_OFFLOADED_XGVMI_MODE
};

enum ucx_allgather_am_id {
	/*< Sent by clients to daemon to notify about allgather operations, and sent by daemons to clients to notify about completions of allgather operations */
	UCX_ALLGATHER_CTRL_AM_ID = 0,
	/*< Exchanged by clients or daemons to perform allgather operations */
	UCX_ALLGATHER_OP_AM_ID = 1,
	UCX_ALLGATHER_CTRL_XGVMI_AM_ID = 2,
	/*< Maximum AM identifier used by the application */
	UCX_ALLGATHER_MAX_AM_ID = UCX_ALLGATHER_CTRL_XGVMI_AM_ID
};

enum ucx_allgather_datatype {
	UCX_ALLGATHER_BYTE,
	UCX_ALLGATHER_INT,
	UCX_ALLGATHER_FLOAT,
	UCX_ALLGATHER_DOUBLE
};

struct ucx_allgather_config {
	enum ucx_allgather_role role; /*< Indicates whether the process is daemon or client */
	uint16_t dest_port; /*< Peer's port which should be used if the port isn't specified in the string of the addresses */
	uint16_t listen_port; /*< Port which should be used to list for incoming connections */
	size_t num_clients; /*< Indicates how many client's connections should be expected by daemons/clients */
	size_t num_daemon_bound_clients; /*< Indicates how many clients are bound to a daemon */
	size_t client_id; /*< Client ID */
	size_t vector_size; /*< allgather vector size */
	enum ucx_allgather_datatype datatype; /*< Datatype of allgather element */
	size_t batch_size; /*< Number of allgather operations to submit simultaneously and wait compeltion for */
	size_t num_batches; /*< Indicates how many batches should be performed by clients */
	enum ucx_allgather_mode allgather_mode; /*< allgather algorithm which should be used */
	struct {
		union {
			/*< Valid after calling dest_addresses_init() */
			STAILQ_HEAD(addresses, ucx_allgather_address) list;
			/*< Valid before calling dest_addresses_init() */
			char *str;
		};
		size_t num; /*< Number of peer's addresses */
	} dest_addresses; /*< Destination addresses */
};

struct ucx_allgather_address {
	STAILQ_ENTRY(ucx_allgather_address) entry; /*< List entry */
	char ip_address_str[64]; /*< Peer's IP address string */
	uint16_t port; /*< Peer's port */
};

struct ucx_allgather_header {
	size_t id; /*< allgather operation identifier */
	size_t sender_client_id; /*< Sender client identifier */
	size_t vector_size;
};

struct ucx_allgather_xgvmi_key {
	uint64_t address;
	size_t length;
	char rkey_buffer[0];
};

struct ucx_allgather_xgvmi_buffer {
	size_t num_keys;
	struct ucx_allgather_xgvmi_key keys[0];
};

struct ucx_allgather_xgvmi_memh {
	uint64_t address;
	struct ucx_memh *memh;
};

/** Request of allgather operation which supervises 'ucx_allgather_request' operations which do some parts of complex allgather operation,
 * e.g. receiving initial data from clients on daemon to do allgather for
 */
struct ucx_allgather_super_request {
	STAILQ_HEAD(allgather_requests, ucx_allgather_request) allgather_requests_list; /*< List of allgather requests received by daemons to perform */
	size_t num_allgather_requests; /*< Number of allgather requests received by daemons and not completed yet */
	size_t num_allgather_operations; /*< Number of send and receive operations that are not completed yet between peers (daemons or nonoffloaded-clients) to consider an allgather operation done */
	int result_vector_owner; /*< Indicates memory ownership over the result vectors */
	void *result_vector; /*< allgather result vector */
	size_t recv_vector_iter; /*< Indicated how many receive vectors are filled by data received from daemons or clients */
	void **recv_vectors; /*< Receive vectors to hold */
	struct ucx_memh **recv_memhs;
	void **recv_rkey_buffers;
	void *xgvmi_rkeys_buffer;
	size_t xgvmi_rkeys_buffer_length;
	struct ucx_allgather_header header; /*< Header of allgather operation */
	size_t result_vector_size; /*< Size of the allgather result vector */
};

/** Request of allgather operation which defines some part of complex allgather operation, e.g. receiving initial data from clients on
 * daemon to do allgather for
 */
struct ucx_allgather_request {
	STAILQ_ENTRY(ucx_allgather_request) entry; /*< List entry */
	struct ucx_allgather_super_request *allgather_super_request; /*< Owner of allgather operation */
	struct ucx_allgather_header header; /*< Header of allgather operation */
	struct ucx_connection *connection; /*< Connection on which an allgather operation was sent on clients or received on daemons */
	void *vector; /*< Vector which contains data to send as a part of an allgather operation */
	size_t vector_size; /*< Size of a vector which should be send as a part of an allgather operation */
	struct ucx_allgather_header *headers; /*< Headers which are sent to clients from daemon */
	size_t num_allgather_operations; /*< How many allgather vectors should be sent to a local clients from daemon */
	struct ucx_allgather_xgvmi_memh **xgvmi_memhs;
};

extern const char * const allgather_role_str[];
extern const char * const allgather_mode_str[];
extern const char * const allgather_datatype_str[];
extern const size_t allgather_datatype_size[];
extern struct ucx_allgather_config ucx_app_config;
struct ucx_context *context;
struct ucx_connection **connections;
extern GHashTable *allgather_super_requests_hash;

void process_cleanup(int num_connections);

int process_init(void);

void allgather_super_request_destroy(struct ucx_allgather_super_request *allgather_super_request);

struct ucx_allgather_super_request *
allgather_super_request_allocate(const struct ucx_allgather_header *header, size_t length, void *result_vector);

static inline struct ucx_allgather_super_request *
allgather_super_request_get(const struct ucx_allgather_header *allgather_header, size_t result_length,
				void *result_vector)
{
	struct ucx_allgather_super_request *allgather_super_request;

	/** Check having allgather super request in the hash */
	allgather_super_request = g_hash_table_lookup(allgather_super_requests_hash, &allgather_header->id);
	if (allgather_super_request == NULL) {
		/** If there is no allgather super request in the hash, allocate it */
		allgather_super_request = allgather_super_request_allocate(allgather_header, result_length, result_vector);
		if (allgather_super_request == NULL)
			return NULL;

		/** Insert the allocated allgather super request to the hash */
		g_hash_table_insert(allgather_super_requests_hash, &allgather_super_request->header.id,
							allgather_super_request);
	} else {
		allgather_super_request->header.sender_client_id = ucx_app_config.client_id;
	}

	return allgather_super_request;
}

void do_allgather(struct ucx_allgather_super_request *allgather_super_request);

static inline void allgather_vector_received(const struct ucx_allgather_header *allgather_header,
								struct ucx_allgather_super_request *allgather_super_request,
								void *vector)
{
	size_t iter;

	assert(allgather_super_request->recv_vector_iter < ucx_app_config.num_clients);

	/** Save vector to the array of receive vectors for futher performing allgather and releasing it then */
	if (ucx_app_config.role == UCX_ALLGATHER_CLIENT) {
		assert(allgather_header->sender_client_id != ucx_app_config.client_id);
		iter = (allgather_header->sender_client_id < ucx_app_config.client_id) ?
				allgather_header->sender_client_id : (allgather_header->sender_client_id - 1);
	} else {
		assert(ucx_app_config.role == UCX_ALLGATHER_DAEMON);
		iter = allgather_header->sender_client_id;
	}
	allgather_super_request->recv_vectors[iter] = vector;
	//fprintf(stderr, "Starting receive operation - %zu to receive %zu\n",
	//		allgather_super_request->recv_vector_iter, allgather_header->sender_client_id);
	++allgather_super_request->recv_vector_iter;

}

int am_recv_allgather_op_callback(struct ucx_am_desc *am_desc);

void allgather_request_destroy(struct ucx_allgather_request *allgather_request);

struct ucx_allgather_request *allgather_request_allocate(struct ucx_connection *connection,
							const struct ucx_allgather_header *header, int ret,
							struct ucx_request *request, size_t length);

#endif /** UCX_ALLGATHER_COMMON_H_ */
