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

#include <sys/time.h>

#include "ucx_allgather_common.h"

DOCA_LOG_REGISTER(UCX_ALLGATHER::Common);

static void connections_cleanup(int num_connections)
{
	int i;

	/** Go over all connections and destroy them by disconnecting */
	for (i = 0; i < num_connections; ++i)
		ucx_disconnect(connections[i]);

	free(connections);
}

/** Connects offloaded clients to their daemon and connects daemons/non-offloaded-clients to other daemons/clients */
static int connections_init(void)
{
	struct ucx_allgather_address *address;
	struct ucx_connection *connection;
	int ret, num_connections = 0;

	connections = malloc(ucx_app_config.dest_addresses.num * sizeof(*connections));
	if (connections == NULL) {
		DOCA_LOG_ERR("failed to allocate memory to hold array of connections");
		goto err;
	}

	/** Go over peer's addresses and establish connection to the peer using specified address */
	STAILQ_FOREACH(address, &ucx_app_config.dest_addresses.list, entry) {
		connection = NULL;
		ret = ucx_connect(context, address->ip_address_str, address->port, &connection);
		if (ret < 0)
			goto err_connections_cleanup;

		/** Save connection to the array of connections */
		connections[num_connections++] = connection;
	}

	return num_connections;

err_connections_cleanup:
	connections_cleanup(num_connections);
err:
	return -1;
}

static guint g_size_t_hash(gconstpointer v)
{
	return (guint) *(const size_t *)v;
}

static gboolean g_size_t_equal(gconstpointer v1, gconstpointer v2)
{
	return *((const size_t *)v1) == *((const size_t *)v2);
}

static void allgather_super_request_destroy_callback(gpointer data)
{
	allgather_super_request_destroy(data);
}

void process_cleanup(int num_connections)
{
	/** Destroy connections to other clients or daemon in case of client or to other daemons in case of daemon */
	connections_cleanup(num_connections);
	g_hash_table_destroy(allgather_super_requests_hash);
}

/** The return value indicates how many connections were created */
int process_init(void)
{
	int ret;

	/** Allocate hash of allgather requests to hold submitted operations */
	allgather_super_requests_hash = g_hash_table_new_full(g_size_t_hash, g_size_t_equal, NULL,
								allgather_super_request_destroy_callback);
	if (allgather_super_requests_hash == NULL) {
		ret = -1;
		goto err;
	}

	/*
	 * Setup receive handler for AM messages from daemons or non-offloaded clients which carry allgather data to do
	 * allgather for
	 */
	ucx_am_set_recv_handler(context, UCX_ALLGATHER_OP_AM_ID, am_recv_allgather_op_callback);

	if ((ucx_app_config.role == UCX_ALLGATHER_DAEMON) ||
		(ucx_app_config.allgather_mode == UCX_ALLGATHER_NON_OFFLOADED_MODE)) {

		/** Setup the listener to accept incoming connections from clients/daemons */
		ret = ucx_listen(context, ucx_app_config.listen_port);
		if (ret < 0)
			goto err_hash_table_destroy;
	}

	/** Initialize connections to other clients or daemon in case of client or to other daemons in case of daemon */
	return connections_init();

err_hash_table_destroy:
	g_hash_table_destroy(allgather_super_requests_hash);
err:
	return ret;
}

void allgather_super_request_destroy(struct ucx_allgather_super_request *allgather_super_request)
{
	size_t i;

	if ((ucx_app_config.allgather_mode == UCX_ALLGATHER_OFFLOADED_XGVMI_MODE) &&
		(ucx_app_config.role == UCX_ALLGATHER_CLIENT)) {
		for (i = 0; i < ucx_app_config.num_clients; ++i) {
			/*if (allgather_super_request->header.sender_client_id == i) {
				continue;
			}*/
			ucx_rkey_buffer_release(allgather_super_request->recv_rkey_buffers[i]);
			ucx_mem_unmap(context, allgather_super_request->recv_memhs[i]);
			allgather_super_request->recv_vectors[i] = NULL;
		}

		free(allgather_super_request->recv_rkey_buffers);
		free(allgather_super_request->recv_memhs);
	}

	if (allgather_super_request->result_vector_owner)
		free(allgather_super_request->result_vector);

	free(allgather_super_request->recv_vectors);
	free(allgather_super_request);
}

static inline void allgather_datatype_memset(void *vector, size_t length)
{
	size_t i;

	switch (ucx_app_config.datatype) {
	case UCX_ALLGATHER_BYTE:
		for (i = 0; i < length; ++i)
			((uint8_t *)vector)[i] = (uint8_t)ucx_app_config.client_id;
		break;
	case UCX_ALLGATHER_INT:
		for (i = 0; i < length; ++i)
			((int *)vector)[i] = (int)ucx_app_config.client_id;
		break;
	case UCX_ALLGATHER_FLOAT:
		for (i = 0; i < length; ++i)
			((float *)vector)[i] = (float)ucx_app_config.client_id;
		break;
	case UCX_ALLGATHER_DOUBLE:
		for (i = 0; i < length; ++i)
			((double *)vector)[i] = (double)ucx_app_config.client_id;
		break;
	}
}

static void* allgather_xgvmi_keys_pack(struct ucx_allgather_super_request *allgather_super_request)
{
	size_t i;
	void *xgvmi_keys_buffer;
	uint8_t *p;
	size_t *rkey_buffer_lengths;
	size_t xgvmi_keys_buffer_length = sizeof(struct ucx_allgather_xgvmi_buffer);

	rkey_buffer_lengths = alloca(sizeof(*rkey_buffer_lengths) * ucx_app_config.num_clients);

	allgather_super_request->recv_memhs = malloc(
			ucx_app_config.num_clients * sizeof(*allgather_super_request->recv_memhs));
	if (allgather_super_request->recv_memhs == NULL) {
		DOCA_LOG_ERR("failed to allocate memory for recv_memhs");
		return NULL;
	}

	allgather_super_request->recv_rkey_buffers = malloc(
			ucx_app_config.num_clients * sizeof(*allgather_super_request->recv_rkey_buffers));
	if (allgather_super_request->recv_rkey_buffers == NULL) {
		DOCA_LOG_ERR("failed to allocate memory for recv_rkey_buffers");
		return NULL;
	}

	for (i = 0; i < ucx_app_config.num_clients; ++i) {
		/*if (allgather_super_request->header.sender_client_id == i) {

			continue;
		}*/

		allgather_super_request->recv_memhs[i] = ucx_mem_map(context, NULL,
															allgather_super_request->result_vector_size *
															allgather_datatype_size[ucx_app_config.datatype],
															NULL, 3, 1);
		if (allgather_super_request->recv_memhs[i] == NULL) {
			DOCA_LOG_ERR("failed to do mem_map");
			return NULL;
		}

		allgather_super_request->recv_vectors[i] = allgather_super_request->recv_memhs[i]->address;
		allgather_super_request->recv_rkey_buffers[i] = ucx_rkey_pack(context, allgather_super_request->recv_memhs[i],
																	  &rkey_buffer_lengths[i]);
		xgvmi_keys_buffer_length += rkey_buffer_lengths[i] + sizeof(struct ucx_allgather_xgvmi_key);
	}

	xgvmi_keys_buffer = malloc(xgvmi_keys_buffer_length);
	if (xgvmi_keys_buffer == NULL) {
		DOCA_LOG_ERR("failed to alloc mem for xgvmi_keys_buffer");
		return NULL;
	}

	p = (uint8_t*)xgvmi_keys_buffer;

	((struct ucx_allgather_xgvmi_buffer*)xgvmi_keys_buffer)->num_keys = ucx_app_config.num_clients;
	p += sizeof(struct ucx_allgather_xgvmi_buffer);

	for (i = 0; i < ucx_app_config.num_clients; ++i) {
		((struct ucx_allgather_xgvmi_key*)p)->length = rkey_buffer_lengths[i];
		((struct ucx_allgather_xgvmi_key*)p)->address = (uint64_t)(uintptr_t)allgather_super_request->recv_vectors[i];
		p += sizeof(struct ucx_allgather_xgvmi_key);

		DOCA_LOG_DBG("%zu: length - %zu, addr - %p", i, rkey_buffer_lengths[i],
						allgather_super_request->recv_vectors[i]);

		memcpy(p, allgather_super_request->recv_rkey_buffers[i], rkey_buffer_lengths[i]);
		p += rkey_buffer_lengths[i];
	}

	assert(p == ((uint8_t*)xgvmi_keys_buffer + xgvmi_keys_buffer_length));

	allgather_super_request->xgvmi_rkeys_buffer = xgvmi_keys_buffer;
	allgather_super_request->xgvmi_rkeys_buffer_length = xgvmi_keys_buffer_length;

	return xgvmi_keys_buffer;
}

struct ucx_allgather_super_request *
allgather_super_request_allocate(const struct ucx_allgather_header *header, size_t length, void *result_vector)
{
	struct ucx_allgather_super_request *allgather_super_request;

	allgather_super_request = malloc(sizeof(*allgather_super_request));
	if (allgather_super_request == NULL) {
		DOCA_LOG_ERR("failed to allocate memory for allgather super request");
		goto err;
	}

	/** Set default values to the fields of the allgather super requests */
	STAILQ_INIT(&allgather_super_request->allgather_requests_list);
	allgather_super_request->header.id = header->id;
	allgather_super_request->header.sender_client_id = ucx_app_config.client_id;
	allgather_super_request->header.vector_size = length;
	allgather_super_request->num_allgather_requests = 0;
	/*
	 * Count required send & receive vectors between us and peers (daemons or non-offloaded clients).
	 * Also, count +1 operation for completing operations in case of no peers exist.
	 */
	if (ucx_app_config.allgather_mode == UCX_ALLGATHER_NON_OFFLOADED_MODE) {
		assert(ucx_app_config.role == UCX_ALLGATHER_CLIENT);
		allgather_super_request->num_allgather_operations = 2 * (ucx_app_config.num_clients - 1) + 1;
	} else if (ucx_app_config.role == UCX_ALLGATHER_CLIENT) {
		assert(ucx_app_config.allgather_mode == UCX_ALLGATHER_OFFLOADED_MODE ||
			   ucx_app_config.allgather_mode == UCX_ALLGATHER_OFFLOADED_XGVMI_MODE);
		assert(ucx_app_config.dest_addresses.num == 1);
		allgather_super_request->num_allgather_operations = ucx_app_config.num_clients - 1;
	} else {
		assert(ucx_app_config.role == UCX_ALLGATHER_DAEMON);
		allgather_super_request->num_allgather_operations = ucx_app_config.num_clients + 1;
	}
	allgather_super_request->result_vector_size = length;
	allgather_super_request->recv_vector_iter = 0;
	if (result_vector == NULL) {
		/*
		 * result_vector is NULL in case processing Active Message receive operation from peers on daemon or
		 * non-offloaded client side
		 */
		allgather_super_request->result_vector_owner = 1;
		allgather_super_request->result_vector = malloc(allgather_super_request->result_vector_size *
								allgather_datatype_size[ucx_app_config.datatype]);
		if (allgather_super_request->result_vector == NULL) {
			DOCA_LOG_ERR("failed to allocate memory to hold the allgather result");
			goto err_allgather_super_request_free;
		}
		allgather_datatype_memset(allgather_super_request->result_vector,
						allgather_super_request->result_vector_size);
	} else {
		allgather_super_request->result_vector_owner = 0;
		allgather_super_request->result_vector = result_vector;
	}

	/** Allocate receive vectors for each connection to be used when doing allgather between daemons or clients */
	allgather_super_request->recv_vectors =
			calloc(ucx_app_config.num_clients, sizeof(*allgather_super_request->recv_vectors));
	if (allgather_super_request->recv_vectors == NULL) {
		DOCA_LOG_ERR("failed to allocate memory for receive vectors");
		goto err_result_vector_free;
	}

	STAILQ_INIT(&allgather_super_request->am_desc_list);

	if ((ucx_app_config.allgather_mode == UCX_ALLGATHER_OFFLOADED_XGVMI_MODE) &&
		(ucx_app_config.role == UCX_ALLGATHER_CLIENT)) {
		allgather_xgvmi_keys_pack(allgather_super_request);
	}

	return allgather_super_request;

err_result_vector_free:
	if (allgather_super_request->result_vector_owner)
		free(allgather_super_request->result_vector);
err_allgather_super_request_free:
	free(allgather_super_request);
err:
	return NULL;
}

void allgather_request_destroy(struct ucx_allgather_request *allgather_request)
{
	//fprintf(stderr, "destroy %p allgather request\n", allgather_request);
	free(allgather_request->headers);
	free(allgather_request->vector);
	free(allgather_request);
}

struct ucx_allgather_request *allgather_request_allocate(struct ucx_connection *connection,
							const struct ucx_allgather_header *header, int ret,
							struct ucx_request *request, size_t length)
{
	struct ucx_allgather_request *allgather_request;

	allgather_request = malloc(sizeof(*allgather_request));
	if (allgather_request == NULL) {
		DOCA_LOG_ERR("failed to allocate memory for allgather request");
		goto err;
	}

	//fprintf(stderr, "allocated %p allgather request\n", allgather_request);

	/** Set default values to the fields of the allgather request */
	allgather_request->header = *header;
	allgather_request->vector = malloc(length * allgather_datatype_size[ucx_app_config.datatype]);
	if (allgather_request->vector == NULL) {
		DOCA_LOG_ERR("failed to allocate memory for receive vector");
		goto err_allgather_request_free;
	}

	if (ucx_app_config.allgather_mode == UCX_ALLGATHER_OFFLOADED_XGVMI_MODE) {
		allgather_request->xgvmi_memhs = calloc(ucx_app_config.num_clients, sizeof(*allgather_request->xgvmi_memhs));
		if (allgather_request->xgvmi_memhs == NULL) {
			DOCA_LOG_ERR("failed to allocate memory for xgvmi keys");
			goto err_allgather_request_free;
		}
	}

	allgather_request->vector_size = length / allgather_datatype_size[ucx_app_config.datatype];
	allgather_request->connection = connection;
	allgather_request->allgather_super_request = NULL;
	if (ucx_app_config.allgather_mode != UCX_ALLGATHER_OFFLOADED_XGVMI_MODE) {
		allgather_request->num_allgather_operations = ucx_app_config.num_clients;
	} else {
		allgather_request->num_allgather_operations = 1;
	}
	allgather_request->headers = malloc(ucx_app_config.num_clients * sizeof(*allgather_request->headers));
	if (allgather_request->headers == NULL) {
		DOCA_LOG_ERR("failed to allocate memory for headers");
		goto err_allgather_vector_free;
	}
	//fprintf(stderr, "allocated allgather request %p - %zu\n", allgather_request, allgather_request->num_allgather_operations);

	return allgather_request;

err_allgather_vector_free:
	free(allgather_request->vector);
err_allgather_request_free:
	free(allgather_request);
err:
	return NULL;
}

static void daemon_allgather_complete_client_operation_callback(void *arg, ucs_status_t status)
{
	struct ucx_allgather_request *allgather_request = arg;
	struct ucx_allgather_super_request *allgather_super_request = allgather_request->allgather_super_request;
	size_t i;

	assert(status == UCS_OK);

	--allgather_request->num_allgather_operations;
	DOCA_LOG_DBG("daemon allgather request %p complete %zu\n", allgather_request, allgather_request->num_allgather_operations);
	//fprintf(stderr, "daemon allgather request %p complete %zu\n", allgather_request, allgather_request->num_allgather_operations);
	if (allgather_request->num_allgather_operations > 0) {
		return;
	}

	/** Sending completion to the client was completed, release the allgather request */
	allgather_request_destroy(allgather_request);

	--allgather_super_request->num_allgather_requests;
	DOCA_LOG_DBG("daemon allgather super request complete %zu\n", allgather_super_request->num_allgather_requests);
	//fprintf(stderr, "daemon allgather super request complete %zu\n", allgather_super_request->num_allgather_requests);
	if (allgather_super_request->num_allgather_requests > 0) {
		/** Not all allgather operations were completed yet by sending AM operation with the result to the client */
		return;
	}

	for (i = 0; i < ucx_app_config.num_clients; ++i) {
		free(allgather_super_request->recv_vectors[i]);
	}

	/** All allgather operations were completed, release allgather super request */
	allgather_super_request_destroy(allgather_super_request);
}

static void allgather_complete_common_operation_callback(void *arg, ucs_status_t status,
					const char *name)
{
	struct ucx_allgather_super_request *allgather_super_request = arg;
	struct ucx_allgather_request *allgather_request, *tmp_allgather_request;
	size_t connection_iter;
	size_t i;

	assert(status == UCS_OK);

    --allgather_super_request->num_allgather_operations;

    DOCA_LOG_DBG("%s num_operations=%zu", name,
                  allgather_super_request->num_allgather_operations);
	//fprintf(stderr, "COMPLETING %zu \n", allgather_super_request->num_allgather_operations);

	/** Check if completed receive and send operations per each connection */
	if (allgather_super_request->num_allgather_operations > 0) {
		/** Not all allgather operations among clients or daemons were completed yet */
		return;
	}

	/** Remove the allgather super request from the hash */
	DOCA_LOG_DBG("remove allgather %zu from hash", allgather_super_request->header.id);
	g_hash_table_steal(allgather_super_requests_hash, &allgather_super_request->header.id);

	if (ucx_app_config.role == UCX_ALLGATHER_CLIENT) {
		/** All allgather operations among clients or daemons were completed */
		for (connection_iter = 0; connection_iter < (ucx_app_config.num_clients - 1); ++connection_iter) {
			/** Do operation among all elements of the received vector */
			free(allgather_super_request->recv_vectors[connection_iter]);
		}

		assert(STAILQ_EMPTY(&allgather_super_request->allgather_requests_list));
		/** allgather operation is completed for client, because there is no need to send the result to peers */
		allgather_super_request_destroy(allgather_super_request);
		return;
	}

	assert(ucx_app_config.role == UCX_ALLGATHER_DAEMON);

	if (ucx_app_config.allgather_mode != UCX_ALLGATHER_OFFLOADED_XGVMI_MODE) {
		for (i = 0; i < ucx_app_config.num_clients; ++i) {
			/** Go over all requests received from the clients and send the result to them */
			STAILQ_FOREACH_SAFE(allgather_request, &allgather_super_request->allgather_requests_list, entry,
								tmp_allgather_request) {
				/** A completion is sent only by daemons to clients */
				//fprintf(stderr, "doing send for %p - %zu\n", allgather_request, allgather_request->num_allgather_operations);
				if (allgather_request->header.sender_client_id == i) {
					daemon_allgather_complete_client_operation_callback(allgather_request, UCS_OK);
					continue;
				}

				allgather_request->headers[i].id = allgather_super_request->header.id;
				allgather_request->headers[i].sender_client_id = i;

				ucx_am_send(allgather_request->connection, UCX_ALLGATHER_OP_AM_ID,
						&allgather_request->headers[i], sizeof(allgather_request->headers[i]),
						allgather_super_request->recv_vectors[i],
						allgather_super_request->result_vector_size *
						allgather_datatype_size[ucx_app_config.datatype], NULL,
						daemon_allgather_complete_client_operation_callback, allgather_request, NULL);
			}
		}
	} else {
		STAILQ_FOREACH_SAFE(allgather_request, &allgather_super_request->allgather_requests_list, entry,
							tmp_allgather_request) {
			ucx_am_send(allgather_request->connection, UCX_ALLGATHER_CTRL_XGVMI_DONE_AM_ID,
						&allgather_request->header, sizeof(allgather_request->header),
						NULL, 0, NULL,
						daemon_allgather_complete_client_operation_callback, allgather_request, NULL);
		}
	}
}

static void allgather_send_complete_callback(void *arg, ucs_status_t status)
{
	allgather_complete_common_operation_callback(arg, status, "allgather_send_complete_callback");

}

void allgather_recv_complete_callback(void *arg, ucs_status_t status)
{
	allgather_complete_common_operation_callback(arg, status, "allgather_recv_complete_callback");
}

void do_allgather(struct ucx_allgather_super_request *allgather_super_request)
{
	struct ucx_allgather_request *allgather_request, *tmp_allgather_request;
	size_t i, client_id;

	//fprintf(stderr, "STARTING ALLGATHER\n");
	DOCA_LOG_DBG("doing allgather");

	if (ucx_app_config.role == UCX_ALLGATHER_CLIENT) {
		/** Post send operations to exchange allgather vectors among other clients */
		for (i = 0; i < ucx_app_config.dest_addresses.num; ++i) {
			//fprintf(stderr, "SENDING %zu\n", allgather_super_request->header.sender_client_id);
			ucx_am_send(connections[i], UCX_ALLGATHER_OP_AM_ID, &allgather_super_request->header,
					sizeof(allgather_super_request->header), allgather_super_request->result_vector,
					allgather_super_request->result_vector_size *
					allgather_datatype_size[ucx_app_config.datatype], NULL,
					allgather_send_complete_callback, allgather_super_request, NULL);
		}
	} else {
		assert(ucx_app_config.role == UCX_ALLGATHER_DAEMON);

		STAILQ_FOREACH_SAFE(allgather_request, &allgather_super_request->allgather_requests_list, entry,
						tmp_allgather_request) {
			for (i = 0; i < ucx_app_config.dest_addresses.num; ++i) {
				client_id = allgather_request->header.sender_client_id;

				allgather_request->headers[i].id = allgather_super_request->header.id;
				allgather_request->headers[i].sender_client_id = client_id;
				allgather_request->headers[i].vector_size = allgather_super_request->result_vector_size;
				//fprintf(stderr, "SENDING %zu\n", allgather_super_request->header.sender_client_id);
				if (ucx_app_config.allgather_mode == UCX_ALLGATHER_OFFLOADED_XGVMI_MODE) {
					DOCA_LOG_DBG("client[%zd] id %zd xgvmi am_send", i, client_id);
					ucx_am_send(connections[i], UCX_ALLGATHER_OP_AM_ID, &allgather_request->headers[i],
							sizeof(allgather_request->headers[i]), (void*)(uintptr_t)allgather_request->xgvmi_memhs[client_id]->address,
							allgather_super_request->result_vector_size *
							allgather_datatype_size[ucx_app_config.datatype], allgather_request->xgvmi_memhs[client_id]->memh,
							allgather_send_complete_callback, allgather_super_request, NULL);
				} else {
					DOCA_LOG_DBG("client[%zd] id %zd am_send", i, client_id);
					ucx_am_send(connections[i], UCX_ALLGATHER_OP_AM_ID, &allgather_request->headers[i],
								sizeof(allgather_request->headers[i]), allgather_super_request->recv_vectors[client_id],
                                allgather_super_request->result_vector_size *
                                allgather_datatype_size[ucx_app_config.datatype], NULL,
                                allgather_send_complete_callback, allgather_super_request, NULL);
				}
			}
		}
	}

	/*
	 * Try to complete the operation, it completes if no other daemons or non-offloaded clients exist or sends were
	 * completed immediately
	 */
	allgather_complete_common_operation_callback(allgather_super_request, UCS_OK, "stub");
}

/** AM receive callback which is invoked when the daemon/client receives notification from another daemon/client */
int am_recv_allgather_op_callback(struct ucx_am_desc *am_desc)
{
	struct ucx_connection *connection;
	const struct ucx_allgather_header *allgather_header;
	struct ucx_allgather_super_request *allgather_super_request;
	void *vector;
	size_t header_length, length;
	size_t vector_size;
	struct ucx_allgather_request *allgather_request;

	ucx_am_desc_query(am_desc, &connection, (const void **)&allgather_header, &header_length, &length);

	DOCA_LOG_DBG("am_desc: header_length %zu length %zu", header_length, length);

	assert(sizeof(*allgather_header) == header_length);
	assert(length % allgather_datatype_size[ucx_app_config.datatype] == 0);

	vector_size = length / allgather_datatype_size[ucx_app_config.datatype];

	/** Either find or allocate the allgather super request to start doing allgather operations */
	allgather_super_request = allgather_super_request_get(allgather_header, vector_size, NULL);
	if (allgather_super_request == NULL)
		return -1;

	if (ucx_app_config.allgather_mode != UCX_ALLGATHER_OFFLOADED_XGVMI_MODE) {
		vector = malloc(allgather_super_request->result_vector_size *
				allgather_datatype_size[ucx_app_config.datatype]);
		if (vector == NULL) {
			DOCA_LOG_ERR("failed to allocate memory to hold receive vector");
			return -1;
		}

		//fprintf(stderr, "is going to receive msg for %zu\n", allgather_header->sender_client_id);
		allgather_vector_received(allgather_header, allgather_super_request, vector);

		/** Continue receiving data to the allocated vector */
		ucx_am_recv(am_desc, vector, length, NULL, allgather_recv_complete_callback, allgather_super_request, NULL);
	} else {
		STAILQ_FOREACH(allgather_request, &allgather_super_request->allgather_requests_list, entry) {
			if (allgather_request->xgvmi_memhs[allgather_header->sender_client_id]->done) {
				DOCA_LOG_DBG("client id %zu: already receuved", allgather_header->sender_client_id);
				continue;
			}

			DOCA_LOG_DBG("found %zu: recv: header_length %zu length %zu - to addr=%p",
							allgather_header->sender_client_id, header_length, length,
							(void*)allgather_request->xgvmi_memhs[allgather_header->sender_client_id]->address);
			ucx_am_recv(am_desc, (void*)allgather_request->xgvmi_memhs[allgather_header->sender_client_id]->address,
						vector_size, allgather_request->xgvmi_memhs[allgather_header->sender_client_id]->memh,
						allgather_recv_complete_callback, allgather_super_request, NULL);
			allgather_request->xgvmi_memhs[allgather_header->sender_client_id]->done = 1;
			return 1;
		}

		DOCA_LOG_DBG("%zu saved: recv: header_length %zu length %zu",
							allgather_header->sender_client_id, header_length, length);
		STAILQ_INSERT_TAIL(&allgather_super_request->am_desc_list, am_desc, entry);
		return 0;
	}
	return 1;
}
