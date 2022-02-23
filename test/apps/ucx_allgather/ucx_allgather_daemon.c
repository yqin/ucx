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

#include <signal.h>
#include <errno.h>
#include <errno.h>

#include "ucx_allgather_daemon.h"

static volatile int running = 1; /*< Indicates if the process still running or not, used by daemons */

DOCA_LOG_REGISTER(UCX_allgather::Daemon);

/** Daemon callback to complete receiving the vector with the data from the client to do allgather for */
static void daemon_am_recv_data_complete_callback(void *arg, ucs_status_t status)
{
	struct ucx_allgather_request *allgather_request = arg;
	struct ucx_allgather_super_request *allgather_super_request;

	assert(status == UCS_OK);

	/** Received size of the vector must be <= the configured size by a user */
	assert(allgather_request->vector_size <= ucx_app_config.vector_size);

	/** Try to find or allocate allgather super request to match the allgather request which is currently received */
	allgather_super_request = allgather_super_request_get(&allgather_request->header, allgather_request->vector_size,
								NULL);
	if (allgather_super_request == NULL) {
		allgather_request_destroy(allgather_request);
		return;
	}

	/** Attach the received allgather request to the allgather super request for futher processing */
	allgather_request->allgather_super_request = allgather_super_request;
	++allgather_super_request->num_allgather_requests;
	allgather_vector_received(&allgather_request->header, allgather_super_request, allgather_request->vector);
	allgather_request->vector = NULL;
	STAILQ_INSERT_TAIL(&allgather_super_request->allgather_requests_list, allgather_request, entry);

	/** The whole result will be sent to the other daemons when all vectors are received from clinets */

	/*free(allgather_request->vector);
	allgather_request->vector = NULL;*/

	if (allgather_super_request->num_allgather_requests == ucx_app_config.num_daemon_bound_clients) {
		/*
		 * Daemons received the allgather vectors from all clients - perform allgather among other daemons
		 * (if any)
		 */
		do_allgather(allgather_super_request);
	} else {
		/** Not all clients sent their vectors to the daemon */
	}
}

/** AM receive callback which is invoked when the daemon receives notification from some client */
int daemon_am_recv_ctrl_callback(struct ucx_am_desc *am_desc)
{
	struct ucx_connection *connection;
	const struct ucx_allgather_header *allgather_header;
	struct ucx_allgather_request *allgather_request;
	size_t header_length, length;

	ucx_am_desc_query(am_desc, &connection, (const void **)&allgather_header, &header_length, &length);

	assert(sizeof(*allgather_header) == header_length);

	allgather_request = allgather_request_allocate(connection, allgather_header, 0, NULL, length);
	if (allgather_request == NULL)
		goto err;

	/** Continue receiving data to the allocated vector */
	ucx_am_recv(am_desc, allgather_request->vector, length, NULL, daemon_am_recv_data_complete_callback,
			allgather_request, NULL);

	return 1;

err:
	return -1;
}
static inline double get_time(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return tv.tv_sec + (tv.tv_usec * 1e-6);
}
static void daemon_am_recv_xgvmi_data_complete_callback(void *arg, ucs_status_t status)
{
	struct ucx_allgather_request *allgather_request = arg;
	struct ucx_allgather_super_request *allgather_super_request;
	size_t i;
	struct ucx_allgather_xgvmi_buffer *xgvmi_buffer;
	struct ucx_allgather_xgvmi_key *xgvmi_key;
	uint8_t *p;
	struct ucx_am_desc *am_desc, *tmp_am_desc;
	struct ucx_allgather_header *allgather_header;
	double start_time, end_time;

	assert(status == UCS_OK);

	allgather_super_request = allgather_super_request_get(&allgather_request->header, allgather_request->vector_size,
								NULL);
	if (allgather_super_request == NULL) {
		allgather_request_destroy(allgather_request);
		return;
	}

	if (ucx_app_config.allgather_mode == UCX_ALLGATHER_OFFLOADED_XGVMI_MODE) {
		allgather_super_request->result_vector_size = ucx_app_config.vector_size;
	}

	/** Parse XGVMI keys */
	start_time = get_time();

	xgvmi_buffer = allgather_request->vector;
	p = (uint8_t*)xgvmi_buffer;
	assert(xgvmi_buffer->num_keys == ucx_app_config.num_clients);
	p += sizeof(*xgvmi_buffer);
	for (i = 0; i < xgvmi_buffer->num_keys; ++i) {
		xgvmi_key = (struct ucx_allgather_xgvmi_key*)p;
		allgather_request->xgvmi_memhs[i] = malloc(sizeof(*allgather_request->xgvmi_memhs[i]));
		if (allgather_request->xgvmi_memhs[i] == NULL) {
			DOCA_LOG_ERR("failed to allocate memory");
			continue;
		}

		DOCA_LOG_DBG("%zu: unpack length - %zu, addr - %p", i, xgvmi_key->length,
						(void*)xgvmi_key->address);

		allgather_request->xgvmi_memhs[i]->done = 0;
		allgather_request->xgvmi_memhs[i]->address = xgvmi_key->address;
		allgather_request->xgvmi_memhs[i]->memh =
				ucx_mem_map(context, (void*)(uintptr_t)allgather_request->xgvmi_memhs[i]->address,
							allgather_request->header.vector_size *
							allgather_datatype_size[ucx_app_config.datatype], xgvmi_key->rkey_buffer, UINT32_MAX, 0);
		p += sizeof(*xgvmi_key) + xgvmi_key->length;
	}

	end_time = get_time();

	DOCA_LOG_INFO("total xgvmi import time (%zd clients): %.0f usec",
	              xgvmi_buffer->num_keys, (end_time - start_time) * 1e6);

	/** Attach the received allgather request to the allgather super request for futher processing */
	allgather_request->allgather_super_request = allgather_super_request;
	++allgather_super_request->num_allgather_requests;
	DOCA_LOG_DBG("num_allgather_requests=%zu num_daemon_bound_clients=%zu",
	              allgather_super_request->num_allgather_requests,
				  ucx_app_config.num_daemon_bound_clients);
	allgather_vector_received(&allgather_request->header, allgather_super_request, allgather_request->vector);
	allgather_request->vector = NULL;
	STAILQ_INSERT_TAIL(&allgather_super_request->allgather_requests_list, allgather_request, entry);

	/** The whole result will be sent to the other daemons when all vectors are received from clinets */

	/*free(allgather_request->vector);
	allgather_request->vector = NULL;*/

	STAILQ_FOREACH_SAFE(am_desc, &allgather_super_request->am_desc_list, entry, tmp_am_desc) {
		allgather_header = (struct ucx_allgather_header*)am_desc->header;
		if (allgather_request->xgvmi_memhs[allgather_header->sender_client_id]->done) {
			DOCA_LOG_DBG("client id %zu: already receuved", allgather_header->sender_client_id);
			continue;
		}

		DOCA_LOG_DBG("found %zu: recv: header_length %zu length %zu - to addr=%p",
						allgather_header->sender_client_id, am_desc->header_length, am_desc->length,
						(void*)allgather_request->xgvmi_memhs[allgather_header->sender_client_id]->address);
		ucx_am_recv(am_desc, (void*)allgather_request->xgvmi_memhs[allgather_header->sender_client_id]->address,
					am_desc->length, allgather_request->xgvmi_memhs[allgather_header->sender_client_id]->memh,
					allgather_recv_complete_callback, allgather_super_request, NULL);
		allgather_request->xgvmi_memhs[allgather_header->sender_client_id]->done = 1;

		STAILQ_REMOVE(&allgather_super_request->am_desc_list, am_desc, ucx_am_desc, entry);
	}

	if (allgather_super_request->num_allgather_requests == ucx_app_config.num_daemon_bound_clients) {
		/*
		 * Daemons received the allgather vectors from all clients - perform allgather among other daemons
		 * (if any)
		 */
		do_allgather(allgather_super_request);
	} else {
		/** Not all clients sent their vectors to the daemon */
		assert(allgather_super_request->num_allgather_requests < ucx_app_config.num_daemon_bound_clients);
	}
}

int daemon_am_recv_ctrl_xgvmi_callback(struct ucx_am_desc *am_desc)
{
	struct ucx_connection *connection;
	const struct ucx_allgather_header *allgather_header;
	struct ucx_allgather_request *allgather_request;
	size_t header_length, length;

	ucx_am_desc_query(am_desc, &connection, (const void **)&allgather_header, &header_length, &length);

	assert(sizeof(*allgather_header) == header_length);

	allgather_request = allgather_request_allocate(connection, allgather_header, 0, NULL, length);
	if (allgather_request == NULL)
		goto err;

	/** Continue receiving data to the allocated vector */
	ucx_am_recv(am_desc, allgather_request->vector, length, NULL, daemon_am_recv_xgvmi_data_complete_callback,
			allgather_request, NULL);

	return 1;

err:
	return -1;
}

static void signal_terminate_handler(int signo)
{
	running = 0;
}

static void signal_terminate_set(void)
{
	struct sigaction new_sigaction = {
		.sa_handler = signal_terminate_handler,
		.sa_flags = 0
	};

	sigemptyset(&new_sigaction.sa_mask);

	if (sigaction(SIGINT, &new_sigaction, NULL) != 0) {
		DOCA_LOG_ERR("failed to set SIGINT signal handler: %s", strerror(errno));
		abort();
	}
}

void daemon_run(void)
{
	int num_connections;

	if (ucx_app_config.num_daemon_bound_clients == 0) {
		/** Nothing to do */
		DOCA_LOG_DBG("stop running - daemon doesn't have clients");
		return;
	}

	signal_terminate_set();

	/** Setup receive handler for AM control messages from client which carries a vector to do allgather for */
	ucx_am_set_recv_handler(context, UCX_ALLGATHER_CTRL_AM_ID, daemon_am_recv_ctrl_callback);
	ucx_am_set_recv_handler(context, UCX_ALLGATHER_CTRL_XGVMI_AM_ID, daemon_am_recv_ctrl_xgvmi_callback);

	/** Initialize needed stuff for the daemon */
	num_connections = process_init();
	if (num_connections < 0)
		return;

	while (running) {
		/** Progress UCX to handle client's allgather requests until signanl isn't received */
		ucx_progress(context);
	}

	/** Signal received - Cleanup previously allocated stuff for the daemon */
	process_cleanup(num_connections);
}
