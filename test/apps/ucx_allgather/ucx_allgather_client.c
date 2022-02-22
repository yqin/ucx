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

#include "ucx_allgather_client.h"

struct ucx_allgather_metrics {
	double min; /*< Minimum time of doing allgather batch, in seconds */
	double max; /*< Maximum time of doing allgather batch, in seconds */
	double avg; /*< Average time of doing allgather batch, in seconds */
	double total; /*< Total time of doing all allgather batches, in seconds */
	size_t current_batch_iter; /*< Current batch iteration number */
	const char *mode_str; /*< Pointer to the string of allgather mode */
	const char *datatype_str; /*< Pointer to the string of allgather datatype */
	const char *operation_str; /*< Pointer to the string of allgather operation */
	size_t batch_size; /*< allgather operations in a single batch */
	size_t vector_size; /*< allgather vector size */
	int compute_repeats; /*< Indicates how many compute repetitions should be done to make "computation time" equal to "pure network time" */
	double compute_time; /*< Pure computation time*/
	double network_time; /*< Pure network time */
	double overlap; /*< Percentage of overlap between computation and network operations */
};

static void **allgather_vectors; /*< Array of allgather vectors */
static struct ucx_memh **allgather_memhs; /*< Array of allgather memory handles */
static void **allgather_rkey_buffers; /*< Array of allgather rkey buffers */
static size_t allgather_rkey_buffer_length = 0;
static size_t allgather_next_id; /*< Next allgather ID which could be allocated by clients */

DOCA_LOG_REGISTER(UCX_allgather::Cleint);


static void allgather_vectors_cleanup(size_t num_allgather_vectors)
{
	size_t vector_iter;

	/** Go through all vectors and free the memory allocated to hold them */
	for (vector_iter = 0; vector_iter < num_allgather_vectors; ++vector_iter) {
		ucx_mem_unmap(context, allgather_memhs[vector_iter]);
		//free(allgather_vectors[vector_iter]);
	}

	free(allgather_vectors);
}

static void allgather_vectors_reset(void)
{
	size_t vector_iter, i;

	/** Go through all vectors, fill them by initial data */
	for (vector_iter = 0; vector_iter < ucx_app_config.batch_size; ++vector_iter) {
		for (i = 0; i < ucx_app_config.vector_size; ++i) {
			/** Initialize vectors by initial values */
			switch (ucx_app_config.datatype) {
			case UCX_ALLGATHER_BYTE:
				((uint8_t *)allgather_vectors[vector_iter])[i] = i % UINT8_MAX;
				break;
			case UCX_ALLGATHER_INT:
				((int *)allgather_vectors[vector_iter])[i] = i % INT_MAX;
				break;
			case UCX_ALLGATHER_FLOAT:
				((float *)allgather_vectors[vector_iter])[i] = (float)i;
				break;
			case UCX_ALLGATHER_DOUBLE:
				((double *)allgather_vectors[vector_iter])[i] = (double)i;
				break;
			}
		}
	}
}

static int allgather_vectors_init(void)
{
	size_t vector_size = ucx_app_config.vector_size * allgather_datatype_size[ucx_app_config.datatype];
	size_t vector_iter, num_allgather_vectors = 0;
	size_t rkey_buffer_length;

	allgather_vectors = malloc(ucx_app_config.batch_size * sizeof(*allgather_vectors));
	if (allgather_vectors == NULL) {
		DOCA_LOG_ERR("failed to allocate memory to hold array of allgather vectors");
		goto err;
	}

	allgather_memhs = malloc(ucx_app_config.batch_size * sizeof(*allgather_memhs));
	if (allgather_memhs == NULL) {
		DOCA_LOG_ERR("failed to allocate memory to hold array of allgather memhs");
		goto err;
	}

	allgather_rkey_buffers = malloc(ucx_app_config.batch_size * sizeof(*allgather_rkey_buffers));
	if (allgather_rkey_buffers == NULL) {
		DOCA_LOG_ERR("failed to allocate memory to hold array of allgather rkey buffers");
		goto err;
	}

	/** Go through all vectors, allocate them */
	for (vector_iter = 0; vector_iter < ucx_app_config.batch_size; ++vector_iter) {
		allgather_memhs[vector_iter] = ucx_mem_map(
				context, NULL, vector_size, NULL, 3,
				ucx_app_config.allgather_mode == UCX_ALLGATHER_OFFLOADED_XGVMI_MODE);
		if (allgather_memhs[vector_iter] == NULL)
			goto err_allgather_vectors_cleanup;

		allgather_vectors[vector_iter] = allgather_memhs[vector_iter]->address;
		assert(allgather_vectors[vector_iter] != NULL);

		if (ucx_app_config.allgather_mode == UCX_ALLGATHER_OFFLOADED_XGVMI_MODE) {
			allgather_rkey_buffers[vector_iter] = ucx_rkey_pack(context, allgather_memhs[vector_iter], &rkey_buffer_length);
			assert(allgather_rkey_buffers[vector_iter] != NULL);
			assert(rkey_buffer_length != 0);
			if (allgather_rkey_buffer_length == 0) {
				allgather_rkey_buffer_length = rkey_buffer_length;
			} else {
				assert(allgather_rkey_buffer_length == rkey_buffer_length);
			}
		}

		++num_allgather_vectors;
	}

	return 0;

err_allgather_vectors_cleanup:
	allgather_vectors_cleanup(num_allgather_vectors);
err:
	return -1;
}

/** Allocate vector for send operation and move iterator to the next one which will be allocated next time */
static inline void *preallocated_vector_get(struct ucx_memh **mem_handle, void **rkey_buffer)
{
	static size_t allgather_vector_iter;
	void *vector = allgather_vectors[allgather_vector_iter];

	if (mem_handle != NULL)
		*mem_handle = allgather_memhs[allgather_vector_iter];

	if (rkey_buffer != NULL)
		*rkey_buffer = allgather_rkey_buffers[allgather_vector_iter];

	allgather_vector_iter = (allgather_vector_iter + 1) % ucx_app_config.batch_size;
	return vector;
}

/** Client callback to complete AM send operation for receiving the allgather result from the daemon */
static void client_am_recv_data_complete_callback(void *arg, ucs_status_t status)
{
	struct ucx_allgather_super_request *allgather_super_request = arg;

	assert(status == UCS_OK);

	g_hash_table_remove(allgather_super_requests_hash, &allgather_super_request->header.id);
}

/** AM receive callback which is invoked when the client gets completion of the whole allgather operation from daemon */
int client_am_recv_ctrl_callback(struct ucx_am_desc *am_desc)
{
	struct ucx_connection *connection;
	const struct ucx_allgather_header *allgather_header;
	struct ucx_allgather_super_request *allgather_super_request;
	size_t header_length, length;

	ucx_am_desc_query(am_desc, &connection, (const void **)&allgather_header, &header_length, &length);

	assert(sizeof(*allgather_header) == header_length);

	allgather_super_request = g_hash_table_lookup(allgather_super_requests_hash, &allgather_header->id);
	if (allgather_super_request == NULL) {
		DOCA_LOG_ERR("failed to find allgather request with id=%zu in hash", allgather_header->id);
		return -1;
	}

	/** Continue receiving data to the allocated vector */
	ucx_am_recv(am_desc, allgather_super_request->result_vector, length, NULL, client_am_recv_data_complete_callback,
			allgather_super_request, NULL);

	return 1;
}

/** Set default values to the fields of the allgather metrics */
static void allgather_metrics_reset(struct ucx_allgather_metrics *allgather_metrics)
{
	allgather_metrics->min = DBL_MAX;
	allgather_metrics->max = 0.;
	allgather_metrics->total = 0.;
	allgather_metrics->avg = 0.;
	allgather_metrics->current_batch_iter = 0;
	allgather_metrics->mode_str = allgather_mode_str[ucx_app_config.allgather_mode];
	allgather_metrics->datatype_str = allgather_datatype_str[ucx_app_config.datatype];
	allgather_metrics->batch_size = ucx_app_config.batch_size;
	allgather_metrics->vector_size = ucx_app_config.vector_size;
	allgather_metrics->compute_repeats = 0;
	allgather_metrics->compute_time = -1.;
	allgather_metrics->network_time = -1.;
	allgather_metrics->overlap = -1.;
}

/** Calculate allgather metrics after allgather batch successfully done */
static void
allgather_metrics_calculate(double run_time, double compute_time,
				struct ucx_allgather_metrics *allgather_metrics)
{
	double overlapped_time, max_possible_overlapped_time;

	/** Minimum run time */
	if (run_time < allgather_metrics->min)
		allgather_metrics->min = run_time;

	/** Maximum run time */
	if (run_time > allgather_metrics->max)
		allgather_metrics->max = run_time;

	/** Total run time */
	allgather_metrics->total += run_time;

	/** Average run time */
	allgather_metrics->avg = allgather_metrics->total / (allgather_metrics->current_batch_iter + 1);

	/*
	 * Overlapped time is a difference between "pure network time" + "current compute time" and
	 * "current average run time"
	 */
	overlapped_time = allgather_metrics->network_time + compute_time - allgather_metrics->avg;

	/* Maximum possible overlapped time is a maximum between "pure network time" and "current compute time" */
	max_possible_overlapped_time = MAX(allgather_metrics->network_time, compute_time);

	/*
	 * Percentage of computation/communication overlap calculated as:
	 * overlap = 100% * (overlapped_time / max_possible_overlapped_time), where
	 * (overlapped_time / max_possible_overlapped_time) should be in [0..1] range
	 */
	allgather_metrics->overlap = 100. * MAX(0., MIN(1., overlapped_time / max_possible_overlapped_time));
}

static inline double get_time(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return tv.tv_sec + (tv.tv_usec * 1e-6);
}

static void matrix_multiplication(float **a, float *x, float *y, int size, int target_reps)
{
	int repeat, i, j;

	/** Do 'target_reps' iterations of matrix multiplication */
	for (repeat = 0; repeat < target_reps; repeat++) {
		/** Matrix multiplication */
		for (i = 0; i < size; ++i) {
			for (j = 0; j < size; ++j)
				x[i] += a[i][j] * y[j];
		}
	}
}

/** Calculate pure compute time */
static double matrix_multiplication_avg_compute_time(float **a, float *x, float *y, int size, int num_reps)
{
	static const int discover_time_repeats = 10;
	double start_time, end_time;
	int repeat;

	/** Do 'discover_time_repeats' iterations of matrix multiplication */
	start_time = get_time();
	for (repeat = 0; repeat < discover_time_repeats; ++repeat)
		matrix_multiplication(a, x, y, size, num_reps);

	end_time = get_time();

	/** Calculate average compute time */
	return (end_time - start_time) / discover_time_repeats;
}

static void cpu_exploit(struct ucx_allgather_metrics *allgather_metrics)
{
	/*
	 * Small matrix is used because the network time is could be small and we want to have a computation time close to
	 * the network time
	 */
	static const int size = 10;
	float **a, *x, *y;
	double start_time, end_time, estimated_overall_time;
	int num_reps;
	int i, j;

	assert(allgather_metrics->network_time >= 0.);

	if (allgather_metrics->network_time == 0.)
		return;

	/** Allocate memory for matrices */
	a = alloca(size * sizeof(*a));
	for (i = 0; i < size; ++i)
		a[i] = alloca(size * sizeof(**a));

	x = alloca(size * sizeof(*x));
	y = alloca(size * sizeof(*y));

	/** allgather metrics weren't initialized for computation */
	/** Initialize matrices */
	for (i = 0; i < size; ++i) {
		x[i] = 0.;
		y[i] = (float)i;
		for (j = 0; j < size; ++j)
			a[i][j] = (float)(i + j);
	}

	if (allgather_metrics->compute_time < 0.) {
		/** Set some initial number of repetitions of matrix multiplications */
		num_reps = (50000000 / (2 * size * size)) + 1;
		/** Calculate average computation time of doing 'num_reps' repetitions */
		estimated_overall_time = matrix_multiplication_avg_compute_time(a, x, y, size, num_reps);

		/** Calculate repetitions of computations to be approximately equal to 'network_time' */
		allgather_metrics->compute_repeats = MAX(1, (int)((num_reps * allgather_metrics->network_time) /
									estimated_overall_time));

		/** Calculate computation time took by calculated 'compute_repeats' iterations of matrix multiplications */
		start_time = get_time();
		matrix_multiplication(a, x, y, size, allgather_metrics->compute_repeats);
		end_time = get_time();
		allgather_metrics->compute_time = end_time - start_time;
	} else {
		/** Do matrix multiplication */
		matrix_multiplication(a, x, y, size, allgather_metrics->compute_repeats);
	}
}

static void allgather_metrics_iteration_print(double run_time, double compute_time,
						struct ucx_allgather_metrics *allgather_metrics)
{
	DOCA_LOG_INFO("%zu: current run time - %.3f seconds, compute - %.3f seconds, min - %.3f seconds, max - %.3f seconds, avg - %.3f seconds\n",
		allgather_metrics->current_batch_iter, run_time, compute_time, allgather_metrics->min, allgather_metrics->max,
		allgather_metrics->avg);
}

static void
allgather_metrics_print(struct ucx_allgather_metrics *allgather_metrics)
{
	DOCA_LOG_INFO("allgather (%s/%s) and matrix multiplication metrics to complete %zu batches (batch size - %zu, vector size - %zu):\n",
			allgather_metrics->mode_str, allgather_metrics->datatype_str,
			allgather_metrics->current_batch_iter, allgather_metrics->batch_size, allgather_metrics->vector_size);
	DOCA_LOG_INFO("min - %.3f seconds\n", allgather_metrics->min);
	DOCA_LOG_INFO("max - %.3f seconds\n", allgather_metrics->max);
	DOCA_LOG_INFO("avg - %.3f seconds\n", allgather_metrics->avg);
	DOCA_LOG_INFO("total - %.3f seconds\n", allgather_metrics->total);
	DOCA_LOG_INFO("computation time - %.3f seconds\n", allgather_metrics->compute_time);
	DOCA_LOG_INFO("pure network time - %.3f seconds\n", allgather_metrics->network_time);
	DOCA_LOG_INFO("computation and communication overlap - %.2f%%\n", allgather_metrics->overlap);
}

static void allgather_offloaded_complete_ctrl_send_callback(void *arg, ucs_status_t status)
{
	assert(status == UCS_OK);
}

static void allgather_offloaded_complete_ctrl_xgvmi_send_callback(void *arg, ucs_status_t status)
{
	struct ucx_allgather_super_request *allgather_super_request = arg;

	assert(status == UCS_OK);

	free(allgather_super_request->xgvmi_rkeys_buffer);
}

static size_t allgather_xgvmi_offloaded_batch_submit(size_t vector_size, size_t batch_size)
{
	struct ucx_connection *connection = connections[0];
	struct ucx_allgather_header allgather_header;
	struct ucx_allgather_super_request *allgather_super_request;
	size_t op_iter;
	struct ucx_memh *mem_handle;
	void *rkey_buffer;

	assert(vector_size <= ucx_app_config.vector_size);

	/** Go over all required allgather requests */
	for (op_iter = 0; op_iter < batch_size; ++op_iter) {
		allgather_header.id = allgather_next_id++;

		allgather_super_request = allgather_super_request_get(&allgather_header, vector_size,
									preallocated_vector_get(&mem_handle, &rkey_buffer));
		if (allgather_super_request == NULL)
			continue;

		/** Send allgather control Active Message with allgather data to the daemon for futher processing */
		ucx_am_send(connection, UCX_ALLGATHER_CTRL_XGVMI_AM_ID, &allgather_super_request->header,
				sizeof(allgather_super_request->header), allgather_super_request->xgvmi_rkeys_buffer,
				allgather_super_request->xgvmi_rkeys_buffer_length, NULL,
				allgather_offloaded_complete_ctrl_xgvmi_send_callback, allgather_super_request, NULL);
	}

	return op_iter;
}

/** Submit a batch of offloaded allgather operations */
static size_t allgather_offloaded_batch_submit(size_t vector_size, size_t batch_size)
{
	struct ucx_connection *connection = connections[0];
	struct ucx_allgather_header allgather_header;
	struct ucx_allgather_super_request *allgather_super_request;
	size_t op_iter;

	assert(vector_size <= ucx_app_config.vector_size);

	/** Go over all required allgather requests */
	for (op_iter = 0; op_iter < batch_size; ++op_iter) {
		allgather_header.id = allgather_next_id++;

		allgather_super_request = allgather_super_request_get(&allgather_header, vector_size,
									preallocated_vector_get(NULL, NULL));
		if (allgather_super_request == NULL)
			continue;

		/** Send allgather control Active Message with allgather data to the daemon for futher processing */
		ucx_am_send(connection, UCX_ALLGATHER_CTRL_AM_ID, &allgather_super_request->header,
				sizeof(allgather_super_request->header), allgather_super_request->result_vector,
				vector_size * allgather_datatype_size[ucx_app_config.datatype], NULL,
				allgather_offloaded_complete_ctrl_send_callback, NULL, NULL);
	}

	return op_iter;
}

/** Submit a batch of non-offloaded allgather operations */
static size_t allgather_non_offloaded_batch_submit(size_t vector_size, size_t batch_size)
{
	struct ucx_allgather_super_request *allgather_super_request;
	struct ucx_allgather_header allgather_header;
	size_t op_iter;

	assert(vector_size <= ucx_app_config.vector_size);

	/** Go over all required allgather requests */
	for (op_iter = 0; op_iter < batch_size; ++op_iter) {
		allgather_header.id = allgather_next_id++;
		allgather_header.sender_client_id = ucx_app_config.client_id;

		allgather_super_request = allgather_super_request_get(&allgather_header, vector_size,
															preallocated_vector_get(NULL, NULL));
		if (allgather_super_request == NULL)
			continue;

		/** Do allgather operation among other clients */
		do_allgather(allgather_super_request);
	}

	return op_iter;
}

static void allgather_batch_wait(void)
{
	/** Wait for completions of all submitted allgather operations */
	while (g_hash_table_size(allgather_super_requests_hash) > 0)
		ucx_progress(context);
}

typedef size_t (*allgather_batch_submit_func)(size_t vector_size, size_t batch_size);

static void allgather_barrier(allgather_batch_submit_func batch_submit_func)
{
	/** Do 0-byte allgather operation to make sure all clients and daemons are up and running */
	batch_submit_func(1, 1);
	allgather_batch_wait();
}

static void
allgather_metrics_init(struct ucx_allgather_metrics *allgather_metrics, allgather_batch_submit_func batch_submit_func)
{
	static const int discover_time_repeats = 3;
	double start_time, end_time;
	int repeat;

	allgather_metrics_reset(allgather_metrics);

	allgather_metrics->network_time = 0;

	/** Calculate a pure network time consumed by a single batch of allgather operations */
	for (repeat = 0; repeat < discover_time_repeats; ++repeat) {
		/** Reset vectors by initial data prior submitting allgather */
		allgather_vectors_reset();

		start_time = get_time();
		batch_submit_func(ucx_app_config.vector_size, ucx_app_config.batch_size);
		allgather_batch_wait();
		end_time = get_time();
		allgather_metrics->network_time += (end_time - start_time);
	}

	/** Calculate average pure network time */
	allgather_metrics->network_time /= discover_time_repeats;

	/** Calculate average pure computation time */
	cpu_exploit(allgather_metrics);
}

static void allgather(allgather_batch_submit_func batch_submit_func)
{
	struct ucx_allgather_metrics allgather_metrics;
	size_t batch_size = ucx_app_config.batch_size;
	double start_time, end_time, run_time;
	double compute_start_time, compute_end_time, compute_time;

	/** Post a barrier to make sure all clients and daemons are up and running prior benchmarking to avoid imbalance */
	allgather_barrier(batch_submit_func);

	allgather_metrics_init(&allgather_metrics, batch_submit_func);

	/** Do benchmarking of allgather */
	for (allgather_metrics.current_batch_iter = 0; allgather_metrics.current_batch_iter < ucx_app_config.num_batches;
			++allgather_metrics.current_batch_iter) {
		/** Reset vectors by initial data prior submitting allgather */
		allgather_vectors_reset();

		/** Calculate time of run time for performing batch of allgather operations and computation */
		start_time = get_time();
		batch_submit_func(ucx_app_config.vector_size, batch_size);

		compute_start_time = get_time();
		cpu_exploit(&allgather_metrics);
		compute_end_time = get_time();
		compute_time = compute_end_time - compute_start_time;
		allgather_batch_wait();

		end_time = get_time();
		run_time = end_time - start_time;

		/** Calculate allgather metrics and print metrics of the current iteration */
		allgather_metrics_calculate(run_time, compute_time, &allgather_metrics);
		allgather_metrics_iteration_print(run_time, compute_time, &allgather_metrics);

		allgather_barrier(batch_submit_func);
	}

	/** Print summary of allgather benchmarking */
	allgather_metrics_print(&allgather_metrics);
}

void client_run(void)
{
	int ret, num_connections;

	/** Allocate and fill vectors which contain data to do allgather for */
	ret = allgather_vectors_init();
	if (ret < 0)
		return;

	/** Setup receive handler for AM control messages from daemon which carry the allgather result */
	ucx_am_set_recv_handler(context, UCX_ALLGATHER_CTRL_AM_ID, client_am_recv_ctrl_callback);

	/** Initialize needed stuff for the client */
	num_connections = process_init();
	if (num_connections <= 0)
		goto out_allgather_vectors_cleanup;

	/** Perform allgather operations */
	switch (ucx_app_config.allgather_mode) {
	case UCX_ALLGATHER_OFFLOADED_MODE:
		allgather(allgather_offloaded_batch_submit);
		break;
	case UCX_ALLGATHER_NON_OFFLOADED_MODE:
		allgather(allgather_non_offloaded_batch_submit);
		break;
	case UCX_ALLGATHER_OFFLOADED_XGVMI_MODE:
		allgather(allgather_xgvmi_offloaded_batch_submit);
		break;
	default:
		DOCA_LOG_ERR("unsupported allgather mode: %d", ucx_app_config.allgather_mode);
	}

	/** Cleanup previously allocated stuff for the client */
	process_cleanup(num_connections);

out_allgather_vectors_cleanup:
	/** Destroy allgather vectors */
	allgather_vectors_cleanup(ucx_app_config.batch_size);
}
