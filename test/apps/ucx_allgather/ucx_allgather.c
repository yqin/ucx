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

#include <assert.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>
#include <float.h>
#include <getopt.h>

#include "ucx_core.h"
#include "ucx_allgather_common.h"
#include "ucx_allgather_daemon.h"
#include "ucx_allgather_client.h"

DOCA_LOG_REGISTER(UCX_ALLGATHER);

/*< Names of allgather process modes */
const char * const allgather_role_str[] = {
	[UCX_ALLGATHER_CLIENT] = "client", /*< Name of client allgather role */
	[UCX_ALLGATHER_DAEMON] = "daemon" /*< Name of daemon allgather role */
};
/*< Names of allgather algorithms */
const char * const allgather_mode_str[] = {
	[UCX_ALLGATHER_NON_OFFLOADED_MODE] = "non-offloaded", /*< Name of non-offloaded allgather algorithm */
	[UCX_ALLGATHER_OFFLOADED_MODE] = "offloaded", /*< Name of offloaded allgather algorithm */
	[UCX_ALLGATHER_OFFLOADED_XGVMI_MODE] = "offloaded-xgvmi" /*< Name of offloaded allgather algorithm */
};
const char * const allgather_datatype_str[] = {
	[UCX_ALLGATHER_BYTE] = "byte", /*< Name of "byte" datatype */
	[UCX_ALLGATHER_INT] = "int", /*< Name of "int" datatype */
	[UCX_ALLGATHER_FLOAT] = "float", /*< Name of "float" datatype */
	[UCX_ALLGATHER_DOUBLE] = "double" /*< Name of "double" datatype */
};
const size_t allgather_datatype_size[] = {
	[UCX_ALLGATHER_BYTE] = sizeof(uint8_t), /*< Size of "byte" datatype */
	[UCX_ALLGATHER_INT] = sizeof(int), /*< Size of "int" datatype */
	[UCX_ALLGATHER_FLOAT] = sizeof(float), /*< Size of "float" datatype */
	[UCX_ALLGATHER_DOUBLE] = sizeof(double) /*< Size of "double" datatype */
};
struct ucx_allgather_config ucx_app_config = {0}; /*< UCX allgather configuration */
struct ucx_context *context; /*< UCX context */
struct ucx_connection **connections; /*< Array of UCX connections */
GHashTable *allgather_super_requests_hash; /*< Hash which contains "ID -> allgather super request" elements */

static void set_role_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;
	const char *str = (const char *) param;

	if (strcmp(str, allgather_role_str[UCX_ALLGATHER_CLIENT]) == 0)
		app_config->role = UCX_ALLGATHER_CLIENT;
	else if (strcmp(str, allgather_role_str[UCX_ALLGATHER_DAEMON]) == 0)
		app_config->role = UCX_ALLGATHER_DAEMON;
	else
		APP_EXIT("unknow role '%s' was specified", str);
}

static void set_dest_ip_str_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;

	app_config->dest_addresses.str = (char *) param;
}

static void set_dest_port_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;

	app_config->dest_port = (uint16_t)atoi((const char *) param);
}

static void set_listen_port_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;

	app_config->listen_port = (uint16_t)atoi((const char *) param);
}

static void set_num_clients_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;

	app_config->num_clients = (size_t)atoi((const char *) param);
}

static void set_num_daemon_bound_clients_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;

	app_config->num_daemon_bound_clients = (size_t)atoi((const char *) param);
}

static void set_client_id_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;

	app_config->client_id = (size_t)atoi((const char *) param);
	//fprintf(stderr, "MY client ID: %zu\n", app_config->client_id);
}

static void set_size_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;

	app_config->vector_size = (size_t)atoi((const char *) param);
}

static void set_datatype_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;
	const char *str = (const char *) param;

	if (strcmp(str, allgather_datatype_str[UCX_ALLGATHER_BYTE]) == 0)
		app_config->datatype = UCX_ALLGATHER_BYTE;
	else if (strcmp(str, allgather_datatype_str[UCX_ALLGATHER_INT]) == 0)
		app_config->datatype = UCX_ALLGATHER_INT;
	else if (strcmp(str, allgather_datatype_str[UCX_ALLGATHER_FLOAT]) == 0)
		app_config->datatype = UCX_ALLGATHER_FLOAT;
	else if (strcmp(str, allgather_datatype_str[UCX_ALLGATHER_DOUBLE]) == 0)
		app_config->datatype = UCX_ALLGATHER_DOUBLE;
	else
		APP_EXIT("unknow datatype '%s' was specified", str);
}

static void set_batch_size_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;

	app_config->batch_size = (size_t)atoi((const char *) param);
}

static void set_num_batches_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;

	app_config->num_batches = (size_t)atoi((const char *) param);
}

static void set_allgather_mode_param(void *config, void *param)
{
	struct ucx_allgather_config *app_config = (struct ucx_allgather_config *) config;
	const char *str = (const char *) param;

	if (strcmp(str, allgather_mode_str[UCX_ALLGATHER_OFFLOADED_XGVMI_MODE]) == 0)
		app_config->allgather_mode = UCX_ALLGATHER_OFFLOADED_XGVMI_MODE;
	else if (strcmp(str, allgather_mode_str[UCX_ALLGATHER_OFFLOADED_MODE]) == 0)
		app_config->allgather_mode = UCX_ALLGATHER_OFFLOADED_MODE;
	else if (strcmp(str, allgather_mode_str[UCX_ALLGATHER_NON_OFFLOADED_MODE]) == 0)
		app_config->allgather_mode = UCX_ALLGATHER_NON_OFFLOADED_MODE;
	else
		APP_EXIT("unknow mode '%s' was specified", str);
}

int doca_print_enable = 0;
static void set_default_config_params(void)
{
	if (getenv("DOCA_PRINT") != NULL) {
		doca_print_enable = 1;
	}
	ucx_app_config.vector_size = 65535;
	ucx_app_config.datatype = UCX_ALLGATHER_FLOAT;
	ucx_app_config.role = UCX_ALLGATHER_CLIENT;
	ucx_app_config.allgather_mode = UCX_ALLGATHER_OFFLOADED_MODE;
	ucx_app_config.dest_addresses.str = NULL;
	ucx_app_config.dest_addresses.num = 0;
	ucx_app_config.dest_port = 0;
	ucx_app_config.listen_port = 0;
	ucx_app_config.num_clients = 0;
	ucx_app_config.num_daemon_bound_clients = 0;
	ucx_app_config.client_id = 0;
	ucx_app_config.batch_size = 64;
	ucx_app_config.num_batches = 10;
}

static void dest_address_cleanup(void)
{
	struct ucx_allgather_address *address, *tmp_addess;

	/** Go through all addresses saved in the configuration and free the memory allocated to hold them */
	STAILQ_FOREACH_SAFE(address, &ucx_app_config.dest_addresses.list, entry, tmp_addess) {
		free(address);
	}
}

static int dest_addresses_init(void)
{
	char *dest_addresses_str = ucx_app_config.dest_addresses.str;
	const char *port_separator;
	char *str;
	size_t ip_addr_length;
	struct ucx_allgather_address *address;

	ucx_app_config.dest_addresses.str = NULL;
	ucx_app_config.dest_addresses.num = 0;
	STAILQ_INIT(&ucx_app_config.dest_addresses.list);

	/** Go over comma-separated list of <IP-address>:[<port>] elements */
	str = strtok(dest_addresses_str, ",");
	while (str != NULL) {
		address = malloc(sizeof(*address));
		if (address == NULL) {
			DOCA_LOG_ERR("failed to allocate memory to hold address");
			goto err;
		}

		/** Parse an element of comma-separated list and insert to the list of peer's addresses */
		port_separator = strchr(str, ':');
		if (port_separator == NULL) {
			/** Port wasn't specified - take port number from -p argument */
			address->port = ucx_app_config.dest_port;
			strncpy(address->ip_address_str, str, sizeof(address->ip_address_str) - 1);
			address->ip_address_str[sizeof(address->ip_address_str) - 1] = '\0';
		} else {
			/** Port was specified - take port number from the string of the address */
			address->port = atoi(port_separator + 1);
			ip_addr_length = port_separator - str;
			memcpy(address->ip_address_str, str, ip_addr_length);
			address->ip_address_str[ip_addr_length] = '\0';
		}

		++ucx_app_config.dest_addresses.num;
		STAILQ_INSERT_TAIL(&ucx_app_config.dest_addresses.list, address, entry);

		str = strtok(NULL, ",");
	}

	return 0;

err:
	dest_address_cleanup();
	return -1;
}

static int parse_args(int argc, char **argv, struct ucx_allgather_config *config)
{
    char *str;
    int c;

	 while ((c = getopt(argc, argv,
                       "r:p:t:c:e:n:s:d:b:i:m:a:")) != -1) {
        switch (c) {
        case 'r':
            set_role_param(config, optarg);
            break;
		case 'p':
            set_dest_port_param(config, optarg);
            break;
		case 't':
            set_listen_port_param(config, optarg);
            break;
		case 'c':
			set_num_clients_param(config, optarg);
			break;
		case 'e':
			set_num_daemon_bound_clients_param(config, optarg);
			break;
		case 'n':
			set_client_id_param(config, optarg);
			break;
		case 's':
			set_size_param(config, optarg);
			break;
		case 'd':
			set_datatype_param(config, optarg);
			break;
		case 'b':
			set_batch_size_param(config, optarg);
			break;
		case 'i':
			set_num_batches_param(config, optarg);
			break;
		case 'm':
			set_allgather_mode_param(config, optarg);
			break;
		case 'a':
			set_dest_ip_str_param(config, optarg);
			break;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
	int ret;

	/** Parse cmdline/json arguments */
	set_default_config_params();
	//doca_argp_init("ucx_allgather", &type_config, &ucx_app_config);
	//register_ucx_allgather_params();
	//doca_argp_start(argc, argv, &doca_general_config);
	parse_args(argc, argv, &ucx_app_config);

	/** Initialize destination addresses specified by a user */
	ret = dest_addresses_init();
	if (ret < 0)
		goto out_doca_argp_destroy;

	/** Create context */
	ret = ucx_init(&context, UCX_ALLGATHER_MAX_AM_ID);
	if (ret < 0)
		goto out_dest_address_cleanup;

	/** Run required code depending on the type of the process */
	if (ucx_app_config.role == UCX_ALLGATHER_DAEMON)
		daemon_run();
	else
		client_run();

	/** Destroy UCX context */
	ucx_destroy(context);
out_dest_address_cleanup:
	/** Destroy destination addresses */
	dest_address_cleanup();
out_doca_argp_destroy:
	//doca_argp_destroy();
	return ret;
}
