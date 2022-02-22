/**
 * Copyright (C) 2022 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include <uct/api/uct.h>
#include <uct/api/v2/uct_v2.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>


#define CHKERR_ACTION(_cond, _msg, _action) \
    do { \
        if (_cond) { \
            fprintf(stderr, "Failed to %s\n", _msg); \
            _action; \
        } \
    } while (0)


#define CHKERR_JUMP(_cond, _msg, _label) CHKERR_ACTION(_cond, _msg, goto _label)

typedef struct {
    char       *server_name;
    uint16_t   server_port;
    const char *md_name;
    int        gvmi_id;
    size_t     size;
    size_t     align;
    uint32_t   mkey;
} cmd_args_t;


/* Device and transport to be used are determined by minimum latency */
static ucs_status_t open_md(const cmd_args_t *cmd_args, uct_md_h *md_p,
                            uct_component_h *component_p)
{
    uct_component_h *components;
    unsigned num_components;
    unsigned cmpt_index;
    uct_component_attr_t component_attr;
    unsigned md_index;
    uct_md_config_t *md_config;
    ucs_status_t status;
    uct_md_h md;

    status = uct_query_components(&components, &num_components);
    CHKERR_JUMP(UCS_OK != status, "query for components", error_ret);

    for (cmpt_index = 0; cmpt_index < num_components; ++cmpt_index) {
        component_attr.field_mask = UCT_COMPONENT_ATTR_FIELD_MD_RESOURCE_COUNT;
        status = uct_component_query(components[cmpt_index], &component_attr);
        CHKERR_JUMP(UCS_OK != status, "query component attributes",
                    release_component_list);

        component_attr.field_mask = UCT_COMPONENT_ATTR_FIELD_MD_RESOURCES;
        component_attr.md_resources = alloca(sizeof(*component_attr.md_resources) *
                                             component_attr.md_resource_count);
        status = uct_component_query(components[cmpt_index], &component_attr);
        CHKERR_JUMP(UCS_OK != status, "query for memory domain resources",
                    release_component_list);

        /* Iterate through memory domain resources */
        for (md_index = 0; md_index < component_attr.md_resource_count; ++md_index) {
            status = uct_md_config_read(components[cmpt_index], NULL, NULL,
                                        &md_config);
            CHKERR_JUMP(UCS_OK != status, "read MD config",
                        release_component_list);

            if (strcmp(component_attr.md_resources[md_index].md_name,
                       cmd_args->md_name)) {
                continue;
            }

            status = uct_md_open(components[cmpt_index],
                                 component_attr.md_resources[md_index].md_name,
                                 md_config, &md);
            uct_config_release(md_config);

            CHKERR_JUMP(UCS_OK != status, "open memory domains",
                        release_component_list);

            *md_p        = md;
            *component_p = components[cmpt_index];
            return UCS_OK;
        }
    }

    status = UCS_ERR_NO_DEVICE;

release_component_list:
    uct_release_component_list(components);
error_ret:
    return status;
}

void do_export(uct_md_h md, uct_component_h component,
               const cmd_args_t *cmd_args)
{
    uct_md_mem_reg_shared_params_t reg_shared_params;
    uct_rkey_bundle_t rkey_bundle;
    uint8_t rkey_buf[1024];
    ucs_status_t status;
    uct_mem_h memh;
    void *ptr;
    int ret;

    ret = posix_memalign(&ptr, cmd_args->align, cmd_args->size);
    CHKERR_JUMP(0 != ret, "allocate memory", error_ret);

    reg_shared_params.address   = ptr;
    reg_shared_params.length    = cmd_args->size;
    reg_shared_params.dest_gvmi = cmd_args->gvmi_id;

    status = uct_md_mem_reg_shared(md, &reg_shared_params, &memh);
    CHKERR_JUMP(UCS_OK != status, "uct_md_mem_reg_shared", error_ret);

    status = uct_md_mkey_pack(md, memh, rkey_buf);
    CHKERR_JUMP(UCS_OK != status, "uct_md_mkey_pack", error_ret);

    status = uct_rkey_unpack(component, rkey_buf, &rkey_bundle);
    CHKERR_JUMP(UCS_OK != status, "uct_rkey_unpack", error_ret);

    printf("shared ptr %p len %zu rkey 0x%x towards gvmi %d\n", ptr,
           cmd_args->size, (uint32_t)rkey_bundle.rkey, cmd_args->gvmi_id);
    printf("press any key to continue\n");
    getchar();

    status = uct_rkey_release(component, &rkey_bundle);
    CHKERR_JUMP(UCS_OK != status, "uct_rkey_release", error_ret);

    status = uct_md_mem_dereg(md, memh);
    CHKERR_JUMP(UCS_OK != status, "uct_md_mem_dereg", error_ret);

    free(ptr);

error_ret:
    ;
}

void do_import(uct_md_h md, uct_component_h component,
               const cmd_args_t *cmd_args)
{
    uct_md_import_shared_rkey_params_t import_params;
    ucs_status_t status;
    uct_mem_h memh;

    printf("unpacking mkey 0x%x on gvmi %d\n", cmd_args->mkey,
           cmd_args->gvmi_id);

    import_params.rkey        = cmd_args->mkey;
    import_params.source_gvmi = cmd_args->gvmi_id; // TODO

    status = uct_md_import_shared_rkey(md, &import_params, &memh);
    CHKERR_JUMP(UCS_OK != status, "uct_md_import_shared_rkey", error_ret);

    printf("imported shared rkey memh=%p\n", memh);

    status = uct_md_mem_dereg(md, memh);
    CHKERR_JUMP(UCS_OK != status, "uct_md_mem_dereg", error_ret);

error_ret:
    ;
}


int main(int argc, char** argv)
{
    uct_component_h component;
    ucs_status_t status;
    uct_md_h md;
    cmd_args_t args;
    int c;

    args.md_name = "mlx5_0";
    args.gvmi_id = 0;
    args.mkey    = 0;
    args.size    = 1024 * 1024;
    args.align   = 65536;

    while ((c = getopt(argc, argv, "d:g:i:s:a:")) != -1) {
        switch (c) {
        case 'd':
            args.md_name = optarg;
            break;
        case 'g':
            args.gvmi_id = atoi(optarg);
            break;
        case 'i':
            args.mkey = strtol(optarg, NULL, 0);
            break;
        case 's':
            args.size = strtoll(optarg, NULL, 0);
            break;
        case 'a':
            args.align = strtoll(optarg, NULL, 0);
            break;
        default:
            printf("Usage: %s [-d <md_name>] [-g <gvmi_id>] [-i <mkey>] [ -s size ] [ -a align ]\n",
                   argv[0]);
            return -1;
        }
    }

    status = open_md(&args, &md, &component);
    if (status != UCS_OK) {
        printf("could not open md\n");
        return -2;
    }

    if (args.mkey) {
        do_import(md, component, &args);
    } else {
        do_export(md, component, &args);
    }

    uct_md_close(md);

    return 0;
}