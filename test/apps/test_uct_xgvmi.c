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
#include <sys/mman.h>


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
    size_t     size;
    size_t     align;
    uint64_t   mkey;
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

ucs_status_t do_export(uct_md_h md, uct_component_h component,
                       const cmd_args_t *cmd_args)
{
    uct_md_mem_reg_params_t params;
    uct_md_mkey_pack_params_t mkey_pack_params;
    uint8_t shared_mkey_buf[1024];
    uint64_t shared_mkey;
    ucs_status_t status = UCS_OK;
    uct_mem_h memh;
    void *ptr;
    int ret;

    ret = posix_memalign(&ptr, cmd_args->align, cmd_args->size);
    CHKERR_JUMP(0 != ret, "allocate memory", error_ret);

    params.field_mask = UCT_MD_MEM_REG_FIELD_FLAGS;
    params.flags      = UCT_MD_MEM_FLAG_SHARED | UCT_MD_MEM_ACCESS_ALL;
    status            = uct_md_mem_reg_v2(md, ptr, cmd_args->size, &params,
                                          &memh);
    CHKERR_JUMP(UCS_OK != status, "uct_md_mem_reg_v2", error_ret);

    mkey_pack_params.field_mask = UCT_MD_MKEY_PACK_FIELD_FLAGS;
    mkey_pack_params.flags      = UCT_MD_MKEY_PACK_FLAG_SHARED;
    status                      = uct_md_mkey_pack_v2(md, memh,
                                                      &mkey_pack_params,
                                                      shared_mkey_buf);
    CHKERR_JUMP(UCS_OK != status, "uct_md_mkey_pack", error_ret);

    shared_mkey = *((uint64_t*)&shared_mkey_buf[0]);
    printf("shared ptr %p len %zu shared_mkey 0x%zx\n", ptr,
           cmd_args->size, shared_mkey);
    printf("press any key to continue\n");
    getchar();

    status = uct_md_mem_dereg(md, memh);
    CHKERR_JUMP(UCS_OK != status, "uct_md_mem_dereg", error_ret);

    free(ptr);

error_ret:
    return status;;
}

ucs_status_t do_import(uct_md_h md, uct_component_h component,
                       const cmd_args_t *cmd_args)
{
    uct_md_mem_attach_params_t attach_params;
    uct_md_mem_dereg_params_t dereg_params;
    ucs_status_t status;

    printf("unpacking mkey 0x%zx\n", cmd_args->mkey);

    attach_params.field_mask         =
            UCT_MD_MEM_ATTACH_FIELD_FLAGS |
            UCT_MD_MEM_ATTACH_FIELD_SHARED_MKEY_BUFFER |
            UCT_MD_MEM_ATTACH_FIELD_MEMH;
    attach_params.flags              = UCT_MD_MEM_ATTACH_FLAG_SHARED;
    attach_params.shared_mkey_buffer = &cmd_args->mkey;
    status                           = uct_md_mem_attach(md, &attach_params);
    CHKERR_ACTION(UCS_OK != status, "uct_md_mem_attach", return status);

    printf("imported shared mkey: address=%p memh=%p\n",
           attach_params.address, attach_params.memh);

    dereg_params.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH |
                              UCT_MD_MEM_DEREG_FIELD_ADDRESS;
    dereg_params.memh       = attach_params.memh;
    dereg_params.address    = attach_params.address;
    status = uct_md_mem_dereg_v2(md, &dereg_params);
    CHKERR_ACTION(UCS_OK != status, "uct_md_mem_dereg", return status);

    return UCS_OK;
}


int main(int argc, char** argv)
{
    uct_component_h component;
    ucs_status_t status;
    uct_md_h md;
    cmd_args_t args;
    int c;

    args.md_name = "mlx5_0";
    args.mkey    = 0lu;
    args.size    = 1024 * 1024;
    args.align   = 65536;

    while ((c = getopt(argc, argv, "d:g:i:s:a:")) != -1) {
        switch (c) {
        case 'd':
            args.md_name = optarg;
            break;
        case 'i':
            args.mkey = strtoull(optarg, NULL, 0);
            break;
        case 's':
            args.size = strtoull(optarg, NULL, 0);
            break;
        case 'a':
            args.align = strtoull(optarg, NULL, 0);
            break;
        default:
            printf("Usage: %s [-d <md_name>] [-g <id>] [-i <mkey>] [ -s size ] [ -a align ]\n",
                   argv[0]);
            return -1;
        }
    }

    status = open_md(&args, &md, &component);
    if (status != UCS_OK) {
        printf("could not open md\n");
        return -2;
    }

    if (args.mkey != 0) {
        status = do_import(md, component, &args);
    } else {
        status = do_export(md, component, &args);
    }

    uct_md_close(md);

    return (status == UCS_OK) ? 0 : -3;
}
