/*
**  Licensed to the Apache Software Foundation (ASF) under one or more
** contributor license agreements.  See the NOTICE file distributed with
** this work for additional information regarding copyright ownership.
** The ASF licenses this file to You under the Apache License, Version 2.0
** (the "License"); you may not use this file except in compliance with
** the License.  You may obtain a copy of the License at
**
**      http://www.apache.org/licenses/LICENSE-2.0
**
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
**  limitations under the License.
*/

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "util_filter.h"
#include "apr_tables.h"
#include "apr_buckets.h"
#include "http_request.h"
#include "apr_strings.h"
#include "http_connection.h"
#include "mpm_common.h"


#include "private.h"

static void *apreq_create_dir_config(apr_pool_t *p, char *d)
{
  /* d == OR_ALL */
  struct dir_config *dc = apr_palloc(p, sizeof * dc);

  dc->filter        = NULL;
  dc->resource      = NULL;
  dc->L             = NULL;
  return dc;
}

apr_status_t lua_output_filter(ap_filter_t *f, apr_bucket_brigade *bb);

static const char *luaex_cmd_OuputFilter(cmd_parms *cmd,
    void *dcfg,
    const char *filter, const char *script)
{
  struct dir_config *conf = dcfg;
  const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);

  if (err != NULL)
    return err;

  if (conf->filter == NULL)
  {
    conf->filter = apr_table_make(cmd->pool, 8);
  }

  if (conf->filter == NULL)
    return "Out of memory";

  apr_table_set(conf->filter, filter , script);
  ap_register_output_filter(filter, lua_output_filter, NULL, AP_FTYPE_RESOURCE);
  return NULL;
}


const char *luaex_cmd_Reslist(cmd_parms *cmd,
                              void *dcfg,
                              const char *resource, const char *script);

typedef struct ml_monitor
{
  const char* script;
  const char* handler;
} ml_monitor;

static const char *Luaex_Monitor(cmd_parms *cmd, void *dcfg,
                                 const char *script, const char *handler)
{
  struct dir_config *conf = dcfg;
  const char *err = ap_check_cmd_context(cmd, NOT_IN_LIMIT);
  ml_monitor *monitor;

  if (err != NULL)
    return err;

  if (conf->monitor == NULL)
  {
    conf->monitor = apr_array_make(cmd->pool, 16, sizeof(ml_monitor));
  }

  if (conf->monitor == NULL)
    return "Out of memory";
  if (conf->monitor->nelts == 16)
    return "Only allow 16 crontab rules";
  monitor = apr_array_push(conf->monitor);

  monitor->script = script;
  monitor->handler = handler ? handler : "handle";

  return NULL;
}

static const command_rec apreq_cmds[] =
{
  AP_INIT_TAKE12("Luaex_Monitor", Luaex_Monitor, NULL, OR_ALL,
  "Monitor hook"),
  AP_INIT_TAKE2("Luaex_OutputFilter", luaex_cmd_OuputFilter, NULL, OR_ALL,
  "Luaex VM Output Filter Script "
  "Lua_Output_Filter FilterName LuaScript"
  "(`@PATH --LuaScript handle Script FilePath', `lua handle script content')"),
#ifdef ML_HAVE_RESLIST
  AP_INIT_TAKE2("Luaex_Reslist", luaex_cmd_Reslist, NULL, OR_ALL,
  "Luaex Resource List management"
  "Luaex_Reslist ResourceName LuaScript"
  "(`@PATH --LuaScript handle Script FilePath', `lua handle script content')"
  "constructor and destructor function must be exist in LuaScript"
  "min, smax, hmax are option value, default is 0, 16, 16"),
#endif
  AP_INIT_TAKE2("Luaex_Handle", ml_set_server_handle, NULL, OR_ALL,
  "Set server handle file and function"),
  AP_INIT_TAKE23("Luaex_MethodHandle", ml_set_method_handle, NULL,
  OR_ALL,
  "Provide a hook for the post_config function for luaex module"),
  { NULL }
};


static int luaex_monitor(apr_pool_t *p, server_rec *s)
{
  char date_str[APR_PATH_MAX];
  apr_time_t now = apr_time_now();
  apr_status_t rc = apr_rfc822_date(date_str, now);
  if (rc == 0)
  {
    printf("TICK: %s\n", date_str);
  }
  return 0;
}

static void register_hooks (apr_pool_t *p)
{
  ap_hook_process_connection(ml_process_connection, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_monitor(luaex_monitor, NULL, NULL, APR_HOOK_MIDDLE);

  ml_register_hooks(p);
}

/** @} */


module AP_MODULE_DECLARE_DATA luaex_module =
{
  STANDARD20_MODULE_STUFF,
  apreq_create_dir_config,
  NULL,
  ml_create_server,
  NULL,
  apreq_cmds,
  register_hooks,
};
