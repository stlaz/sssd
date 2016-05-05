/*
    SSSD

    IPA Backend Module -- Access control

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/param.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_hosts.h"
#include "providers/ipa/ipa_hbac_private.h"
#include "providers/ipa/ipa_hbac_rules.h"

/* External logging function for HBAC. */
void hbac_debug_messages(const char *file, int line,
                         const char *function,
                         enum hbac_debug_level level,
                         const char *fmt, ...)
{
    int loglevel;

    switch(level) {
    case HBAC_DBG_FATAL:
        loglevel = SSSDBG_FATAL_FAILURE;
        break;
    case HBAC_DBG_ERROR:
        loglevel = SSSDBG_OP_FAILURE;
        break;
    case HBAC_DBG_WARNING:
        loglevel = SSSDBG_MINOR_FAILURE;
        break;
    case HBAC_DBG_INFO:
        loglevel = SSSDBG_CONF_SETTINGS;
        break;
    case HBAC_DBG_TRACE:
        loglevel = SSSDBG_TRACE_INTERNAL;
        break;
    default:
        loglevel = SSSDBG_UNRESOLVED;
        break;
    }

    if (DEBUG_IS_SET(loglevel)) {
        va_list ap;

        va_start(ap, fmt);
        sss_vdebug_fn(file, line, function, loglevel, 0, fmt, ap);
        va_end(ap);
    }
}

static void ipa_access_reply(struct hbac_ctx *hbac_ctx, int pam_status)
{
    struct be_req *be_req = hbac_ctx->be_req;
    struct pam_data *pd;
    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);
    pd->pam_status = pam_status;

    /* destroy HBAC context now to release all used resources and LDAP connection */
    talloc_zfree(hbac_ctx);

    if (pam_status == PAM_SUCCESS || pam_status == PAM_PERM_DENIED) {
        be_req_terminate(be_req, DP_ERR_OK, pam_status, NULL);
    } else {
        be_req_terminate(be_req, DP_ERR_FATAL, pam_status, NULL);
    }
}

enum hbac_result {
    HBAC_ALLOW = 1,
    HBAC_DENY,
    HBAC_NOT_APPLICABLE
};

enum check_result {
    RULE_APPLICABLE = 0,
    RULE_NOT_APPLICABLE,
    RULE_ERROR
};

static void ipa_hbac_check(struct tevent_req *req);
static int hbac_retry(struct hbac_ctx *hbac_ctx);
static void hbac_connect_done(struct tevent_req *subreq);
static bool hbac_check_step_result(struct hbac_ctx *hbac_ctx, int ret);

static int hbac_get_host_info_step(struct hbac_ctx *hbac_ctx);

static void ipa_hbac_evaluate_rules(struct hbac_ctx *hbac_ctx);

void ipa_access_handler(struct be_req *be_req)
{
    struct pam_data *pd;
    struct ipa_access_ctx *ipa_access_ctx;
    struct tevent_req *req;
    struct sss_domain_info *dom;
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);

    ipa_access_ctx = talloc_get_type(be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                                     struct ipa_access_ctx);

    dom = be_ctx->domain;
    if (strcasecmp(pd->domain, be_ctx->domain->name) != 0) {
        /* Subdomain request, verify subdomain */
        dom = find_domain_by_name(be_ctx->domain, pd->domain, true);
    }

    /* First, verify that this account isn't locked.
     * We need to do this in case the auth phase was
     * skipped (such as during GSSAPI single-sign-on
     * or SSH public key exchange.
     */
    req = sdap_access_send(be_req, be_ctx->ev, be_ctx, dom,
                           ipa_access_ctx->sdap_access_ctx,
                           ipa_access_ctx->sdap_access_ctx->id_ctx->conn,
                           pd);
    if (!req) {
        be_req_terminate(be_req, DP_ERR_FATAL, PAM_SYSTEM_ERR, NULL);
        return;
    }
    tevent_req_set_callback(req, ipa_hbac_check, be_req);
}

static void ipa_hbac_check(struct tevent_req *req)
{
    struct be_req *be_req;
    struct be_ctx *be_ctx;
    struct pam_data *pd;
    struct hbac_ctx *hbac_ctx = NULL;
    struct ipa_access_ctx *ipa_access_ctx;
    int ret;

    be_req = tevent_req_callback_data(req, struct be_req);
    be_ctx = be_req_get_be_ctx(be_req);
    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);

    ret = sdap_access_recv(req);
    talloc_zfree(req);

    switch(ret) {
    case EOK:
        /* Account wasn't locked. Continue below
         * to HBAC processing.
         */
        break;
    case ERR_ACCESS_DENIED:
        /* Account was locked. Return permission denied
         * here.
         */
        pd->pam_status = PAM_PERM_DENIED;
        be_req_terminate(be_req, DP_ERR_OK, pd->pam_status, NULL);
        return;
    case ERR_ACCOUNT_EXPIRED:
        pd->pam_status = PAM_ACCT_EXPIRED;
        be_req_terminate(be_req, DP_ERR_OK, pd->pam_status, NULL);
        return;
    default:
        /* We got an unexpected error. Return it as-is */
        pd->pam_status = PAM_SYSTEM_ERR;
        be_req_terminate(be_req, DP_ERR_FATAL, pd->pam_status,
                         sss_strerror(ret));
        return;
    }

    hbac_ctx = talloc_zero(be_req, struct hbac_ctx);
    if (hbac_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    hbac_ctx->be_req = be_req;
    hbac_ctx->pd = pd;
    ipa_access_ctx = talloc_get_type(be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                                     struct ipa_access_ctx);
    hbac_ctx->access_ctx = ipa_access_ctx;
    hbac_ctx->sdap_ctx = ipa_access_ctx->sdap_ctx;
    hbac_ctx->ipa_options = ipa_access_ctx->ipa_options;
    hbac_ctx->tr_ctx = ipa_access_ctx->tr_ctx;
    hbac_ctx->search_bases = ipa_access_ctx->hbac_search_bases;
    if (hbac_ctx->search_bases == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No HBAC search base found.\n");
        ret = EINVAL;
        goto fail;
    }

    ret = hbac_retry(hbac_ctx);
    if (ret != EOK) {
        goto fail;
    }

    return;

fail:
    if (hbac_ctx) {
        /* Return an proper error */
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
    } else {
        be_req_terminate(be_req, DP_ERR_FATAL, PAM_SYSTEM_ERR, NULL);
    }
}

static int hbac_retry(struct hbac_ctx *hbac_ctx)
{
    struct tevent_req *subreq;
    int ret;
    bool offline;
    time_t now, refresh_interval;
    struct ipa_access_ctx *access_ctx = hbac_ctx->access_ctx;
    struct be_ctx *be_ctx = be_req_get_be_ctx(hbac_ctx->be_req);

    offline = be_is_offline(be_ctx);
    DEBUG(SSSDBG_TRACE_ALL,
          "Connection status is [%s].\n", offline ? "offline" : "online");

    refresh_interval = dp_opt_get_int(hbac_ctx->ipa_options,
                                      IPA_HBAC_REFRESH);

    now = time(NULL);
    if (now < access_ctx->last_update + refresh_interval) {
        /* Simulate offline mode and just go to the cache */
        DEBUG(SSSDBG_TRACE_FUNC, "Performing cached HBAC evaluation\n");
        offline = true;
    }

    if (!offline) {
        if (hbac_ctx->sdap_op == NULL) {
            hbac_ctx->sdap_op = sdap_id_op_create(hbac_ctx,
                                          hbac_ctx->sdap_ctx->conn->conn_cache);
            if (hbac_ctx->sdap_op == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_create failed.\n");
                return EIO;
            }
        }

        subreq = sdap_id_op_connect_send(hbac_ctx->sdap_op, hbac_ctx, &ret);
        if (!subreq) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_id_op_connect_send failed: %d(%s).\n", ret, strerror(ret));
            talloc_zfree(hbac_ctx->sdap_op);
            return ret;
        }

        tevent_req_set_callback(subreq, hbac_connect_done, hbac_ctx);
    } else {
        /* Evaluate the rules based on what we have in the
         * sysdb
         */
        ipa_hbac_evaluate_rules(hbac_ctx);
        return EOK;
    }
    return EOK;
}

static void hbac_connect_done(struct tevent_req *subreq)
{
    struct hbac_ctx *hbac_ctx = tevent_req_callback_data(subreq, struct hbac_ctx);
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (dp_error == DP_ERR_OFFLINE) {
        /* switching to offline mode */
        talloc_zfree(hbac_ctx->sdap_op);

        ipa_hbac_evaluate_rules(hbac_ctx);
        return;
    } else if (ret != EOK) {
        goto fail;
    }

    ret = hbac_get_host_info_step(hbac_ctx);
    if (ret != EOK) {
        goto fail;
    }

    return;

fail:
    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
}

static void hbac_clear_rule_data(struct hbac_ctx *hbac_ctx)
{
    hbac_ctx->host_count = 0;
    talloc_zfree(hbac_ctx->hosts);

    hbac_ctx->hostgroup_count = 0;
    talloc_zfree(hbac_ctx->hostgroups);

    hbac_ctx->service_count = 0;
    talloc_zfree(hbac_ctx->services);

    hbac_ctx->servicegroup_count = 0;
    talloc_zfree(hbac_ctx->servicegroups);

    hbac_ctx->rule_count = 0;
    talloc_zfree(hbac_ctx->rules);
}

/* Check whether the current HBAC request is processed in off-line mode */
static inline bool hbac_ctx_is_offline(struct hbac_ctx *ctx)
{
    return ctx == NULL || ctx->sdap_op == NULL;
}

/* Check the step result code and continue, retry, get offline result or abort accordingly */
static bool hbac_check_step_result(struct hbac_ctx *hbac_ctx, int ret)
{
    int dp_error;

    if (ret == EOK) {
        return true;
    }

    if (hbac_ctx_is_offline(hbac_ctx)) {
        /* already offline => the error is fatal */
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
        return false;
    }

    ret = sdap_id_op_done(hbac_ctx->sdap_op, ret, &dp_error);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            /* switching to offline mode */
            talloc_zfree(hbac_ctx->sdap_op);

            /* Free any of the results we've gotten */
            hbac_clear_rule_data(hbac_ctx);

            dp_error = DP_ERR_OK;
        }

        if (dp_error == DP_ERR_OK) {
            /* retry */
            ret = hbac_retry(hbac_ctx);
            if (ret == EOK) {
                return false;
            }
        }
    }

    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
    return false;
}

static void hbac_get_service_info_step(struct tevent_req *req);
static void hbac_get_rule_info_step(struct tevent_req *req);
static void hbac_sysdb_save (struct tevent_req *req);

static int hbac_get_host_info_step(struct hbac_ctx *hbac_ctx)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(hbac_ctx->be_req);
    const char *hostname;
    struct tevent_req *req;

    if (dp_opt_get_bool(hbac_ctx->ipa_options, IPA_HBAC_SUPPORT_SRCHOST)) {
        /* Support srchost
         * -> we don't want any particular host,
         *    we want all hosts
         */
        hostname = NULL;

        /* THIS FEATURE IS DEPRECATED */
        DEBUG(SSSDBG_MINOR_FAILURE, "WARNING: Using deprecated option "
                    "ipa_hbac_support_srchost.\n");
        sss_log(SSS_LOG_NOTICE, "WARNING: Using deprecated option "
                    "ipa_hbac_support_srchost.\n");
    } else {
        hostname = dp_opt_get_string(hbac_ctx->ipa_options, IPA_HOSTNAME);
    }

    req = ipa_host_info_send(hbac_ctx, be_ctx->ev,
                             sdap_id_op_handle(hbac_ctx->sdap_op),
                             hbac_ctx->sdap_ctx->opts,
                             hostname,
                             hbac_ctx->access_ctx->host_map,
                             hbac_ctx->access_ctx->hostgroup_map,
                             hbac_ctx->access_ctx->host_search_bases);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not get host info\n");
        return ENOMEM;
    }
    tevent_req_set_callback(req, hbac_get_service_info_step, hbac_ctx);

    return EOK;
}

static void hbac_get_service_info_step(struct tevent_req *req)
{
    errno_t ret;
    struct hbac_ctx *hbac_ctx =
            tevent_req_callback_data(req, struct hbac_ctx);
    struct be_ctx *be_ctx = be_req_get_be_ctx(hbac_ctx->be_req);

    ret = ipa_host_info_recv(req, hbac_ctx,
                             &hbac_ctx->host_count,
                             &hbac_ctx->hosts,
                             &hbac_ctx->hostgroup_count,
                             &hbac_ctx->hostgroups);
    talloc_zfree(req);
    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    /* Get services and service groups */
    req = ipa_hbac_service_info_send(hbac_ctx, be_ctx->ev,
                                    sdap_id_op_handle(hbac_ctx->sdap_op),
                                     hbac_ctx->sdap_ctx->opts,
                                    hbac_ctx->search_bases);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,"Could not get service info\n");
        goto fail;
    }
    tevent_req_set_callback(req, hbac_get_rule_info_step, hbac_ctx);
    return;

fail:
    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
}

static void hbac_get_rule_info_step(struct tevent_req *req)
{
    errno_t ret;
    size_t i;
    const char *ipa_hostname;
    const char *hostname;
    struct hbac_ctx *hbac_ctx =
            tevent_req_callback_data(req, struct hbac_ctx);
    struct be_ctx *be_ctx = be_req_get_be_ctx(hbac_ctx->be_req);

    ret = ipa_hbac_service_info_recv(req, hbac_ctx,
                                     &hbac_ctx->service_count,
                                     &hbac_ctx->services,
                                     &hbac_ctx->servicegroup_count,
                                     &hbac_ctx->servicegroups);
    talloc_zfree(req);
    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    /* Get the ipa_host attrs */
    hbac_ctx->ipa_host = NULL;
    ipa_hostname = dp_opt_get_cstring(hbac_ctx->ipa_options, IPA_HOSTNAME);
    if (ipa_hostname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing ipa_hostname, this should never happen.\n");
        goto fail;
    }

    for (i = 0; i < hbac_ctx->host_count; i++) {
        ret = sysdb_attrs_get_string(hbac_ctx->hosts[i],
                                     SYSDB_FQDN,
                                     &hostname);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not locate IPA host\n");
            goto fail;
        }

        if (strcasecmp(hostname, ipa_hostname) == 0) {
            hbac_ctx->ipa_host = hbac_ctx->hosts[i];
            break;
        }
    }
    if (hbac_ctx->ipa_host == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not locate IPA host\n");
        goto fail;
    }


    /* Get the list of applicable rules */
    req = ipa_hbac_rule_info_send(hbac_ctx,
                                  be_ctx->ev,
                                  sdap_id_op_handle(hbac_ctx->sdap_op),
                                  hbac_ctx->sdap_ctx->opts,
                                  hbac_ctx->search_bases,
                                  hbac_ctx->ipa_host);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not get rules\n");
        goto fail;
    }

    tevent_req_set_callback(req, hbac_sysdb_save, hbac_ctx);
    return;

fail:
    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
}

static void hbac_sysdb_save(struct tevent_req *req)
{
    errno_t ret;
    bool in_transaction = false;
    struct hbac_ctx *hbac_ctx =
            tevent_req_callback_data(req, struct hbac_ctx);
    struct be_ctx *be_ctx = be_req_get_be_ctx(hbac_ctx->be_req);
    struct sss_domain_info *domain = be_ctx->domain;
    struct ldb_dn *base_dn;
    struct ipa_access_ctx *access_ctx =
            talloc_get_type(be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                            struct ipa_access_ctx);
    TALLOC_CTX *tmp_ctx;

    ret = ipa_hbac_rule_info_recv(req, hbac_ctx,
                                  &hbac_ctx->rule_count,
                                  &hbac_ctx->rules);
    talloc_zfree(req);
    if (ret == ENOENT) {
        /* No rules were found that apply to this
         * host.
         */

        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
            return;
        }
        /* Delete any rules in the sysdb so offline logins
         * are also denied.
         */
        base_dn = sysdb_custom_subtree_dn(tmp_ctx, domain, HBAC_RULES_SUBDIR);
        if (base_dn == NULL) {
            talloc_free(tmp_ctx);
            ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
            return;
        }

        ret = sysdb_delete_recursive(domain->sysdb, base_dn, true);
        talloc_free(tmp_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_delete_recursive failed.\n");
            ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
            return;
        }

        /* If no rules are found, we default to DENY */
        ipa_access_reply(hbac_ctx, PAM_PERM_DENIED);
        return;
    }

    if (!hbac_check_step_result(hbac_ctx, ret)) {
        return;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not start transaction\n");
        goto fail;
    }
    in_transaction = true;

    /* Save the hosts */
    ret = ipa_hbac_sysdb_save(domain,
                              HBAC_HOSTS_SUBDIR, SYSDB_FQDN,
                              hbac_ctx->host_count, hbac_ctx->hosts,
                              HBAC_HOSTGROUPS_SUBDIR, SYSDB_NAME,
                              hbac_ctx->hostgroup_count,
                              hbac_ctx->hostgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error saving hosts: [%d][%s]\n",
                  ret, strerror(ret));
        goto fail;
    }

    /* Save the services */
    ret = ipa_hbac_sysdb_save(domain,
                              HBAC_SERVICES_SUBDIR, IPA_CN,
                              hbac_ctx->service_count, hbac_ctx->services,
                              HBAC_SERVICEGROUPS_SUBDIR, IPA_CN,
                              hbac_ctx->servicegroup_count,
                              hbac_ctx->servicegroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error saving services:  [%d][%s]\n",
                  ret, strerror(ret));
        goto fail;
    }
    /* Save the rules */
    ret = ipa_hbac_sysdb_save(domain,
                              HBAC_RULES_SUBDIR, IPA_UNIQUE_ID,
                              hbac_ctx->rule_count,
                              hbac_ctx->rules,
                              NULL, NULL, 0, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error saving rules:  [%d][%s]\n",
                  ret, strerror(ret));
        goto fail;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto fail;
    }
    in_transaction = false;

    /* We don't need the rule data any longer,
     * the rest of the processing relies on
     * sysdb lookups.
     */
    hbac_clear_rule_data(hbac_ctx);


    access_ctx->last_update = time(NULL);

    /* Now evaluate the request against the rules */
    ipa_hbac_evaluate_rules(hbac_ctx);

    return;

fail:
    if (in_transaction) {
        ret = sysdb_transaction_cancel(domain->sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Could not cancel transaction\n");
        }
    }
    ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
}

void ipa_hbac_evaluate_rules(struct hbac_ctx *hbac_ctx)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(hbac_ctx->be_req);
    errno_t ret;
    struct hbac_rule **hbac_rules;
    struct hbac_eval_req *eval_req;
    enum hbac_eval_result result;
    struct hbac_info *info;

    /* Get HBAC rules from the sysdb */
    ret = hbac_get_cached_rules(hbac_ctx, be_ctx->domain,
                                &hbac_ctx->rule_count, &hbac_ctx->rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not retrieve rules from the cache\n");
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
    }

    ret = hbac_ctx_to_rules(hbac_ctx, hbac_ctx,
                            &hbac_rules, &eval_req);
    if (ret == EPERM) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "DENY rules detected. Denying access to all users\n");
        ipa_access_reply(hbac_ctx, PAM_PERM_DENIED);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not construct HBAC rules\n");
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
        return;
    }

    hbac_enable_debug(hbac_debug_messages);

    result = hbac_evaluate(hbac_rules, eval_req, &info);
    if (result == HBAC_EVAL_ALLOW) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Access granted by HBAC rule [%s]\n",
                  info->rule_name);
        hbac_free_info(info);
        ipa_access_reply(hbac_ctx, PAM_SUCCESS);
        return;
    } else if (result == HBAC_EVAL_ERROR) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error [%s] occurred in rule [%s]\n",
                  hbac_error_string(info->code),
                  info->rule_name);
        hbac_free_info(info);
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
        return;
    } else if (result == HBAC_EVAL_OOM) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Insufficient memory\n");
        ipa_access_reply(hbac_ctx, PAM_SYSTEM_ERR);
        return;
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "Access denied by HBAC rules\n");
    hbac_free_info(info);
    ipa_access_reply(hbac_ctx, PAM_PERM_DENIED);
}

errno_t hbac_get_cached_rules(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              size_t *_rule_count,
                              struct sysdb_attrs ***_rules)
{
    errno_t ret;
    struct ldb_message **msgs;
    struct sysdb_attrs **rules;
    size_t rule_count;
    TALLOC_CTX *tmp_ctx;
    char *filter;
    const char *attrs[] = { OBJECTCLASS,
                            IPA_CN,
                            SYSDB_ORIG_DN,
                            IPA_UNIQUE_ID,
                            IPA_ENABLED_FLAG,
                            IPA_ACCESS_RULE_TYPE,
                            IPA_MEMBER_USER,
                            IPA_USER_CATEGORY,
                            IPA_MEMBER_SERVICE,
                            IPA_SERVICE_CATEGORY,
                            IPA_SOURCE_HOST,
                            IPA_SOURCE_HOST_CATEGORY,
                            IPA_EXTERNAL_HOST,
                            IPA_MEMBER_HOST,
                            IPA_HOST_CATEGORY,
                            IPA_ACCESSTIME,
                            NULL };

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    filter = talloc_asprintf(tmp_ctx, "(objectClass=%s)", IPA_HBAC_RULE);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              HBAC_RULES_SUBDIR, attrs,
                              &rule_count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up HBAC rules\n");
        goto done;
    } if (ret == ENOENT) {
       rule_count = 0;
    }

    ret = sysdb_msg2attrs(tmp_ctx, rule_count, msgs, &rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not convert ldb message to sysdb_attrs\n");
        goto done;
    }

    if (_rules) *_rules = talloc_steal(mem_ctx, rules);
    if (_rule_count) *_rule_count = rule_count;

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}
