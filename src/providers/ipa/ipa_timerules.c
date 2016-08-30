/*
    SSSD

    IPA Provider - Time Rules Caching

    Authors:
        Stanislav Laznicka <slaznick@redhat.cz>

    Copyright (C) 2015 Red Hat

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

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_hbac_private.h"

struct ipa_timerule_state {
    struct tevent_context *ev;
    // struct sysdb_ctx *sysdb;
    struct sdap_handle *sh;
    struct sdap_options *opts;
    const char **attrs;
    // struct sdap_attr_map *timerule_map;

    char *timerule_filter;
    char *cur_filter;

    struct sdap_search_base **search_bases;
    int search_base_iter;

    /* Return values */
    size_t timerule_count;
    struct sysdb_attrs **timerules;
};

static errno_t
ipa_timerule_info_next(struct tevent_req *req,
                       struct ipa_timerule_state *state);
static void
ipa_timerule_info_done(struct tevent_req *subreq);

struct tevent_req *
ipa_timerule_info_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct sdap_handle *sh,
                       struct sdap_options *opts,
                       struct sdap_search_base **search_bases)
{
    errno_t ret;
    struct ipa_timerule_state *state;
    struct tevent_req *req;
    char *timerule_filter;

    req = tevent_req_create(mem_ctx, &state, struct ipa_timerule_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->sh = sh;
    state->opts = opts;

    state->search_bases = search_bases;
    state->search_base_iter = 0;

    timerule_filter = talloc_asprintf(state, "(objectClass=%s)",
                                     IPA_TIMERULE);
    if (timerule_filter == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    state->timerule_filter = timerule_filter;
    state->cur_filter = NULL;

    state->attrs = talloc_array(state, const char *, 5);
    if (state->attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to allocate service attribute list.\n");
        ret = ENOMEM;
        goto immediate;
    }
    state->attrs[0] = OBJECTCLASS;
    state->attrs[1] = IPA_CN;
    state->attrs[2] = IPA_MEMBEROF;
    state->attrs[3] = IPA_ACCESSTIME;
    state->attrs[4] = NULL;

    ret = ipa_timerule_info_next(req, state);
    if (ret == EOK) {
        ret = EINVAL;
    }

    if (ret != EAGAIN) {
        goto immediate;
    }

    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}


static errno_t
ipa_timerule_info_next(struct tevent_req *req,
                       struct ipa_timerule_state *state)
{
    struct tevent_req *subreq;
    struct sdap_search_base *base;

    base = state->search_bases[state->search_base_iter];
    if (base  == NULL) {
        return EOK;
    }

    talloc_zfree(state->cur_filter);
    state->cur_filter = sdap_combine_filters(state, state->timerule_filter,
                                             base->filter);
    if (state->cur_filter == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Sending request for next search base: "
                              "[%s][%d][%s]\n", base->basedn, base->scope,
                              state->cur_filter);
    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   base->basedn, base->scope,
                                   state->cur_filter,
                                   state->attrs, NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT),
                                   true);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error requesting service info\n");
        return EIO;
    }
    tevent_req_set_callback(subreq, ipa_timerule_info_done, req);

    return EAGAIN;
}


static void
ipa_timerule_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_timerule_state *state =
            tevent_req_data(req, struct ipa_timerule_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &state->timerule_count,
                                &state->timerules);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    if (state->timerule_count > 0) {
        ret = replace_attribute_name(IPA_MEMBEROF, SYSDB_ORIG_MEMBEROF,
                                     state->timerule_count,
                                     state->timerules);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not replace attribute names\n");
            goto done;
        }
    }

    state->search_base_iter++;
    ret = ipa_timerule_info_next(req, state);
    if (ret == EAGAIN) {
        return;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error [%d][%s]\n", ret, strerror(ret));
        tevent_req_error(req, ret);
    }
}


errno_t
ipa_timerule_info_recv(struct tevent_req *req,
                       TALLOC_CTX *mem_ctx,
                       size_t *timerule_count,
                       struct sysdb_attrs ***timerules)
{
    size_t c;
    struct ipa_timerule_state *state =
            tevent_req_data(req, struct ipa_timerule_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *timerule_count = state->timerule_count;
    *timerules = talloc_steal(mem_ctx, state->timerules);
    for (c = 0; c < state->timerule_count; c++) {
        /* Guarantee the memory heirarchy of the list */
        talloc_steal(state->timerules, state->timerules[c]);
    }

    return EOK;
}


errno_t
timerule_attrs_to_rule(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char *rule_name,
                       struct sysdb_attrs *rule_attrs,
                       struct hbac_time_rules ***_timerules)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message_element *el;
    struct hbac_time_rules **new_timerules = NULL;
    const char *attrs[] = {IPA_CN, IPA_ACCESSTIME, NULL};;
    char *member_dn;
    char *filter;
    size_t num_rules = 0;
    size_t count;
    struct ldb_message **msgs;
    const char *name;
    const char *rule_string;    /* currently we expect only one rule string */

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return ENOMEM;

    DEBUG(SSSDBG_TRACE_LIBS, "Processing time rules for rule [%s]\n",
          rule_name);

    ret = sysdb_attrs_get_el(rule_attrs, IPA_MEMBER_TIMERULE, &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_attrs_get_el failed.\n");
        goto done;
    }
    if (ret == ENOENT || el->num_values == 0) {
        el->num_values = 0;
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No time rules specified, rule will always apply.\n");
    }

    new_timerules = talloc_array(tmp_ctx, struct hbac_time_rules *,
                                 el->num_values + 1);
    if (new_timerules == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (int i = 0; i < el->num_values; i++) {
        ret = sss_filter_sanitize(tmp_ctx,
                                  (const char *)el->values[i].data,
                                  &member_dn);
        if (ret != EOK) goto done;

        filter = talloc_asprintf(member_dn, "(%s=%s)",
                                 SYSDB_ORIG_DN, member_dn);
        if (filter == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_search_custom(tmp_ctx, domain, filter,
                                  HBAC_TIMERULES_SUBDIR, attrs,
                                  &count, &msgs);
        if (ret != EOK && ret != ENOENT) goto done;
        if (ret == EOK && count == 0) {
            ret = ENOENT;
        }

        if (ret == EOK) {
            if (count > 1) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "The original DN [%s] matched multiple services. "
                      "Skipping.\n", member_dn);
                talloc_zfree(member_dn);
                continue;
            }

            /*TODO: work with sysdb_attrs_get_el, sss_ldb_el_to_string_list
                    to get the actual content of this element*/
            name = ldb_msg_find_attr_as_string(msgs[0], IPA_CN, NULL);
            if (name == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Attribute is missing: [%s]\n",
                      IPA_CN);
                ret = EFAULT;
                goto done;
            }
            rule_string = ldb_msg_find_attr_as_string(msgs[0], IPA_ACCESSTIME,
                                                      NULL);
            if (rule_string == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Attribute is missing: [%s]\n",
                      IPA_ACCESSTIME);
                ret = EFAULT;
                goto done;
            }

            new_timerules[num_rules] = talloc_zero(new_timerules,
                                                   struct hbac_time_rules);
            if (new_timerules[num_rules] == NULL) {
                ret = ENOMEM;
                goto done;
            }

            new_timerules[num_rules]->name = talloc_strdup(
                                                new_timerules[num_rules],
                                                name);
            if (new_timerules[num_rules]->name == NULL) {
                ret = ENOMEM;
                goto done;
            }

            new_timerules[num_rules]->accesstimes =
                talloc_array(new_timerules[num_rules], const char *, 2);
            new_timerules[num_rules]->accesstimes[0] =
                    talloc_strdup(new_timerules[num_rules]->accesstimes,
                                  rule_string);
            if (new_timerules[num_rules]->accesstimes == NULL) {
                ret = ENOMEM;
                goto done;
            }

            new_timerules[num_rules]->accesstimes[1] = NULL;
            num_rules++;
        } else { /* end if (ret == EOK) */
            DEBUG(SSSDBG_CRIT_FAILURE, "[%s] is not a time rule. Skipping.\n",
                  member_dn);
        }
        talloc_zfree(member_dn);
    }
    new_timerules[num_rules] = NULL;
    ret = EOK;

done:
    if (ret == EOK) {
        *_timerules = talloc_steal(mem_ctx, new_timerules);
    }
    talloc_free(tmp_ctx);
    return ret;
}
