/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include <stdlib.h>
#include <check.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <talloc.h>
#include <libical/ical.h>

#include "tests/common_check.h"
#include "lib/ipa_hbac/ipa_hbac.h"

#define HBAC_TEST_USER "testuser"
#define HBAC_TEST_INVALID_USER "nosuchuser"

#define HBAC_TEST_GROUP1 "testgroup1"
#define HBAC_TEST_GROUP2 "testgroup2"
#define HBAC_TEST_INVALID_GROUP "nosuchgroup"

#define HBAC_TEST_SERVICE "testservice"
#define HBAC_TEST_INVALID_SERVICE "nosuchservice"

#define HBAC_TEST_SERVICEGROUP1 "login_services"
#define HBAC_TEST_SERVICEGROUP2 "all_services"
#define HBAC_TEST_INVALID_SERVICEGROUP "nosuchservicegroup"

#define HBAC_TEST_SRCHOST "client.example.com"
#define HBAC_TEST_INVALID_SRCHOST "nosuchsrchost"

#define HBAC_TEST_SRCHOSTGROUP1 "site_hosts"
#define HBAC_TEST_SRCHOSTGROUP2 "corp_hosts"
#define HBAC_TEST_INVALID_SRCHOSTGROUP "nosuchsrchostgroup"


/* These don't make sense for a user/group/service but they do the job and
 * every one is from a different codepage */
/* Latin Extended A - "Czech" */
const uint8_t user_utf8_lowcase[] = { 0xC4, 0x8D, 'e', 'c', 'h', 0x0 };
const uint8_t user_utf8_upcase[] = { 0xC4, 0x8C, 'e', 'c', 'h', 0x0 };
const uint8_t user_utf8_lowcase_neg[] = { 0xC4, 0x8E, 'e', 'c', 'h', 0x0 };
/* Latin 1 Supplement - "Munchen" */
const uint8_t service_utf8_lowcase[] = { 'm', 0xC3, 0xBC, 'n', 'c', 'h', 'e', 'n', 0x0 };
const uint8_t service_utf8_upcase[] = { 'M', 0xC3, 0x9C, 'N', 'C', 'H', 'E', 'N', 0x0 };
/* Greek - "AlphaBetaGamma" */
const uint8_t srchost_utf8_lowcase[] = { 0xCE, 0xB1, 0xCE, 0xB2, 0xCE, 0xB3, 0x0  };
const uint8_t srchost_utf8_upcase[] = { 0xCE, 0x91, 0xCE, 0x92, 0xCE, 0x93, 0x0 };
/* Turkish "capital I" and "dotless i" */
const uint8_t user_lowcase_tr[] = { 0xC4, 0xB1, 0x0 };
const uint8_t user_upcase_tr[] = { 0x49, 0x0 };

static void get_allow_all_rule(TALLOC_CTX *mem_ctx,
                               struct hbac_rule **allow_rule)
{
    struct hbac_rule *rule;
    /* Create a rule that ALLOWs all services, users and
     * remote hosts.
     */
    rule = talloc_zero(mem_ctx, struct hbac_rule);
    fail_if (rule == NULL);

    rule->enabled = true;

    rule->services = talloc_zero(rule, struct hbac_rule_element);
    fail_if (rule->services == NULL);
    rule->services->category = HBAC_CATEGORY_ALL;
    rule->services->names = NULL;
    rule->services->groups = NULL;

    rule->users = talloc_zero(rule, struct hbac_rule_element);
    fail_if (rule->users == NULL);
    rule->users->category = HBAC_CATEGORY_ALL;
    rule->users->names = NULL;
    rule->users->groups = NULL;

    rule->targethosts = talloc_zero(rule, struct hbac_rule_element);
    fail_if (rule->targethosts == NULL);
    rule->targethosts->category = HBAC_CATEGORY_ALL;
    rule->targethosts->names = NULL;
    rule->targethosts->groups = NULL;

    rule->srchosts = talloc_zero(rule, struct hbac_rule_element);
    fail_if (rule->srchosts == NULL);
    rule->srchosts->category = HBAC_CATEGORY_ALL;
    rule->srchosts->names = NULL;
    rule->srchosts->groups = NULL;

    rule->timerules = talloc_zero(rule, struct hbac_time_rules);
    fail_if(rule->timerules == NULL);
    rule->timerules->accesstimes = NULL;

    *allow_rule = rule;
}

static void get_test_user(TALLOC_CTX *mem_ctx,
                          struct hbac_request_element **user)
{
    struct hbac_request_element *new_user;

    new_user = talloc_zero(mem_ctx, struct hbac_request_element);
    fail_if (new_user == NULL);

    new_user->name = talloc_strdup(new_user, HBAC_TEST_USER);
    fail_if(new_user->name == NULL);

    new_user->groups = talloc_array(new_user, const char *, 3);
    fail_if(new_user->groups == NULL);

    new_user->groups[0] = talloc_strdup(new_user->groups, HBAC_TEST_GROUP1);
    fail_if(new_user->groups[0] == NULL);

    new_user->groups[1] = talloc_strdup(new_user->groups, HBAC_TEST_GROUP2);
    fail_if(new_user->groups[1] == NULL);

    new_user->groups[2] = NULL;

    *user = new_user;
}

static void get_test_service(TALLOC_CTX *mem_ctx,
                             struct hbac_request_element **service)
{
    struct hbac_request_element *new_service;

    new_service = talloc_zero(mem_ctx, struct hbac_request_element);
    fail_if (new_service == NULL);

    new_service->name = talloc_strdup(new_service, HBAC_TEST_SERVICE);
    fail_if(new_service->name == NULL);

    new_service->groups = talloc_array(new_service, const char *, 3);
    fail_if(new_service->groups == NULL);

    new_service->groups[0] = talloc_strdup(new_service->groups, HBAC_TEST_SERVICEGROUP1);
    fail_if(new_service->groups[0] == NULL);

    new_service->groups[1] = talloc_strdup(new_service->groups, HBAC_TEST_SERVICEGROUP2);
    fail_if(new_service->groups[1] == NULL);

    new_service->groups[2] = NULL;

    *service = new_service;
}

static void get_test_srchost(TALLOC_CTX *mem_ctx,
                             struct hbac_request_element **srchost)
{
    struct hbac_request_element *new_srchost;

    new_srchost = talloc_zero(mem_ctx, struct hbac_request_element);
    fail_if (new_srchost == NULL);

    new_srchost->name = talloc_strdup(new_srchost, HBAC_TEST_SRCHOST);
    fail_if(new_srchost->name == NULL);

    new_srchost->groups = talloc_array(new_srchost, const char *, 3);
    fail_if(new_srchost->groups == NULL);

    new_srchost->groups[0] = talloc_strdup(new_srchost->groups,
                                           HBAC_TEST_SRCHOSTGROUP1);
    fail_if(new_srchost->groups[0] == NULL);

    new_srchost->groups[1] = talloc_strdup(new_srchost->groups,
                                           HBAC_TEST_SRCHOSTGROUP2);
    fail_if(new_srchost->groups[1] == NULL);

    new_srchost->groups[2] = NULL;

    *srchost = new_srchost;
}

static char *hbac_time_rules_err_string(TALLOC_CTX *ctx, errno_t expected,
                                        errno_t result, struct hbac_info *info,
                                        const char *time_str, const char *rule)
{
    return talloc_asprintf(ctx,
                          "Expected [%s], got [%s]; "
                          "Error: [%s]\n"
                          "Current time: [%s]\n"
                          "Time rule:\n%s",
                          hbac_result_string(expected),
                          hbac_result_string(result),
                          info ? hbac_error_string(info->code) : "Unknown",
                          time_str,
                          rule);
}

static char *
strftime_with_ctx(TALLOC_CTX *ctx, const char *fmt, struct tm *t)
{
    char tmp[100];

    if (strftime(tmp, 100*sizeof(char), fmt, t) == 0)
        return NULL;

    return (char *)talloc_strdup(ctx, tmp);
}

START_TEST(ipa_hbac_test_allow_all)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    fail_if (eval_req == NULL);

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    fail_if (rules == NULL);

    get_allow_all_rule(rules, &rules[0]);
    rules[0]->name = talloc_strdup(rules[0], "Allow All");
    fail_if(rules[0]->name == NULL);
    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;
    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_user)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    fail_if (eval_req == NULL);

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    fail_if (rules == NULL);

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a specific user */
    rules[0]->name = talloc_strdup(rules[0], "Allow user");
    fail_if(rules[0]->name == NULL);
    rules[0]->users->category = HBAC_CATEGORY_NULL;

    rules[0]->users->names = talloc_array(rules[0], const char *, 2);
    fail_if(rules[0]->users->names == NULL);

    rules[0]->users->names[0] = HBAC_TEST_USER;
    rules[0]->users->names[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->users->names[0] = HBAC_TEST_INVALID_USER;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_utf8)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    fail_if (eval_req == NULL);

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Override the with UTF8 values */
    eval_req->user->name = (const char *) &user_utf8_lowcase;
    eval_req->srchost->name = (const char *) &srchost_utf8_lowcase;
    eval_req->service->name = (const char *) &service_utf8_lowcase;

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    fail_if (rules == NULL);

    get_allow_all_rule(rules, &rules[0]);

    rules[0]->name = talloc_strdup(rules[0], "Allow user");
    fail_if(rules[0]->name == NULL);
    rules[0]->users->category = HBAC_CATEGORY_NULL;

    /* Modify the rule to allow only a specific user */
    rules[0]->users->names = talloc_array(rules[0], const char *, 2);
    fail_if(rules[0]->users->names == NULL);

    rules[0]->users->names[0] = (const char *) &user_utf8_upcase;
    rules[0]->users->names[1] = NULL;

    /* Modify the rule to allow only a specific service */
    rules[0]->services->category = HBAC_CATEGORY_NULL;

    rules[0]->services->names = talloc_array(rules[0], const char *, 2);
    fail_if(rules[0]->services->names == NULL);

    rules[0]->services->names[0] = (const char *) &service_utf8_upcase;
    rules[0]->services->names[1] = NULL;

    /* Modify the rule to allow only a specific service */
    rules[0]->srchosts->category = HBAC_CATEGORY_NULL;

    rules[0]->srchosts->names = talloc_array(rules[0], const char *, 2);
    fail_if(rules[0]->services->names == NULL);

    rules[0]->srchosts->names[0] = (const char *) &srchost_utf8_upcase;
    rules[0]->srchosts->names[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;


    /* Negative test - a different letter */
    rules[0]->users->names[0] = (const char *) &user_utf8_lowcase_neg;

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test - Turkish dotless i. We cannot know that capital I
     * casefolds into dotless i unless we know the language is Turkish */
    eval_req->user->name = (const char *) &user_lowcase_tr;
    rules[0]->users->names[0] = (const char *) &user_upcase_tr;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_group)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    fail_if (eval_req == NULL);

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    fail_if (rules == NULL);

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a group of users */
    rules[0]->name = talloc_strdup(rules[0], "Allow group");
    fail_if(rules[0]->name == NULL);
    rules[0]->users->category = HBAC_CATEGORY_NULL;

    rules[0]->users->names = NULL;
    rules[0]->users->groups = talloc_array(rules[0], const char *, 2);
    fail_if(rules[0]->users->groups == NULL);

    rules[0]->users->groups[0] = HBAC_TEST_GROUP1;
    rules[0]->users->groups[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->users->groups[0] = HBAC_TEST_INVALID_GROUP;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_svc)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    fail_if (eval_req == NULL);

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    fail_if (rules == NULL);

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a specific service */
    rules[0]->name = talloc_strdup(rules[0], "Allow service");
    fail_if(rules[0]->name == NULL);
    rules[0]->services->category = HBAC_CATEGORY_NULL;

    rules[0]->services->names = talloc_array(rules[0], const char *, 2);
    fail_if(rules[0]->services->names == NULL);

    rules[0]->services->names[0] = HBAC_TEST_SERVICE;
    rules[0]->services->names[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->services->names[0] = HBAC_TEST_INVALID_SERVICE;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_svcgroup)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    fail_if (eval_req == NULL);

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    fail_if (rules == NULL);

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a group of users */
    rules[0]->name = talloc_strdup(rules[0], "Allow servicegroup");
    fail_if(rules[0]->name == NULL);
    rules[0]->services->category = HBAC_CATEGORY_NULL;

    rules[0]->services->names = NULL;
    rules[0]->services->groups = talloc_array(rules[0], const char *, 2);
    fail_if(rules[0]->services->groups == NULL);

    rules[0]->services->groups[0] = HBAC_TEST_SERVICEGROUP1;
    rules[0]->services->groups[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->services->groups[0] = HBAC_TEST_INVALID_SERVICEGROUP;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_srchost)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    fail_if (eval_req == NULL);

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    fail_if (rules == NULL);

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a specific service */
    rules[0]->name = talloc_strdup(rules[0], "Allow srchost");
    fail_if(rules[0]->name == NULL);
    rules[0]->srchosts->category = HBAC_CATEGORY_NULL;

    rules[0]->srchosts->names = talloc_array(rules[0], const char *, 2);
    fail_if(rules[0]->srchosts->names == NULL);

    rules[0]->srchosts->names[0] = HBAC_TEST_SRCHOST;
    rules[0]->srchosts->names[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->srchosts->names[0] = HBAC_TEST_INVALID_SRCHOST;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_srchostgroup)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    fail_if (eval_req == NULL);

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    fail_if (rules == NULL);

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a group of users */
    rules[0]->name = talloc_strdup(rules[0], "Allow srchostgroup");
    fail_if(rules[0]->name == NULL);
    rules[0]->srchosts->category = HBAC_CATEGORY_NULL;

    rules[0]->srchosts->names = NULL;
    rules[0]->srchosts->groups = talloc_array(rules[0], const char *, 2);
    fail_if(rules[0]->srchosts->groups == NULL);

    rules[0]->srchosts->groups[0] = HBAC_TEST_SRCHOSTGROUP1;
    rules[0]->srchosts->groups[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->srchosts->groups[0] = HBAC_TEST_INVALID_SRCHOSTGROUP;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_accesstime)
{

    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    struct tm *tm_now;
    char *now_str;
    bool is_valid;
    uint32_t missing_attrs;

    /* Mon, 18 Apr 2016 07:39:57 UTC */
    time_t tstamp = 1460965197;
    char ical_head[] = "BEGIN:VCALENDAR\r\n"
                       "PRODID:-//The Company//iCal4j 1.0//EN\r\n"
                       "VERSION:2.0\r\n"
                       "METHOD:REQUEST\r\n"
                       "BEGIN:VEVENT\r\n"
                       "UID:1@company.org\r\n"
                       "DTSTAMP:20160406T112129Z\r\n";

    char ical_tail[] = "END:VEVENT\r\n"
                       "END:VCALENDAR\r\n";


    const int NUM_ALLOW_RULES = 14;
    const int NUM_DENY_RULES = 16;

    const char *allow_rules[] = {
        /* 1 DTSTART with DATE-TIME value */
        "DTSTART:20160418T073957Z\r\n",
        /* 2 DTSTART with DATE value */
        "DTSTART;VALUE=DATE:20160418\r\n",
        /* 3 DTSTART and DTEND, DATE-TIME values, in time-zones */
        "DTSTART:20160310T101500Z\r\nDTEND;TZID=CET:20160418T093958\r\n",
        /* 4 DTSTART and DTEND, DATE values */
        "DTSTART;VALUE=DATE:20160310\r\nDTEND;VALUE=DATE:20160419\r\n",
        /* 5 DTSTART as DATE-TIME and DURATION */
        "DTSTART:20160410T063600Z\r\nDURATION:P8DT1H3M58S\r\n",
        /* 6 DTSTART as DATE and DURATION */
        "DTSTART:20160401\r\nDURATION:P3W\r\n",
        /* 7 RDATE with PERIOD values */
        "DTSTART:20100101T000000Z\r\nRDATE;VALUE=PERIOD:20100101T000000Z/PT1S,"
        " 20150418T073957Z/P366DT1S\r\n",
        /* 8 RDATE with DATE-TIME values, time-zoned */
        "DTSTART;TZID=CET:19900522T000000\r\n"
        "RDATE;TZID=CET:19900522T000000,20000202T200202,"
        " 20160418T093957\r\n",
        /* 9 RDATE with DATE values */
        "DTSTART;VALUE=DATE:19891117\r\nRDATE;VALUE=DATE:19891117,20200202,"
        " 20160418\r\n",
        /* 10 RDATE and EXDATE */
        "DTSTART:19951010T195110Z\r\n"
        "RDATE: 19951010T195110Z, 20051010T195110Z, 20160418T073957Z\r\n"
        "EXDATE:20051010T195110Z, 20160418T093957Z\r\n",
        /* 11 RRULE */
        "DTSTART:20101115T083957Z\r\n"
        "RRULE:FREQ=YEARLY;INTERVAL=1;BYMONTH=4,11;BYDAY=MO;BYHOUR=7,8\r\n",
        /* 12 RRULE: EXDATE cancels intermediate event */
        "DTSTART:20101115T083957Z\r\n"
        "RRULE:FREQ=YEARLY;INTERVAL=1;BYMONTH=4,11;BYDAY=MO;BYHOUR=7,8\r\n"
        "EXDATE:20141117T083957Z\r\n",
        /* 13 RRULE with DTSTART+DTEND */
        "DTSTART:20101115T050000Z\r\n"
        "DTEND:20101115T070000Z\r\n"
        "RRULE:FREQ=MONTHLY;INTERVAL=5;BYDAY=MO;BYHOUR=5,6\r\n",
        /* 14 RRULE with DTSTART+DTEND, EXDATE cancels first matching event */
        "DTSTART:20101115T050000Z\r\n"
        "DTEND:20101115T070000Z\r\n"
        "RRULE:FREQ=MONTHLY;INTERVAL=5;BYDAY=MO,TU,WE;BYHOUR=5,6,7\r\n"
        "EXDATE: 20160418T060000Z\r\n",
    };

    const char *noallow_rules[] = {
        /* 1 DTSTART with DATE-TIME value */
        "DTSTART:20160418T093957Z\r\n",
        /* 2 DTSTART with DATE value */
        "DTSTART;VALUE=DATE:20160419\r\n",
        /* 3 DTSTART and DTEND, DATE-TIME values, in time-zones */
        "DTSTART:20160310T101500Z\r\nDTEND;TZID=CET:20160418T093957\r\n",
        /* 4 DTSTART and DTEND, DATE values */
        "DTSTART;VALUE=DATE:20160310\r\nDTEND;VALUE=DATE:20160418\r\n",
        /* 5 DTSTART and DURATION */
        "DTSTART:20160410T063600Z\r\nDURATION:P8DT1H\r\n",
        /* 6 DTSTART as DATE and DURATION */
        "DTSTART:20160401\r\nDURATION:P2W\r\n",
        /* 7 RDATE with PERIOD values */
        "DTSTART:20100101T000000Z\r\nRDATE;VALUE=PERIOD:20100101T000000Z/PT1S,"
        " 20150418T073957Z/P366D\r\n",
        /* 8 RDATE with DATE-TIME values */
        "DTSTART;TZID=CET:19900522T000000\r\n"
        "RDATE:19900522T000000Z,20000202T200202Z, 20160418T093957Z\r\n",
        /* 9 RDATE with DATE values */
        "DTSTART;VALUE=DATE:19891117\r\nRDATE;VALUE=DATE:19891117,20200202,"
        " 20160419\r\n",
        /* 10 RDATE with EXDATE */
        "DTSTART;VALUE=DATE:19891117\r\n"
        "RDATE;VALUE=DATE:19891117, 20200202, 20160418\r\n"
        "EXDATE;VALUE=DATE:20160418\r\n",
        /* 11 RDATE with EXDATE - DATE-TIME values */
        "DTSTART;TZID=America/New_York:19951010T195110\r\n"
        "RDATE: 19951010T195110Z, 20051010T195110Z, 20160418T073957Z\r\n"
        "EXDATE:20051010T195110Z, 20160418T073957Z\r\n",
        /* 12 RDATE: EXDATE to exclude DTSTART date */
        "DTSTART;VALUE=DATE:20160418\r\n"
        "RDATE;VALUE=DATE:19891117,20200202, 20160418\r\n"
        "EXDATE;VALUE=DATE:20160418\r\n",
        /* 13 RRULE */
        "DTSTART:20101115T083957Z\r\n"
        "RRULE:FREQ=YEARLY;BYMONTH=4,11;BYDAY=MO\r\n",
        /* 14 RRULE: EXDATE cancels the right event */
        "DTSTART:20101115T083957Z\r\n"
        "RRULE:FREQ=YEARLY;INTERVAL=1;BYMONTH=4,11;BYDAY=MO;BYHOUR=7,8\r\n"
        "EXDATE:20160418T073957Z\r\n",
        /* 15 RRULE with DTSTART+DTEND */
        "DTSTART:20101115T050000Z\r\n"
        "DTEND:20101115T070000Z\r\n"
        "RRULE:FREQ=MONTHLY;INTERVAL=5;BYDAY=MO,TU,WE;BYHOUR=1,5\r\n",
        /* 16 RRULE with DTSTART+DTEND and cancelling EXDATE */
        "DTSTART:20101115T050000Z\r\n"
        "DTEND:20101115T070000Z\r\n"
        "RRULE:FREQ=MONTHLY;INTERVAL=5;BYDAY=MO,TU,WE;BYHOUR=5,6\r\n"
        "EXDATE: 20160418T060000Z\r\n",
    };

    test_ctx = talloc_new(global_talloc_context);

    tm_now = localtime(&tstamp);
    now_str = strftime_with_ctx(test_ctx, "%Y%m%dT%H%M%S", tm_now);

    /* Create a requset */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    fail_if(eval_req == NULL);

    //tstamp = time(NULL);
    fail_if(tstamp == -1);

    eval_req->request_time = tstamp;

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Rules array for evaluation */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    fail_if(rules == NULL);

    /* Will use only one rule at a time */
    rules[1] = NULL;

    get_allow_all_rule(rules, &rules[0]);

    /* Preparations of the rule for time rules addition */
    rules[0]->name = talloc_strdup(rules[0], "Timed rule");
    fail_if(rules[0]->name == NULL);

    rules[0]->timerules = talloc_zero(rules[0], struct hbac_time_rules);
    fail_if(rules[0]->timerules == NULL);

    rules[0]->timerules->accesstimes = talloc_array(rules[0]->timerules,
                                                    const char *, 4);
    fail_if(rules[0]->timerules->accesstimes == NULL);

    /* Evaluating one time rule at a time */
    rules[0]->timerules->accesstimes[1] = NULL;
    for(int i = 0; i < NUM_DENY_RULES; i++) {
        /* No-allow time rule */
        rules[0]->timerules->accesstimes[0] = talloc_asprintf(test_ctx,
                                                              "%s%s%s",
                                                              ical_head,
                                                              noallow_rules[i],
                                                              ical_tail);;
        /* Validate the rule */
        is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
        fail_unless(is_valid);
        fail_unless(missing_attrs == 0);

        /* No-allow time rule */
        result = hbac_evaluate(rules, eval_req, &info);
        fail_unless(result == HBAC_EVAL_DENY,
                    hbac_time_rules_err_string(test_ctx, HBAC_EVAL_DENY,
                                               result, info, now_str,
                                               rules[0]->timerules->accesstimes[0])
                    );
        hbac_free_info(info);
        info = NULL;
    }

    for(int i = 0; i < NUM_ALLOW_RULES; i++) {
        /* Allow time rule */
        rules[0]->timerules->accesstimes[0] = talloc_asprintf(test_ctx,
                                                              "%s%s%s",
                                                              ical_head,
                                                              allow_rules[i],
                                                              ical_tail);
        /* Validate the rule */
        is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
        fail_unless(is_valid);
        fail_unless(missing_attrs == 0);

        /* Evaluate the rule */
        result = hbac_evaluate(rules, eval_req, &info);
        fail_unless(result == HBAC_EVAL_ALLOW,
                    hbac_time_rules_err_string(test_ctx, HBAC_EVAL_ALLOW,
                                               result, info, now_str,
                                               rules[0]->timerules->accesstimes[0])
                   );
        hbac_free_info(info);
        info = NULL;
    }

    const char two_events_allow[] =
            /* first, non-allow part */
            "DTSTART:20101115T050000Z\r\n"
            "DTEND:20101115T070000Z\r\n"
            "RRULE:FREQ=MONTHLY;INTERVAL=5;BYDAY=MO,TU,WE;BYHOUR=5,6\r\n"
            "EXDATE: 20160418T060000Z\r\n"
            "END:VEVENT\r\n"
            /* second, allow part */
            "BEGIN:VEVENT\r\n"
            "UID:1@darkside.com\r\n"
            "DTSTAMP:20160406T112129Z\r\n"
            "DTSTART:20101115T050000Z\r\n"
            "DTEND:20101115T070000Z\r\n"
            "RRULE:FREQ=MONTHLY;INTERVAL=5;BYDAY=MO;BYHOUR=5,6\r\n";

    rules[0]->timerules->accesstimes[0] = talloc_asprintf(test_ctx,
                                                          "%s%s%s",
                                                          ical_head,
                                                          two_events_allow,
                                                          ical_tail);
    /* Validate the rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rule */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_ALLOW,
                hbac_time_rules_err_string(test_ctx, HBAC_EVAL_ALLOW,
                                           result, info, now_str,
                                           rules[0]->timerules->accesstimes[0])
             );
    hbac_free_info(info);
    info = NULL;

    const char two_events_noallow[] =
            /* nonmatching TDATE */
            "DTSTART;VALUE=DATE:19891117\r\n"
            "RDATE;VALUE=DATE:19891117,20200202,20160419\r\n"
            "END:VEVENT\r\n"
            /* duration too short  */
            "BEGIN:VEVENT\r\n"
            "UID:1@darkside.com\r\n"
            "DTSTAMP:20160406T112129Z\r\n"
            "DTSTART:20160401\r\nDURATION:P2W\r\n";

    rules[0]->timerules->accesstimes[0] = talloc_asprintf(test_ctx,
                                                          "%s%s%s",
                                                          ical_head,
                                                          two_events_noallow,
                                                          ical_tail);
    /* Validate the rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    fail_unless(is_valid);
    fail_unless(missing_attrs == 0);

    /* Evaluate the rule */
    result = hbac_evaluate(rules, eval_req, &info);
    fail_unless(result == HBAC_EVAL_DENY,
                hbac_time_rules_err_string(test_ctx, HBAC_EVAL_DENY,
                                           result, info, now_str,
                                           rules[0]->timerules->accesstimes[0])
             );
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_incomplete)
{
    TALLOC_CTX *test_ctx;
    struct hbac_rule *rule;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    rule = talloc_zero(test_ctx, struct hbac_rule);

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rule, &missing_attrs);
    fail_if(is_valid);
    fail_unless(missing_attrs | HBAC_RULE_ELEMENT_USERS);
    fail_unless(missing_attrs | HBAC_RULE_ELEMENT_SERVICES);
    fail_unless(missing_attrs | HBAC_RULE_ELEMENT_TARGETHOSTS);
    fail_unless(missing_attrs | HBAC_RULE_ELEMENT_SOURCEHOSTS);

    talloc_free(test_ctx);
}
END_TEST

Suite *hbac_test_suite (void)
{
    Suite *s = suite_create ("HBAC");

    TCase *tc_hbac = tcase_create("HBAC_rules");
    tcase_add_checked_fixture(tc_hbac,
                              ck_leak_check_setup,
                              ck_leak_check_teardown);

    tcase_add_test(tc_hbac, ipa_hbac_test_allow_all);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_user);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_group);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_svc);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_svcgroup);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_srchost);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_srchostgroup);
    tcase_add_test(tc_hbac, ipa_hbac_test_accesstime);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_utf8);
    tcase_add_test(tc_hbac, ipa_hbac_test_incomplete);

    suite_add_tcase(s, tc_hbac);
    return s;
}

int main(int argc, const char *argv[])
{
    int number_failed;

    tests_set_cwd();

    Suite *s = hbac_test_suite();
    SRunner *sr = srunner_create(s);

    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
