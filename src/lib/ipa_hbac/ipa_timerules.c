/*
    SSSD

    IPA Provider - Time Rules Evaluation

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

#define _XOPEN_SOURCE 500  /* for lstat and readlink */
#include <stdlib.h>
#include <errno.h>  /* for ENOMEM in c89 */
#include <time.h>
#include <unistd.h> /* for readlink() */
#include <limits.h> /* for PATH_MAX */
#include <sys/stat.h> /* to determine if /ect/localtime is a link */
#include <string.h>
#include <libical/ical.h>
#include "ipa_hbac.h"
#include "ipa_timerules.h"
#include "util/sss_utf8.h"

#define MAX_TZNAME_LEN 50

static errno_t
eval_time_rule(const char * rule,
               icaltimetype now,
               bool *matched);

icaltimezone *get_icaltimezone(void);
int icaltime_compare_patched(icaltimetype a, icaltimetype b);
char *get_olson_timezone(void);

errno_t
hbac_evaluate_time_rules(struct hbac_time_rules *rule,
                    time_t req_time,
                    bool *matched)
{
    errno_t ret = EOK;
    char *zone_str = NULL;
    icaltimezone *zone;
    icaltimetype now;
    int i;  /* array of timerules iterator */

    /* No access time policies = always match */
    if (!rule->accesstimes || !rule->accesstimes[0]) {
        *matched = true;
        return EOK;
    }

    if((zone_str = get_olson_timezone()) == NULL) {
        return ENOMEM;
    }
    zone = icaltimezone_get_builtin_timezone(zone_str);

    /* libical is rather weird and creates 'floating' time first */
    now = icaltime_from_timet_with_zone(req_time, 0, zone);
    now = icaltime_convert_to_zone(now, zone);
    for (i = 0; rule->accesstimes[i]; i++) {
        ret = eval_time_rule(rule->accesstimes[i], now, matched);
        if (ret != EOK) {
            *matched = false;
            ret = ENOMATCH;
            goto done;
        }
        else if (*matched == true) {
            ret = EOK;
            goto done;
        }
    }

done:
    if (zone_str != NULL)
    {
        free(zone_str);
    }
    /* the following frees zone variable as well */
    icaltimezone_free_builtin_timezones();
    return ret;
}

bool
icaltime_in_range(icaltimetype t,
                  icaltimetype b1,
                  icaltimetype b2);

bool
icaltime_in_exdate(icalcomponent *c,
                   icaltimetype t);

icaltimetype
icaltime_from_datetime_property(icalproperty *p,
                               icaltimetype (*get_icaltime)(const icalproperty *));

struct icaldatetimeperiodtype
icaldatetimeperiod_from_property(
       icalproperty *p,
       struct icaldatetimeperiodtype (*get_icaltime)(const icalproperty *)
);

static errno_t
eval_rrule(icalcomponent *vevent,
           struct icalrecurrencetype *recur,
           icaltimetype rule_start,
           struct icaldurationtype rule_duration,
           icaltimetype now,
           bool *matched);

static errno_t
eval_time_rule(const char * rule,
               icaltimetype now,
               bool *matched)
{
    icalcomponent *c;
    icalcomponent *vevent;
    icalproperty *dtstart;
    icalproperty *dtend;
    icalproperty *rrule;
    icalproperty *duration;
    icalproperty *rdate;
    struct icalrecurrencetype recur;
    struct icaldatetimeperiodtype rdate_val;
    icaltimetype rule_start;
    icaltimetype rule_end;
    struct icaldurationtype rule_duration;
    errno_t ret;

    *matched = false;
    /* icalcomponent_isa returns the kind of the given component */
    if ((c = icalparser_parse_string(rule)) == NULL
         || icalcomponent_count_errors(c)
         || icalcomponent_isa(c) != ICAL_VCALENDAR_COMPONENT)
    {
        return ENOMATCH;
    }

    /* Go through all the VEVENTs in VCALENDAR */
    for (vevent = icalcomponent_get_first_component(c, ICAL_VEVENT_COMPONENT);
         vevent != NULL;
         vevent = icalcomponent_get_next_component(c, ICAL_VEVENT_COMPONENT))
    {
        dtstart = icalcomponent_get_first_property(vevent, ICAL_DTSTART_PROPERTY);
        dtend = icalcomponent_get_first_property(vevent, ICAL_DTEND_PROPERTY);
        rrule = icalcomponent_get_first_property(vevent, ICAL_RRULE_PROPERTY);
        rdate = icalcomponent_get_first_property(vevent, ICAL_RDATE_PROPERTY);
        duration = icalcomponent_get_first_property(vevent, ICAL_DURATION_PROPERTY);
        rdate = icalcomponent_get_first_property(vevent, ICAL_RDATE_PROPERTY);

        if (dtstart == NULL) {
            return ENOMATCH;
        }

        rule_start = icaltime_from_datetime_property(dtstart,
                                                     icalproperty_get_dtstart);

        if (dtend && duration) {
            /* DTEND and DURATION can't appear both in one VEVENT */
            return ENOMATCH;
        }

        if (dtend) {
            rule_end = icaltime_from_datetime_property(dtend,
                                                       icalproperty_get_dtend);

            if (icaltime_is_date(rule_end) != icaltime_is_date(rule_start)) {
                /* DTEND and DTSTART need to have the same value type */
                return ENOMATCH;
            }
            /* Save duration of the event */
            rule_duration = icaltime_subtract(rule_end, rule_start);
        }
        else if (duration) {
            rule_duration = icalproperty_get_duration(duration);
            /* duration must be only dur-week or dur-day if DTSTART date value*/
            if (icaltime_is_date(rule_start) && (rule_duration.hours
                    || rule_duration.minutes || rule_duration.seconds))
            {
                return ENOMATCH;
            }
            rule_end = icaltime_add(rule_start, rule_duration);
        }
        else {
            rule_duration = icaldurationtype_from_int(0);
            if (rule_start.is_date == 1) {
                /*
                 * if rule_start is date, default duration is 1 day,
                 * 0 seconds otherwise
                 */
                rule_duration.days++;
            }
            rule_end = icaltime_add(rule_start, rule_duration);
        }

        if (icaldurationtype_is_bad_duration(rule_duration)
            || rule_duration.is_neg == 1)
        {
            /* Negative or wrong duration */
            return ENOMATCH;
        }

        if (icaltime_in_range(now, rule_start, rule_end)) {
            *matched = true;
        }

        if (!rrule && !rdate) {
            /* neither RRULE or RDATE appears, dont't take EXDATE in account */
            return EOK;
        }
        else if (*matched && !icaltime_in_exdate(vevent, rule_start)) {
            /* Either no EXDATE or it did not match any EXDATE */
            return EOK;
        }
        *matched = false; /* if DTSTART matched but was also in EXDATE */

        if (rdate) {
            /* we already got first RDATE loaded */
            do {
                rdate_val = icaldatetimeperiod_from_property(
                        rdate, icalproperty_get_rdate);
                if (icaltime_is_null_time(rdate_val.time)) {
                    /* this RDATE is of PERIOD type */
                    icaltimetype period_start = rdate_val.period.start;
                    icaltimetype period_end;
                    if (icaltime_is_null_time(rdate_val.period.end)) {
                        /* end is of DURATION type */
                        period_end = icaltime_add(period_start,
                                                  rdate_val.period.duration);
                    }
                    else {
                        period_end = rdate_val.period.end;
                    }
                    if (icaltime_in_range(now, period_start, period_end)
                        && !icaltime_in_exdate(vevent, period_start))
                    {
                        *matched = true;
                        return EOK;
                    }
                }  /* if (icaltime_is_null_time())*/
                else {
                    /* this RDATE is of DATE/DATE-TIME type */
                    if (icaltime_in_range(
                            now, rdate_val.time,
                            icaltime_add(rdate_val.time, rule_duration)
                            )
                        && !icaltime_in_exdate(vevent, rdate_val.time))
                   {
                       *matched = true;
                       return EOK;
                   }
                }
            } while ((rdate = icalcomponent_get_next_property(
                            vevent, ICAL_RDATE_PROPERTY)) != NULL);
        }  /* if (rdate) */

        if (rrule) {
            recur = icalproperty_get_rrule(rrule);
            if ((ret = eval_rrule(vevent, &recur, rule_start, rule_duration,
                                  now, matched)) != EOK)
            {
                return ret;
            }
            if (*matched == true) {
                return EOK;
            }
        }  /* if rrule */
        /* continue with the next VEVENT component in case of no match here */
    }  /* for vevent = icalcomponent_get_first ... */

    return EOK;
}

/*
 * libical 1.0.1 icaltime_compare() is tainted as both of the compared times
 * are converted to UTC before comparison. This results in possible
 * misrepresentation of floating time which should be time zone independent.
 * A fix to this is to convert the floating time to the same zone as is the
 * other compared time.
 */
int icaltime_compare_patched(icaltimetype a, icaltimetype b)
{
    icaltimetype cmp_a;
    icaltimetype cmp_b;
    cmp_a = a;
    cmp_b = b;

/*
 * The compiler would rant about discarding const although that should not be
 * a problem here
 */
 #pragma GCC diagnostic push
 #pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
    if (a.zone != b.zone) {
        if (a.zone == NULL && !a.is_utc) {
            cmp_a = icaltime_convert_to_zone(a, b.zone);
        }
        else if (b.zone == NULL && !b.is_utc) {
            cmp_b = icaltime_convert_to_zone(b, a.zone);
        }
    }
#pragma GCC diagnostic push
    return icaltime_compare(cmp_a, cmp_b);
}

/*
 * Gets Olson Time Zone name from /etc/localtime or /etc/timezone depending
 * whether this's Red Hat or Debian distribution.
 *
 * The returned string needs to be freed.
 */
char *get_olson_timezone(void)
{
    const char *tzdir = "zoneinfo";
    char *path;
    char *token;
    char *result;
    struct stat file_stat;
    FILE *tzfile = NULL;

    if((path = (char *)calloc(PATH_MAX + 1, sizeof(char))) == NULL) {
        return NULL;
    }

    if((result = (char *)calloc(PATH_MAX + 1, sizeof(char))) == NULL) {
        free(path);
        return NULL;
    }

    if (lstat("/etc/localtime", &file_stat) == -1) {
        /* Problems accessing the time zone file */
        goto err;
    }

    if (S_ISLNK(file_stat.st_mode)) {
        /*
         *If the file is a link, this is either Red Hat-like distribution or
         * older Debian-like distribution
         */
        if(readlink("/etc/localtime", path, PATH_MAX) == -1)
        {
            goto err;
        }
    }
    else {
        /* /etc/localtime is not a link -> newer Debian-like distribution */
        /* There should be a /etc/timezone file */
        if ((tzfile = fopen("/etc/timezone", "r")) == NULL) {
            goto err;
        }
        if (fread(path, sizeof(char), PATH_MAX, tzfile) == 0 || ferror(tzfile))
        {
            /* error reading /etc/timezone file */
            goto err;
        }
        fclose(tzfile);
        tzfile = NULL;
    }

    token = strtok(path, "/");
    do {
        if (strncmp(tzdir, (const char *)token, strlen(tzdir)) == 0) {
            while ((token = strtok(NULL, "/")) != NULL)
            {
                strcat(result, token);
                strcat(result, "/");
            }
            /* Remove last '/' */
            result[strlen(result)-1] = '\0';
            free(path);
            return result;
        }
    } while ((token = strtok(NULL, "/")) != NULL);

err:
    if (tzfile != NULL) {
        fclose(tzfile);
    }
    free(path);
    free(result);
    return NULL;
}


/*
 * Get icaltimetype correctly converted to a timezone according to the
 * TZID parameter set at the according property
 */
icaltimetype
icaltime_from_datetime_property(icalproperty *p,
                                icaltimetype (*get_icaltime)(const icalproperty *))
{
    icaltimetype ret;
    icalparameter *param;

    ret = get_icaltime(p);
    param = icalproperty_get_first_parameter(p, ICAL_TZID_PARAMETER);
    if (param != NULL && !icaltime_is_date(ret)) {
        icaltimezone *zone;
        zone = icaltimezone_get_builtin_timezone(icalparameter_get_tzid(param));
        ret = icaltime_convert_to_zone(ret, zone);
    }
    return ret;
}

/*
 * Get icaldatetimeperiodtype correctly converted to a timezone according to the
 * TZID parameter set at the according property
 */
struct icaldatetimeperiodtype
icaldatetimeperiod_from_property(
        icalproperty *p,
        struct icaldatetimeperiodtype (*get_icaltime)(const icalproperty *)
)
{
    struct icaldatetimeperiodtype ret;
    icalparameter *param;

    ret = get_icaltime(p);
    param = icalproperty_get_first_parameter(p, ICAL_TZID_PARAMETER);

    if (param == NULL) {
        return ret;
    }

    icaltimezone *zone;
    zone = icaltimezone_get_builtin_timezone(icalparameter_get_tzid(param));
    if (!icaltime_is_null_time(ret.time)) {
        /* The property is of either DATE of DATE-TIME type */
        icaltimetype tmp = ret.time;
        tmp = icaltime_convert_to_zone(tmp, zone);
        ret.time = tmp;

    }
    else {
        /* The property is of PERIOD type */
        icaltimetype tmp = ret.period.start;
        tmp = icaltime_convert_to_zone(tmp, zone);
        ret.period.start = tmp;
        tmp = ret.period.end;
        tmp = icaltime_convert_to_zone(tmp, zone);
        ret.period.end = tmp;
    }
    return ret;
}


/*
 * Returns true if t lies in interval <b1, b2)
 */
bool
icaltime_in_range(icaltimetype t,
                  icaltimetype b1,
                  icaltimetype b2)
{
    int tmp_res;
    if (((tmp_res = icaltime_compare_patched(t, b1)) > 0
                && icaltime_compare_patched(t, b2) < 0
        ) || tmp_res == 0)
    {
        return true;
    }
    return false;
}

/*
 * Returns true if t is a date/date-time among EXDATE values
 */
bool
icaltime_in_exdate(icalcomponent *c,
                   icaltimetype t)
{
    icalproperty *exdate;
    for (exdate = icalcomponent_get_first_property(
                                    c, ICAL_EXDATE_PROPERTY);
         exdate != NULL;
         exdate= icalcomponent_get_next_property(c, ICAL_EXDATE_PROPERTY))
     {
         icaltimetype exdate_time = icalproperty_get_exdate(exdate);
         if (icaltime_compare_patched(exdate_time, t) == 0) {
             return true;
         }
     }
     return false;
}

/*
 * Evaluates RRULE property
 *
 * @param vevent        The VEVENT component containing the RRULE
 * @param recur         Structure with the information from RRULE from vevent
 * @param rule_start    Structure with information about the vevent's DTSTART
 * @param duration      Duration of the event (same for all generated event of
 *                      one RRULE)
 * @param now           The time to compare against
 * @param matched       Flag whether the time from now matched any occurence
 */
static errno_t
eval_rrule(icalcomponent *vevent,
           struct icalrecurrencetype *recur,
           icaltimetype rule_start,
           struct icaldurationtype rule_duration,
           icaltimetype now,
           bool *matched)
{
    icaltimetype rec_event;
    icalrecur_iterator *rec_it = NULL;

    rec_it = icalrecur_iterator_new(*recur, rule_start);
    if (!rec_it) {
        return ENOMEM;
    }

    /*
     * Iterate through the recurring events defined by RRULE and check
     * if current time falls in the event span
     */
    for (rec_event = icalrecur_iterator_next(rec_it);
        !icaltime_is_null_time(rec_event);
        rec_event = icalrecur_iterator_next(rec_it))
    {
        /* icaltime_compare(a,b) returns -1, 0, 1 for a<b, a==b, a>b*/
        /* lower border greater than current time */
        int cmp_res;
        if ((cmp_res = icaltime_compare_patched(rec_event, now)) > 0) {
            *matched = false;
            if (rec_it) {
                icalrecur_iterator_free(rec_it);
            }
            return EOK;
        }

        /*
         * Current time is in the period of the recurrence or
         * matches recurrence start date (if no DTEND)
         */
        if ((cmp_res == 0
             || icaltime_compare_patched(
                    now, icaltime_add(rec_event, rule_duration)) < 0)
            && !icaltime_in_exdate(vevent, rec_event))
        {
            *matched = true;
            if (rec_it) {
                icalrecur_iterator_free(rec_it);
            }
            return EOK;
        }
    }  /* for icalrecur_iterator *rec_event ... */

    if (rec_it) {
        icalrecur_iterator_free(rec_it);
    }
    return EOK;
}