/*
    SSSD

    IPA Provider - Time Rules Parsing

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

#ifndef IPA_TIMERULES_H_
#define IPA_TIMERULES_H_

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#endif

errno_t
hbac_evaluate_time_rules(struct hbac_time_rules *rule,
                         time_t req_time,
                         bool *matched);


#endif
