/*
 * Copyright (C) 1994-2020 Altair Engineering, Inc.
 * For more information, contact Altair at www.altair.com.
 *
 * This file is part of the PBS Professional ("PBS Pro") software.
 *
 * Open Source License Information:
 *
 * PBS Pro is free software. You can redistribute it and/or modify it under the
 * terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * PBS Pro is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Commercial License Information:
 *
 * For a copy of the commercial license terms and conditions,
 * go to: (http://www.pbspro.com/UserArea/agreement.html)
 * or contact the Altair Legal Department.
 *
 * Altair’s dual-license business model allows companies, individuals, and
 * organizations to create proprietary derivative works of PBS Pro and
 * distribute them - whether embedded or bundled with other software -
 * under a commercial license agreement.
 *
 * Use of Altair’s trademarks, including but not limited to "PBS™",
 * "PBS Professional®", and "PBS Pro™" and Altair’s logos is subject to Altair's
 * trademark licensing policies.
 *
 */


/**
 * @file	enc_attropl.c
 * @brief
 * encode_DIS_attropl() - encode a list of PBS API "attropl" structures
 *
 *	The first item encoded is a unsigned integer, a count of the
 *	number of attropl entries in the linked list.  This is encoded
 *	even when there are no attropl entries in the list.
 *
 * @par Each individual entry is then encoded as:
 *		u int	size of the three strings (name, resource, value)
 *			including the terminating nulls
 *		string	attribute name
 *		u int	1 or 0 if resource name does or does not follow
 *		string	resource name (if one)
 *		string  value of attribute/resource
 *		u int	"op" of attrlop
 * @note
 *	the encoding of a attropl is the same as the encoding of
 *	the pbs_ifl.h structures "attrl" and the server svrattrl.  Any
 *	one of the three forms can be decoded into any of the three with the
 *	possible loss of the "flags" field (which is the "op" of the attrlop).
 */

#include <pbs_config.h>   /* the master config generated by configure */

#include "pbs_ifl.h"
#include "dis.h"

/**
 * @brief
 *	- encode a list of PBS API "attropl" structures
 *
 * @par	Note:
 *	The first item encoded is a unsigned integer, a count of the
 *      number of attropl entries in the linked list.  This is encoded
 *      even when there are no attropl entries in the list.
 *
 * @par	 Each individual entry is then encoded as:\n
 *			u int   size of the three strings (name, resource, value)
 *                      	including the terminating nulls\n
 *			string  attribute name\n
 *			u int   1 or 0 if resource name does or does not follow\n
 *			string  resource name (if one)\n
 *			string  value of attribute/resource\n
 *			u int   "op" of attrlop\n
 *
 * @par	Note:
 *	the encoding of a attropl is the same as the encoding of
 *      the pbs_ifl.h structures "attrl" and the server svrattrl.  Any
 *      one of the three forms can be decoded into any of the three with the
 *      possible loss of the "flags" field (which is the "op" of the attrlop).
 *
 * @param[in] sock - socket id
 * @param[in] pattropl - pointer to attropl structure
 *
 * @return      int
 * @retval      DIS_SUCCESS(0)  success
 * @retval      error code      error
 *
 */

int
encode_DIS_attropl(int sock, struct attropl *pattropl)
{
	unsigned int ct = 0;
	unsigned int name_len;
	struct attropl *ps;
	int rc;

	/* count how many */

	for (ps = pattropl; ps; ps = ps->next) {
		++ct;
	}

	if ((rc = diswui(sock, ct)) != 0)
		return rc;

	for (ps = pattropl; ps; ps = ps->next) {
		/* length of three strings */
		name_len = (int)strlen(ps->name) + (int)strlen(ps->value) + 2;
		if (ps->resource)
			name_len += strlen(ps->resource) + 1;

		if ((rc = diswui(sock, name_len)) != 0)
			break;
		if ((rc = diswst(sock, ps->name)) != 0)
			break;
		if (ps->resource) { /* has a resource name */
			if ((rc = diswui(sock, 1)) != 0)
				break;
			if ((rc = diswst(sock, ps->resource)) != 0)
				break;
		} else {
			if ((rc = diswui(sock, 0)) != 0) /* no resource name */
				break;
		}
		if ((rc = diswst(sock, ps->value))	||
			(rc = diswui(sock, (unsigned int)ps->op)))
				break;
	}
	return rc;
}
