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
 * @file	dec_rcpy.c
 * @brief
 * 	decode_DIS_replyCmd() - decode a Batch Protocol Reply Structure for a Command
 *
 *	This routine decodes a batch reply into the form used by commands.
 *	The only difference between this and the server version is on status
 *	replies.  For commands, the attributes are decoded into a list of
 *	attrl structure rather than the server's svrattrl.
 *
 * 	batch_reply structure defined in libpbs.h, it must be allocated
 *	by the caller.
 */

#include <pbs_config.h>   /* the master config generated by configure */

#include <sys/types.h>
#include <stdlib.h>
#include "libpbs.h"
#include "dis.h"

/**
 * @brief-
 *	decode a Batch Protocol Reply Structure for a Command
 *
 * @par	Functionality:
 *		This routine decodes a batch reply into the form used by commands.
 *      	The only difference between this and the server version is on status
 *      	replies.  For commands, the attributes are decoded into a list of
 *      	attrl structure rather than the server's svrattrl.
 *
 * Note: batch_reply structure defined in libpbs.h, it must be allocated
 *       by the caller.
 *
 * @param[in] sock - socket descriptor
 * @param[in] reply - pointer to batch_reply structure
 *
 * @return	int
 * @retval	-1	error
 * @retval	0	Success
 *
 */

int
decode_DIS_replyCmd(int sock, struct batch_reply *reply)
{
	int		      ct;
	int		      i;
	struct brp_select    *psel;
	struct brp_select   **pselx;
	struct brp_cmdstat   *pstcmd;
	struct brp_cmdstat  **pstcx;
	int		      rc = 0;
	size_t		      txtlen;
	preempt_job_info 	*ppj = NULL;

	/* first decode "header" consisting of protocol type and version */

	i = disrui(sock, &rc);
	if (rc != 0) return rc;
	if (i != PBS_BATCH_PROT_TYPE) return DIS_PROTO;
	i = disrui(sock, &rc);
	if (rc != 0) return rc;
	if (i != PBS_BATCH_PROT_VER) return DIS_PROTO;

	/* next decode code, auxcode and choice (union type identifier) */

	reply->brp_code    = disrsi(sock, &rc);
	if (rc) return rc;
	reply->brp_auxcode = disrsi(sock, &rc);
	if (rc) return rc;
	reply->brp_choice  = disrui(sock, &rc);
	if (rc) return rc;


	switch (reply->brp_choice) {

		case BATCH_REPLY_CHOICE_NULL:
			break;	/* no more to do */

		case BATCH_REPLY_CHOICE_Queue:
		case BATCH_REPLY_CHOICE_RdytoCom:
		case BATCH_REPLY_CHOICE_Commit:
			disrfst(sock, PBS_MAXSVRJOBID+1, reply->brp_un.brp_jid);
			if (rc)
				return (rc);
			break;

		case BATCH_REPLY_CHOICE_Select:

			/* have to get count of number of strings first */

			reply->brp_un.brp_select = NULL;
			pselx = &reply->brp_un.brp_select;
			ct = disrui(sock, &rc);
			if (rc) return rc;

			while (ct--) {
				psel = (struct brp_select *)malloc(sizeof(struct brp_select));
				if (psel == 0) return DIS_NOMALLOC;
				psel->brp_next = NULL;
				psel->brp_jobid[0] = '\0';
				rc = disrfst(sock, PBS_MAXSVRJOBID+1, psel->brp_jobid);
				if (rc) {
					(void)free(psel);
					return rc;
				}
				*pselx = psel;
				pselx  = &psel->brp_next;
			}
			break;

		case BATCH_REPLY_CHOICE_Status:

			/* have to get count of number of status objects first */

			reply->brp_un.brp_statc = NULL;
			pstcx = &reply->brp_un.brp_statc;
			ct = disrui(sock, &rc);
			if (rc) return rc;

			while (ct--) {
				pstcmd = (struct brp_cmdstat *)malloc(sizeof(struct brp_cmdstat));
				if (pstcmd == 0) return DIS_NOMALLOC;

				pstcmd->brp_stlink = NULL;
				pstcmd->brp_objname[0] = '\0';
				pstcmd->brp_attrl = NULL;

				pstcmd->brp_objtype = disrui(sock, &rc);
				if (rc == 0) {
					rc = disrfst(sock, PBS_MAXSVRJOBID+1,
						pstcmd->brp_objname);
				}
				if (rc) {
					(void)free(pstcmd);
					return rc;
				}
				rc = decode_DIS_attrl(sock, &pstcmd->brp_attrl);
				if (rc) {
					(void)free(pstcmd);
					return rc;
				}
				*pstcx = pstcmd;
				pstcx  = &pstcmd->brp_stlink;
			}
			break;

		case BATCH_REPLY_CHOICE_Text:

			/* text reply */

		  	reply->brp_un.brp_txt.brp_str = disrcs(sock, &txtlen, &rc);
			reply->brp_un.brp_txt.brp_txtlen = txtlen;
			break;

		case BATCH_REPLY_CHOICE_Locate:

			/* Locate Job Reply */

			rc = disrfst(sock, PBS_MAXDEST+1, reply->brp_un.brp_locate);
			break;

		case BATCH_REPLY_CHOICE_RescQuery:

			/* Resource Query Reply */

			reply->brp_un.brp_rescq.brq_avail = NULL;
			reply->brp_un.brp_rescq.brq_alloc = NULL;
			reply->brp_un.brp_rescq.brq_resvd = NULL;
			reply->brp_un.brp_rescq.brq_down  = NULL;
			ct = disrui(sock, &rc);
			if (rc) break;
			reply->brp_un.brp_rescq.brq_number = ct;
			reply->brp_un.brp_rescq.brq_avail  =
				(int *)malloc(ct * sizeof(int));
			if (reply->brp_un.brp_rescq.brq_avail == NULL)
				return DIS_NOMALLOC;
			reply->brp_un.brp_rescq.brq_alloc  =
				(int *)malloc(ct * sizeof(int));
			if (reply->brp_un.brp_rescq.brq_alloc == NULL)
				return DIS_NOMALLOC;
			reply->brp_un.brp_rescq.brq_resvd  =
				(int *)malloc(ct * sizeof(int));
			if (reply->brp_un.brp_rescq.brq_resvd == NULL)
				return DIS_NOMALLOC;
			reply->brp_un.brp_rescq.brq_down   =
				(int *)malloc(ct * sizeof(int));
			if (reply->brp_un.brp_rescq.brq_down == NULL)
				return DIS_NOMALLOC;

			for (i=0; (i < ct) && (rc == 0); ++i)
				*(reply->brp_un.brp_rescq.brq_avail+i) = disrui(sock, &rc);
			for (i=0; (i < ct) && (rc == 0); ++i)
				*(reply->brp_un.brp_rescq.brq_alloc+i) = disrui(sock, &rc);
			for (i=0; (i < ct) && (rc == 0); ++i)
				*(reply->brp_un.brp_rescq.brq_resvd+i) = disrui(sock, &rc);
			for (i=0; (i < ct) && (rc == 0); ++i)
				*(reply->brp_un.brp_rescq.brq_down+i)  = disrui(sock, &rc);
			break;

		case BATCH_REPLY_CHOICE_PreemptJobs:

			/* Preempt Jobs Reply */
			ct = disrui(sock, &rc);
			reply->brp_un.brp_preempt_jobs.count = ct;
			if (rc) break;

			ppj = calloc(sizeof(struct preempt_job_info), ct);
			reply->brp_un.brp_preempt_jobs.ppj_list = ppj;

			for (i = 0; i < ct; i++) {
				if (((rc = disrfst(sock, PBS_MAXSVRJOBID + 1, ppj[i].job_id)) != 0) ||
					((rc = disrfst(sock, PREEMPT_METHOD_HIGH + 1, ppj[i].order)) != 0))
						return rc;
			}

			break;

		default:
			return -1;
	}

	return rc;
}
