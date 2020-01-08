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
#include <pbs_config.h>   /* the master config generated by configure */

#include	<tcl.h>
#ifdef NAS
#include	<string.h>
#include	<stdlib.h>
#endif
#include	"portability.h"
#include	"pbs_error.h"
#ifdef NAS
#include	"pbs_ifl.h"
#include	"pbs_internal.h"
#endif
#include	"log.h"


#ifdef NAS
/* localmod 071 */
extern char *	tcl_atrsep;

/* localmod 099 */
int	quiet = 0;

/* localmod 098 */
extern char badparm[];
extern char not_connected[];
extern char fail[];
extern Tcl_Obj	*pbserr;
extern Tcl_Obj	*pbsmsg;
extern int	connector;
void batresult(Tcl_Interp *interp, struct batch_status *bs);
Tcl_Obj *attrlist(Tcl_Interp *interp, struct attrl *ap);


#define SET_PBSERR(value) \
	(void)Tcl_ObjSetVar2(interp, pbserr, NULL, \
	Tcl_NewIntObj((value)), TCL_GLOBAL_ONLY | TCL_LEAVE_ERR_MSG)

#define SET_PBSMSG(msg) \
	(void)Tcl_ObjSetVar2(interp, pbsmsg, NULL, \
	Tcl_NewStringObj((msg), -1), TCL_GLOBAL_ONLY)

#define PBS_CALL(function, note) \
	if ( function ) { \
		Tcl_SetObjResult(interp, Tcl_NewIntObj(-1)); \
		msg = pbs_geterrmsg(connector); \
		sprintf(log_buffer, "%s: %s (%d)", note, \
			msg ? msg : fail, pbs_errno); \
		if(!quiet) \
			log_err(-1, cmd, log_buffer); \
	} \
	else \
		Tcl_SetObjResult(interp, Tcl_NewIntObj(0)); \

/* localmod 071 */
int
PBS_atrsep(ClientData clientData, Tcl_Interp *interp, int objc,
	Tcl_Obj *CONST objv[]) {
	int		ret;
	char *		newvalue;

	newvalue = NULL;
	switch (objc) {
		case 2:
			newvalue = Tcl_GetString(objv[1]);
		case 1:
			break;
		default:
			Tcl_WrongNumArgs(interp, 1, objv, "?string?");
			return TCL_ERROR;
	}
	Tcl_SetObjResult(interp, Tcl_NewStringObj(tcl_atrsep, strlen(tcl_atrsep)));
	if (newvalue) {
		free(tcl_atrsep);
		tcl_atrsep = strdup(newvalue);
	}
	return TCL_OK;
}

/* localmod 098 */
int
PBS_confirm(ClientData clientData, Tcl_Interp *interp, int objc,
	Tcl_Obj *CONST objv[])
{
	char		*cmd;
	char		*reqid;
	char		*exechost;
	unsigned long	start = 0;
	char		*extend = NULL;
	char		*msg;
	int		ret;

	switch (objc) {
		case 5:	extend = Tcl_GetString(objv[4]);
			/* Fall through */
		case 4: ret = Tcl_GetLongFromObj(interp, objv[3], (long *)&start);
			if (ret != TCL_OK) {
				return ret;
			}
			/* Fall through */
		case 3: exechost = Tcl_GetString(objv[2]);
			reqid = Tcl_GetString(objv[1]);
			break;
		default:
			Tcl_WrongNumArgs(interp, 1, objv, "resvid exechost ?start_time? ?extra?");
			return TCL_ERROR;
	}
	cmd = Tcl_GetString(objv[0]);
	if (connector < 0) {
		if(!quiet)
			log_err(-1, cmd, not_connected);
		SET_PBSERR(PBSE_NOSERVER);
		return TCL_OK;
	}

	PBS_CALL(pbs_confirmresv(connector, reqid, exechost, start, extend), reqid)
	SET_PBSERR(pbs_errno);
	return TCL_OK;
}


/* localmod 099 */
int
PBS_quiet(ClientData clientData, Tcl_Interp *interp, int objc,
	Tcl_Obj *CONST objv[])
{
	int		ret;
	int		newvalue;

	newvalue = quiet;
	switch (objc) {
		case 2:
			ret = Tcl_GetBooleanFromObj(interp, objv[1], &newvalue);
			if (ret != TCL_OK) {
				return ret;
			}
		case 1:
			break;
		default:
			Tcl_WrongNumArgs(interp, 1, objv, "?bool?");
			return TCL_ERROR;
	}
	Tcl_SetObjResult(interp, Tcl_NewIntObj(quiet));
	quiet = newvalue;
	return TCL_OK;
}

/* localmod 098 */
int
PBS_StatResv(ClientData clientData, Tcl_Interp *interp, int objc,
	Tcl_Obj *CONST objv[])
{
	char	*msg;
	struct	batch_status	*bs;
	char    *extend = NULL;

	if (objc > 2) {  /* can have one argument for extend field */
		sprintf(log_buffer, badparm, Tcl_GetString(objv[0]));
		Tcl_SetResult(interp, log_buffer, TCL_VOLATILE);
		return TCL_ERROR;
	}
	if (objc == 2) {
		extend = Tcl_GetString(objv[1]);
	}

	if (connector < 0) {
		if(!quiet)
			log_err(-1, Tcl_GetString(objv[0]), not_connected);
		SET_PBSERR(PBSE_NOSERVER);
		return TCL_OK;
	}

	if ((bs = pbs_statresv(connector, NULL, NULL, extend)) == NULL) {
		if (pbs_errno != PBSE_NONE) {
			msg = pbs_geterrmsg(connector);
			sprintf(log_buffer, "%s (%d)",
				msg ? msg : fail, pbs_errno);
			if(!quiet)
				log_err(-1, Tcl_GetString(objv[0]), log_buffer);
		}
	}
	else
		batresult(interp, bs);

	SET_PBSERR(pbs_errno);
	return TCL_OK;
}

int
PBS_StatSched(clientData, interp, argc, argv)
ClientData	clientData;
Tcl_Interp	*interp;
int		argc;
char	*argv[];
{
	char	*msg;
	struct	batch_status	*bs;
	Tcl_Obj	*threel[3];

	if (argc != 1) {
		sprintf(log_buffer, badparm, argv[0]);
		Tcl_SetResult(interp, log_buffer, TCL_VOLATILE);
		return TCL_ERROR;
	}

	if (connector < 0) {
		if(!quiet)
			log_err(-1, (char *)argv[0], not_connected);
		SET_PBSERR(PBSE_NOSERVER);
		return TCL_OK;
	}

	if ((bs = pbs_statsched(connector, NULL, NULL)) == NULL) {
		if (pbs_errno != PBSE_NONE) {
			msg = pbs_geterrmsg(connector);
			sprintf(log_buffer, "%s (%d)",
				msg ? msg : fail, pbs_errno);
			if(!quiet)
				log_err(-1, (char *)argv[0], log_buffer);
		}
	}
	else {
		threel[0] = Tcl_NewStringObj(bs->name, -1);
		threel[1] = attrlist(interp, bs->attribs);
		threel[2] = Tcl_NewStringObj(bs->text, -1);

		Tcl_SetObjResult(interp, Tcl_NewListObj(3, threel));

		pbs_statfree(bs);
	}

	SET_PBSERR(pbs_errno);
	return TCL_OK;
}

int
PBS_StatVnode(clientData, interp, objc, objv)
ClientData	clientData;
Tcl_Interp	*interp;
int		objc;
Tcl_Obj	*CONST	objv[];
{
	char	*msg, *cmd;
	char	*node = NULL;
	struct	batch_status	*bs;

	if (objc == 2)
		node = Tcl_GetStringFromObj(objv[1], NULL);
	else if (objc != 1) {
		Tcl_WrongNumArgs(interp, 1, objv, "?node?");
		return TCL_ERROR;
	}

	cmd = Tcl_GetStringFromObj(objv[0], NULL);
	if (connector < 0) {
		if(!quiet)
			log_err(-1, cmd, not_connected);
		SET_PBSERR(PBSE_NOSERVER);
		return TCL_OK;
	}

	if ((bs = pbs_statvnode(connector, node, NULL, NULL)) == NULL) {
		if (pbs_errno != PBSE_NONE) {
			msg = pbs_geterrmsg(connector);
			sprintf(log_buffer, "%s (%d)",
				msg ? msg : fail, pbs_errno);
			if(!quiet)
				log_err(-1, cmd, log_buffer);
		}
	}
	else
		batresult(interp, bs);

	SET_PBSERR(pbs_errno);
	return TCL_OK;
}
#endif


/*
 **	This is a site dependent routine provided as a place holder
 **	for whatever C code which may be required for your scheduler.
 */
void
site_cmds(interp)
Tcl_Interp	*interp;
{
	DBPRT(("%s: entered\n", __func__))
#ifdef NAS
	/* localmod 071 */
	Tcl_CreateObjCommand(interp, "pbsatrsep", PBS_atrsep, NULL, NULL);
	/* localmod 099 */
	Tcl_CreateObjCommand(interp, "pbsquiet", PBS_quiet, NULL, NULL);
	/* localmod 098 */
	Tcl_CreateObjCommand(interp, "pbsconfirm", PBS_confirm, NULL, NULL);
	Tcl_CreateObjCommand(interp, "pbsstatresv", PBS_StatResv, NULL, NULL);
	Tcl_CreateObjCommand(interp, "pbsstatsched", PBS_StatSched, NULL, NULL);
	Tcl_CreateObjCommand(interp, "pbsstatvnode", PBS_StatVnode, NULL, NULL);
#endif
	return;
}
