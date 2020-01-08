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
 * @file    svr_connect.c
 *
 * @brief
 * 		svr_connect.c - contains routines to tie the structures used by
 *		net_client and net_server together with those used by the
 *		various PBS_*() routines in the API.
 *
 *		svr_connect() opens a connection with can be used with the
 *		API routines and still be selected in wait_request().
 *
 *		svr_disconnect() closes the above connection.
 *
 *		svr_disconnect_with_wait_option() like svr_disconnect() but there's
 *		an option to wait until connection has completely closed.
 *
 *		svr_force_disconnect() = directly closes the connection without asking
 *		the other end to close first.
 *
 * Functions included are:
 * 	svr_connect()
 * 	svr_disconnect()
 * 	svr_disconnect_with_wait_option()
 * 	socket_to_handle()
 * 	svr_force_disconnect()
 *
 */

#include <pbs_config.h>   /* the master config generated by configure */

#include <stdio.h>
#include <sys/types.h>

#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>

#include <errno.h>
#include "libpbs.h"
#include "server_limits.h"
#include "net_connect.h"
#include "attribute.h"
#include "pbs_nodes.h"
#include "svrfunc.h"
#include "dis.h"
#include "list_link.h"
#include "attribute.h"
#include "work_task.h"
#include "log.h"



/* global data */

struct connect_handle connection[PBS_MAX_CONNECTIONS]; /* used by API */

extern int		 errno;

extern int		 pbs_errno;
extern unsigned int	 pbs_server_port_dis;
extern unsigned int	 pbs_mom_port;
extern char		*msg_daemonname;
extern char		*msg_noloopbackif;

extern pbs_net_t	 pbs_server_addr;

extern sigset_t		 allsigs;		/* see pbsd_main.c */

/**
 * @brief
 *		opens a connection which can be used with the
 *      API routines and still be selected in wait_request(). It is called by
 *      the server whenever we need to send a request to another server, or
 *      talk to MOM.
 *
 * @param[in]   hostaddr - address of the host
 * @param[in]   port - port number f the host
 * @param[in]   func - pointer to function
 * @param[in]   cntype - indicates whether a connection table entry is in
 *                  use or is free
 * @param[in]   prot    - Connect over RPP or over TCP?
 *
 * @return	int
 * @retval	>=0	: connection handle returned on success. Note that a value
 *		 			of PBS_LOCAL_CONNECTION is special, it means the server
 *		 			is talking to itself.
 * @retval	-1	: PBS_NET_RC_FATAL (-1) is retuned if the error is believed
 *               	to be permanent
 * @retval	-2	: PBS_NET_RC_RETRY (-2) if the error is believed to be temporary,
 *               	ie retry.
 */
int
svr_connect(pbs_net_t hostaddr, unsigned int port, void (*func)(int), enum conn_type cntype, int prot)
{
	int handle;
	int mode;
	int sock;
	mominfo_t *pmom = 0;
	conn_t *conn = NULL;

	/* First, determine if the request is to another server or ourselves */

	if ((hostaddr == pbs_server_addr) && (port == pbs_server_port_dis))
		return (PBS_LOCAL_CONNECTION);	/* special value for local */

	pmom = tfind2((unsigned long)hostaddr, port, &ipaddrs);
	if ((pmom != NULL) && (port == pmom->mi_port)) {
		if (((mom_svrinfo_t *)(pmom->mi_data))->msr_state & INUSE_DOWN) {
			pbs_errno = PBSE_NORELYMOM;
			return (PBS_NET_RC_FATAL);
		}
	}

	if (prot == PROT_RPP) {
		if (!pmom) {
			pbs_errno = PBSE_SYSTEM;
			return (PBS_NET_RC_RETRY);
		}
		return ((mom_svrinfo_t *) (pmom->mi_data))->msr_stream;
	}

	/* obtain the connection to the other server */
	/*  block signals while we attempt to connect */

	if (sigprocmask(SIG_BLOCK, &allsigs, NULL) == -1)
		log_err(errno, msg_daemonname, "sigprocmask(BLOCK)");

	mode = B_RESERVED;
	if (pbs_conf.auth_method == AUTH_MUNGE)
		mode = B_EXTERNAL|B_SVR;

	sock = client_to_svr(hostaddr, port, 0x0 | mode);
	if (pbs_errno == PBSE_NOLOOPBACKIF)
		log_err(PBSE_NOLOOPBACKIF, "client_to_svr", msg_noloopbackif);

	if ((sock < 0) && (errno == ECONNREFUSED)) {
		/* try one additional time */
		sock = client_to_svr(hostaddr, port, 0x0 | mode);
		if (pbs_errno == PBSE_NOLOOPBACKIF)
			log_err(PBSE_NOLOOPBACKIF, "client_to_svr", msg_noloopbackif);
	}

	/* unblock signals */
	if (sigprocmask(SIG_UNBLOCK, &allsigs, NULL) == -1)
		log_err(errno, msg_daemonname, "sigprocmask(UNBLOCK)");

	if (sock < 0) {
		/* if execution node, mark it down  */
		if (pmom) {
			static	char	error_mess[256];

			sprintf(error_mess, "cannot open TCP stream: %s (%d)",
				strerror(errno), errno);
			momptr_down(pmom, error_mess);
		}
		pbs_errno = PBSE_NORELYMOM;
		return (sock);	/* PBS_NET_RC_RETRY or PBS_NET_RC_FATAL */
	}

	/* add the connection to the server connection table and select list */

	if (func) {
		conn = add_conn(sock, ToServerDIS, hostaddr, port, NULL, func);
	} else {
		conn = add_conn(sock, ToServerDIS, 0, 0, NULL, NULL);/* empty slot */
	}


	if (!conn) {
		(void)close(sock);
		pbs_errno = PBSE_SYSTEM;
		return (PBS_NET_RC_FATAL);
	}

	/* add_conn() may have created an entry already. If not,        */
	/* connection_find_usable_index() will give us an empty slot.   */
	conn->cn_sock = sock;
	conn->cn_authen |= PBS_NET_CONN_AUTHENTICATED;

	/* find a connect_handle entry we can use and pass to the PBS_*() */

	handle = socket_to_handle(sock);
	if (handle == -1) {
		close_conn(sock);
		pbs_errno = PBSE_NOCONNECTS;
		return (PBS_NET_RC_RETRY);
	}

	return (handle);
}
/**
 * @brief
 *		Close a connection made with svr_connect() by sending a
 *		PBS_BATCH_Disconnect request to the remote host.
 *
 * @note
 *		This will not wait for the remote host to close the
 *		connection. The calling program (like the main server) should
 *		take care of checking existing connections where the
 *		remote end has closed the connection as a PBS_BATCH_Disconnect
 *		response. If so, then proceed to locally close the connection.
 *
 * @param[in]	handle	-	the index to the connection table containing the socket
 *							to communicate the PBS_BATCH_Disconnect request.
 * @return	void
 */

void
svr_disconnect(int handle)
{
	svr_disconnect_with_wait_option(handle, 0);
}

/**
 * @brief
 *		Close a connection made with svr_connect() by sending a
 *		PBS_BATCH_Disconnect to the remote host. If the parameter
 *		'wait' is set to 1, then this function call would wait until
 *		connection is completely closed by the remote host.
 *
 * @note
 *		In addition to closing the actual connection, both the
 *		server's connection table and the handle table used by
 *		the API routines must be cleaned-up.
 *
 * @param[in]	handle	-	the index to the connection table containing the socket
 *							to communicate the PBS_BATCH_Disconnect request.
 * @param[in]	wait	-	if set to 1, then  this function waits until the remote
 *							host has closed the connection.
 *
 * @return	void
 *
 */

void
svr_disconnect_with_wait_option(int handle, int wait)
{
	int sock;
	char x;

	if ((handle >= 0) && (handle < PBS_LOCAL_CONNECTION)) {
		if (pbs_client_thread_lock_connection(handle) != 0)
			return;

		sock = connection[handle].ch_socket;
		DIS_tcp_setup(sock);
		if ((encode_DIS_ReqHdr(sock, PBS_BATCH_Disconnect, pbs_current_user) == 0) && (DIS_tcp_wflush(sock) == 0)) {
			conn_t *conn = get_conn(sock);

			/* if no error, will be closed when process_request */
			/* sees the EOF					    */

			if (wait) {
				for (;;) {
					/* wait for EOF (closed connection) */
					/* from remote host, in response to */
					/* PBS_BATCH_Disconnect */
					if (read(sock, &x, 1) < 1)
						break;
				}

				(void)close(connection[handle].ch_socket);
			} else if (conn) {
				conn->cn_func = close_conn;
				conn->cn_oncl = 0;
			}
		} else {
			/* error sending disconnect, just close now */
			close_conn(connection[handle].ch_socket);
		}
		if (connection[handle].ch_errtxt != NULL) {
			free(connection[handle].ch_errtxt);
			connection[handle].ch_errtxt = NULL;
		}
		connection[handle].ch_errno = 0;
		connection[handle].ch_inuse = 0;

		(void)pbs_client_thread_unlock_connection(handle);
		pbs_client_thread_destroy_connect_context(handle);
	}
}

/**
 * @brief
 * 		socket_to_handle() - turn a socket into a connection handle
 *		as used by the libpbs.a routines.
 *
 * @param[in]	sock	-	opened socket
 *
 * @return	int
 * @retval	>=0	: connection handle if successful
 * @retval	-1	: error, error number set in pbs_errno.
 */

int
socket_to_handle(int sock)
{
	int	i;
	conn_t	*conn = get_conn(sock);

	if (!conn)
		return (-1);

	for (i=0; i<PBS_MAX_CONNECTIONS; i++) {
		if (connection[i].ch_inuse == 0) {

			if (pbs_client_thread_lock_conntable() != 0)
				return -1;

			connection[i].ch_stream = 0;
			connection[i].ch_inuse = 1;
			connection[i].ch_errno = 0;
			connection[i].ch_socket= sock;
			connection[i].ch_errtxt = 0;

			if (pbs_client_thread_unlock_conntable() != 0)
				return -1;
			/* save handle for later close */

			conn->cn_handle = i;
			return (i);
		}
	}
	pbs_errno = PBSE_NOCONNECTS;
	return (-1);
}

/**
 * @brief
 * 		svr_force_disconnect - force the close of a connection handle
 *		Unlike svr_disconnect(), this does not send disconnect message
 *		and wait for the connection to be closed by the other end;
 *		just force it closed now.
 *
 * @param[in]	handle	-	connection handle
 */
void
svr_force_disconnect(int handle)
{
	if ((handle >= 0) && (handle < PBS_LOCAL_CONNECTION)) {
		if (pbs_client_thread_lock_connection(handle) != 0)
			return;

		close_conn(connection[handle].ch_socket);
		if (connection[handle].ch_errtxt != NULL) {
			free(connection[handle].ch_errtxt);
			connection[handle].ch_errtxt = NULL;
		}
		connection[handle].ch_errno = 0;
		connection[handle].ch_inuse = 0;

		(void)pbs_client_thread_unlock_connection(handle);
		pbs_client_thread_destroy_connect_context(handle);
	}
}
