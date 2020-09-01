# coding: utf-8

# Copyright (C) 1994-2020 Altair Engineering, Inc.
# For more information, contact Altair at www.altair.com.
#
# This file is part of both the OpenPBS software ("OpenPBS")
# and the PBS Professional ("PBS Pro") software.
#
# Open Source License Information:
#
# OpenPBS is free software. You can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# OpenPBS is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
# License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Commercial License Information:
#
# PBS Pro is commercially licensed software that shares a common core with
# the OpenPBS software.  For a copy of the commercial license terms and
# conditions, go to: (http://www.pbspro.com/agreement.html) or contact the
# Altair Legal Department.
#
# Altair's dual-license business model allows companies, individuals, and
# organizations to create proprietary derivative works of OpenPBS and
# distribute them - whether embedded or bundled with other software -
# under a commercial license agreement.
#
# Use of Altair's trademarks, including but not limited to "PBS™",
# "OpenPBS®", "PBS Professional®", and "PBS Pro™" and Altair's logos is
# subject to Altair's trademark licensing policies.


import copy
import logging
import os
import re
import socket
import sys


from ptl.utils.pbs_dshutils import DshUtils


class PBSInitServices(object):
    """
    PBS initialization services

    :param hostname: Machine hostname
    :type hostname: str or None
    :param conf: PBS configuaration file
    :type conf: str or None
    """

    def __init__(self, hostname=None, conf=None):
        self.logger = logging.getLogger(__name__)
        self.hostname = hostname
        if self.hostname is None:
            self.hostname = socket.gethostname()
        self.dflt_conf_file = os.environ.get('PBS_CONF_FILE', '/etc/pbs.conf')
        self.conf_file = conf
        self.du = DshUtils()
        self.is_linux = sys.platform.startswith('linux')

    def initd(self, hostname=None, op='status', conf_file=None,
              init_script=None, daemon='all'):
        """
        Run the init script for a given operation

        :param hostname: hostname on which to execute the init script
        :type hostname: str or None
        :param op: one of status, start, stop, restart
        :type op: str
        :param conf_file: optional path to a configuration file
        :type conf_file: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        :param daemon: name of daemon to operate on. one of server, mom,
                       sched, comm or all
        :type daemon: str
        """
        if hostname is None:
            hostname = self.hostname
        if conf_file is None:
            conf_file = self.conf_file
        return self._unix_initd(hostname, op, conf_file, init_script, daemon)

    def restart(self, hostname=None, init_script=None):
        """
        Run the init script for a restart operation

        :param hostname: hostname on which to execute the init script
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='restart', init_script=init_script)

    def restart_server(self, hostname=None, init_script=None):
        """
        Run the init script for a restart server

        :param hostname: hostname on which to restart server
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='restart', init_script=init_script,
                          daemon='server')

    def restart_mom(self, hostname=None, init_script=None):
        """
        Run the init script for a restart mom

        :param hostname: hostname on which to restart mom
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='restart', init_script=init_script,
                          daemon='mom')

    def restart_sched(self, hostname=None, init_script=None):
        """
        Run the init script for a restart sched

        :param hostname: hostname on which to restart sched
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='restart', init_script=init_script,
                          daemon='sched')

    def restart_comm(self, hostname=None, init_script=None):
        """
        Run the init script for a restart comm

        :param hostname: hostname on which to restart comm
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='restart', init_script=init_script,
                          daemon='comm')

    def start(self, hostname=None, init_script=None):
        """
        Run the init script for a start operation

        :param hostname: hostname on which to execute the init script
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='start', init_script=init_script)

    def start_server(self, hostname=None, init_script=None):
        """
        Run the init script for a start server

        :param hostname: hostname on which to start server
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='start', init_script=init_script,
                          daemon='server')

    def start_mom(self, hostname=None, init_script=None):
        """
        Run the init script for a start mom

        :param hostname: hostname on which to start mom
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='start', init_script=init_script,
                          daemon='mom')

    def start_sched(self, hostname=None, init_script=None):
        """
        Run the init script for a start sched

        :param hostname: hostname on which to start sched
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='start', init_script=init_script,
                          daemon='sched')

    def start_comm(self, hostname=None, init_script=None):
        """
        Run the init script for a start comm

        :param hostname: hostname on which to start comm
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='start', init_script=init_script,
                          daemon='comm')

    def stop(self, hostname=None, init_script=None):
        """
        Run the init script for a stop operation

        :param hostname: hostname on which to execute the init script
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='stop', init_script=init_script)

    def stop_server(self, hostname=None, init_script=None):
        """
        Run the init script for a stop server

        :param hostname: hostname on which to stop server
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='stop', init_script=init_script,
                          daemon='server')

    def stop_mom(self, hostname=None, init_script=None):
        """
        Run the init script for a stop mom

        :param hostname: hostname on which to stop mom
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='stop', init_script=init_script,
                          daemon='mom')

    def stop_sched(self, hostname=None, init_script=None):
        """
        Run the init script for a stop sched

        :param hostname: hostname on which to stop sched
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='stop', init_script=init_script,
                          daemon='sched')

    def stop_comm(self, hostname=None, init_script=None):
        """
        Run the init script for a stop comm

        :param hostname: hostname on which to stop comm
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='stop', init_script=init_script,
                          daemon='comm')

    def status(self, hostname=None, init_script=None):
        """
        Run the init script for a status operation

        :param hostname: hostname on which to execute the init script
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='status', init_script=init_script)

    def status_server(self, hostname=None, init_script=None):
        """
        Run the init script for a status server

        :param hostname: hostname on which to status server
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='status', init_script=init_script,
                          daemon='server')

    def status_mom(self, hostname=None, init_script=None):
        """
        Run the init script for a status mom

        :param hostname: hostname on which to status mom
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='status', init_script=init_script,
                          daemon='mom')

    def status_sched(self, hostname=None, init_script=None):
        """
        Run the init script for a status sched

        :param hostname: hostname on which to status sched
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='status', init_script=init_script,
                          daemon='sched')

    def status_comm(self, hostname=None, init_script=None):
        """
        Run the init script for a status comm

        :param hostname: hostname on which to status comm
        :type hostname: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        """
        return self.initd(hostname, op='status', init_script=init_script,
                          daemon='comm')

    def _unix_initd(self, hostname, op, conf_file, init_script, daemon):
        """
        Helper function for initd ``(*nix version)``

        :param hostname: hostname on which init script should run
        :type hostname: str
        :param op: Operation on daemons - start, stop, restart or status
        :op type: str
        :param conf_file: Optional path to the pbs configuration file
        :type conf_file: str or None
        :param init_script: optional path to a PBS init script
        :type init_script: str or None
        :param daemon: name of daemon to operate on. one of server, mom,
                       sched, comm or all
        :type daemon: str
        """
        init_cmd = copy.copy(self.du.sudo_cmd)
        if daemon is not None and daemon != 'all':
            conf = self.du.parse_pbs_config(hostname, conf_file)
            dconf = {
                'PBS_START_SERVER': 0,
                'PBS_START_MOM': 0,
                'PBS_START_SCHED': 0,
                'PBS_START_COMM': 0
            }
            if daemon == 'server' and conf.get('PBS_START_SERVER', 0) != 0:
                dconf['PBS_START_SERVER'] = 1
            elif daemon == 'mom' and conf.get('PBS_START_MOM', 0) != 0:
                dconf['PBS_START_MOM'] = 1
            elif daemon == 'sched' and conf.get('PBS_START_SCHED', 0) != 0:
                dconf['PBS_START_SCHED'] = 1
            elif daemon == 'comm' and conf.get('PBS_START_COMM', 0) != 0:
                dconf['PBS_START_COMM'] = 1
            for k, v in dconf.items():
                init_cmd += ["%s=%s" % (k, str(v))]
            _as = True
        else:
            fn = None
            if (conf_file is not None) and (conf_file != self.dflt_conf_file):
                init_cmd += ['PBS_CONF_FILE=' + conf_file]
                _as = True
            else:
                _as = False
            conf = self.du.parse_pbs_config(hostname, conf_file)
        if (init_script is None) or (not init_script.startswith('/')):
            if 'PBS_EXEC' not in conf:
                msg = 'Missing PBS_EXEC setting in pbs config'
                raise PbsInitServicesError(rc=1, rv=False, msg=msg)
            if init_script is None:
                init_script = os.path.join(conf['PBS_EXEC'], 'libexec',
                                           'pbs_init.d')
            else:
                init_script = os.path.join(conf['PBS_EXEC'], 'etc',
                                           init_script)
            if not self.du.isfile(hostname, path=init_script, sudo=True):
                # Could be Type 3 installation where we will not have
                # PBS_EXEC/libexec/pbs_init.d
                return []
        init_cmd += [init_script, op]
        msg = 'running init script to ' + op + ' pbs'
        if daemon is not None and daemon != 'all':
            msg += ' ' + daemon
        msg += ' on ' + hostname
        if conf_file is not None:
            msg += ' using ' + conf_file
        msg += ' init_cmd=%s' % (str(init_cmd))
        self.logger.info(msg)
        ret = self.du.run_cmd(hostname, init_cmd, as_script=_as,
                              logerr=False)
        if ret['rc'] != 0:
            raise PbsInitServicesError(rc=ret['rc'], rv=False,
                                       msg='\n'.join(ret['err']))
        else:
            return ret

    def switch_version(self, hostname=None, version=None):
        """
        Switch to another version of PBS installed on the system

        :param hostname: The hostname to operate on
        :type hostname: str or None
        :param version: version to switch
        """
        pbs_conf = self.du.parse_pbs_config(hostname)
        if 'PBS_EXEC' in pbs_conf:
            dn = os.path.dirname(pbs_conf['PBS_EXEC'])
            newver = os.path.join(dn, version)
            ret = self.du.isdir(hostname, path=newver)
            if not ret:
                msg = 'no version ' + version + ' on host ' + hostname
                raise PbsInitServicesError(rc=0, rv=False, msg=msg)
            self.stop(hostname)
            dflt = os.path.join(dn, 'default')
            ret = self.du.isfile(hostname, path=dflt)
            if ret:
                self.logger.info('removing symbolic link ' + dflt)
                self.du.rm(hostname, dflt, sudo=True, logerr=False)
                self.du.set_pbs_config(hostname, confs={'PBS_EXEC': dflt})
            else:
                self.du.set_pbs_config(hostname, confs={'PBS_EXEC': newver})

            self.logger.info('linking ' + newver + ' to ' + dflt)
            self.du.run_cmd(hostname, ['ln', '-s', newver, dflt],
                            sudo=True, logerr=False)
            self.start(hostname)
