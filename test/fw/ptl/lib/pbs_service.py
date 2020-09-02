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


import ast
import base64
import collections
import copy
import datetime
import grp
import json
import logging
import os
import pickle
import pwd
import random
import re
import socket
import string
import sys
import tempfile
import threading
import time
import traceback
from collections import OrderedDict
from distutils.version import LooseVersion
from operator import itemgetter

from ptl.lib.pbs_api_to_cli import api_to_cli
from ptl.utils.pbs_cliutils import CliUtils
from ptl.utils.pbs_dshutils import DshUtils, PtlUtilError
from ptl.utils.pbs_procutils import ProcUtils
from ptl.utils.pbs_testusers import (ROOT_USER, TEST_USER, PbsUser,
                                     DAEMON_SERVICE_USER)
from ptl.lib.pbs_testlib import *
from ptl.lib.pbsobject import *
try:
    import psycopg2
    PSYCOPG = True
except:
    PSYCOPG = False

try:
    from ptl.lib.pbs_ifl import *
    API_OK = True
except:
    try:
        from ptl.lib.pbs_ifl_mock import *
    except:
        sys.stderr.write("failed to import pbs_ifl, run pbs_swigify " +
                         "to make it\n")
        raise ImportError
    API_OK = False

class PBSService(PBSObject):

    """
    Generic PBS service object to hold properties of PBS daemons

    :param name: The name associated to the object
    :type name: str or None
    :param attrs: Dictionary of attributes to set on object
    :type attrs: Dictionary
    :param defaults: Dictionary of default attributes. Setting
                     this will override any other object's default
    :type defaults: Dictionary
    :param pbsconf_file: Optional path to the pbs configuration
                         file
    :type pbsconf_file: str or None
    :param snapmap: A dictionary of PBS objects (node,server,etc)
                    to mapped files from PBS snapshot directory
    :type snapmap: Dictionary
    :param snap: path to PBS snap directory
                 (This will override snapmap)
    :type snap: str or None
    """
    du = DshUtils()
    pu = ProcUtils()

    def __init__(self, name=None, attrs=None, defaults=None, pbsconf_file=None,
                 snapmap=None, snap=None):
        if attrs is None:
            attrs = {}
        if defaults is None:
            defaults = {}
        if snapmap is None:
            snapmap = {}
        if name is None:
            self.hostname = socket.gethostname()
        else:
            self.hostname = name
        if snap:
            self.snapmap = self._load_from_snap(snap)
            self.has_snap = True
            self.snap = snap
        elif len(snapmap) > 0:
            self.snapmap = snapmap
            self.snap = None
            self.has_snap = True
        else:
            self.snapmap = {}
            self.snap = None
            self.has_snap = False
        if not self.has_snap:
            try:
                self.fqdn = socket.gethostbyaddr(self.hostname)[0]
                if self.hostname != self.fqdn:
                    self.logger.info('FQDN name ' + self.fqdn + ' differs '
                                     'from name provided ' + self.hostname)
                    self.hostname = self.fqdn
            except:
                pass
        else:
            self.fqdn = self.hostname

        self.shortname = self.hostname.split('.')[0]
        self.platform = self.du.get_platform()

        self.logutils = None
        self.logfile = None
        self.acctlogfile = None
        self.pbs_conf = {}
        self.pbs_env = {}
        self._is_local = True
        self.launcher = None
        self.dyn_created_files = []
        self.saved_config = {}

        PBSObject.__init__(self, name, attrs, defaults)

        if not self.has_snap:
            if not self.du.is_localhost(self.hostname):
                self._is_local = False

        if pbsconf_file is None and not self.has_snap:
            self.pbs_conf_file = self.du.get_pbs_conf_file(name)
        else:
            self.pbs_conf_file = pbsconf_file

        if self.pbs_conf_file == '/etc/pbs.conf':
            self.default_pbs_conf = True
        elif (('PBS_CONF_FILE' not in os.environ) or
              (os.environ['PBS_CONF_FILE'] != self.pbs_conf_file)):
            self.default_pbs_conf = False
        else:
            self.default_pbs_conf = True

        # default pbs_server_name to hostname, it will get set again once the
        # config file is processed
        self.pbs_server_name = self.hostname

        # If snap is given then bypass parsing pbs.conf
        if self.has_snap:
            if snap is None:
                t = 'snapshot_%s' % (time.strftime("%y%m%d_%H%M%S"))
                self.snap = os.path.join(self.du.get_tempdir(), t)
            self.pbs_conf['PBS_HOME'] = self.snap
            self.pbs_conf['PBS_EXEC'] = self.snap
            self.pbs_conf['PBS_SERVER'] = self.hostname
            m = re.match(r'.*snapshot_(?P<datetime>\d{6,6}_\d{6,6}).*',
                         self.snap)
            if m:
                tm = time.strptime(m.group('datetime'), "%y%m%d_%H%M%S")
                self.ctime = int(time.mktime(tm))
        else:
            self.pbs_conf = self.du.parse_pbs_config(self.hostname,
                                                     self.pbs_conf_file)
            if self.pbs_conf is None or len(self.pbs_conf) == 0:
                self.pbs_conf = {'PBS_HOME': "", 'PBS_EXEC': ""}
            else:
                ef = os.path.join(self.pbs_conf['PBS_HOME'], 'pbs_environment')
                self.pbs_env = self.du.parse_pbs_environment(self.hostname, ef)
                self.pbs_server_name = self.du.get_pbs_server_name(
                    self.pbs_conf)

        self.init_logfile_path(self.pbs_conf)

    def _load_from_snap(self, snap):
        snapmap = {}
        snapmap[SERVER] = os.path.join(snap, 'server', 'qstat_Bf.out')
        snapmap[VNODE] = os.path.join(snap, 'node', 'pbsnodes_va.out')
        snapmap[QUEUE] = os.path.join(snap, 'server', 'qstat_Qf.out')
        snapmap[JOB] = os.path.join(snap, 'job', 'qstat_tf.out')
        if not os.path.isfile(snapmap[JOB]):
            snapmap[JOB] = os.path.join(snap, 'job', 'qstat_f.out')
        snapmap[RESV] = os.path.join(snap, 'reservation', 'pbs_rstat_f.out')
        snapmap[SCHED] = os.path.join(snap, 'scheduler', 'qmgr_psched.out')
        snapmap[HOOK] = []
        if (os.path.isdir(os.path.join(snap, 'server_priv')) and
                os.path.isdir(os.path.join(snap, 'server_priv', 'hooks'))):
            _ld = os.listdir(os.path.join(snap, 'server_priv', 'hooks'))
            for f in _ld:
                if f.endswith('.HK'):
                    snapmap[HOOK].append(
                        os.path.join(snap, 'server_priv', 'hooks', f))

        return snapmap

    def init_logfile_path(self, conf=None):
        """
        Initialize path to log files for this service

        :param conf: PBS conf file parameters
        :type conf: Dictionary
        """
        elmt = self._instance_to_logpath(self)
        if elmt is None:
            return

        if conf is not None and 'PBS_HOME' in conf:
            tm = time.strftime("%Y%m%d", time.localtime())
            self.logfile = os.path.join(conf['PBS_HOME'], elmt, tm)
            self.acctlogfile = os.path.join(conf['PBS_HOME'], 'server_priv',
                                            'accounting', tm)

    def _instance_to_logpath(self, inst):
        """
        returns the log path associated to this service
        """
        if inst.__class__.__name__ == "Scheduler":
            logval = 'sched_logs'
        elif inst.__class__.__name__ == "Server":
            logval = 'server_logs'
        elif inst.__class__.__name__ == "MoM":
            logval = 'mom_logs'
        elif inst.__class__.__name__ == "Comm":
            logval = 'comm_logs'
        else:
            logval = None
        return logval

    def _instance_to_cmd(self, inst):
        """
        returns the command associated to this service
        """
        if inst.__class__.__name__ == "Scheduler":
            cmd = 'pbs_sched'
        elif inst.__class__.__name__ == "Server":
            cmd = 'pbs_server'
        elif inst.__class__.__name__ == "MoM":
            cmd = 'pbs_mom'
        elif inst.__class__.__name__ == "Comm":
            cmd = 'pbs_comm'
        else:
            cmd = None
        return cmd

    def _instance_to_servicename(self, inst):
        """
        return the service name associated to the instance. One of
        ``server, scheduler, or mom.``
        """
        if inst.__class__.__name__ == "Scheduler":
            nm = 'scheduler'
        elif inst.__class__.__name__ == "Server":
            nm = 'server'
        elif inst.__class__.__name__ == "MoM":
            nm = 'mom'
        elif inst.__class__.__name__ == "Comm":
            nm = 'comm'
        else:
            nm = ''
        return nm

    def _instance_to_privpath(self, inst):
        """
        returns the path to priv associated to this service
        """
        if inst.__class__.__name__ == "Scheduler":
            priv = 'sched_priv'
        elif inst.__class__.__name__ == "Server":
            priv = 'server_priv'
        elif inst.__class__.__name__ == "MoM":
            priv = 'mom_priv'
        elif inst.__class__.__name__ == "Comm":
            priv = 'server_priv'
        else:
            priv = None
        return priv

    def _instance_to_lock(self, inst):
        """
        returns the path to lock file associated to this service
        """
        if inst.__class__.__name__ == "Scheduler":
            lock = 'sched.lock'
        elif inst.__class__.__name__ == "Server":
            lock = 'server.lock'
        elif inst.__class__.__name__ == "MoM":
            lock = 'mom.lock'
        elif inst.__class__.__name__ == "Comm":
            lock = 'comm.lock'
        else:
            lock = None
        return lock

    def set_launcher(self, execargs=None):
        self.launcher = execargs

    def _isUp(self, inst):
        """
        returns True if service is up and False otherwise
        """
        live_pids = self._all_instance_pids(inst)
        pid = self._get_pid(inst)
        if live_pids is not None and pid in live_pids:
            return True
        return False

    def _signal(self, sig, inst=None, procname=None):
        """
        Send signal ``sig`` to service. sig is the signal name
        as it would be sent to the program kill, e.g. -HUP.

        Return the ``out/err/rc`` from the command run to send
        the signal. See DshUtils.run_cmd

        :param inst: Instance
        :type inst: str
        :param procname: Process name
        :type procname: str or None
        """
        pid = None

        if inst is not None:
            pid = self._get_pid(inst)

        if procname is not None:
            pi = self.pu.get_proc_info(self.hostname, procname)
            if pi is not None and pi.values() and list(pi.values())[0]:
                for _p in list(pi.values())[0]:
                    ret = self.du.run_cmd(self.hostname, ['kill', sig, _p.pid],
                                          sudo=True)
                return ret

        if pid is None:
            return {'rc': 0, 'err': '', 'out': 'no pid to signal'}

        return self.du.run_cmd(self.hostname, ['kill', sig, pid], sudo=True)

    def _all_instance_pids(self, inst):
        """
        Return a list of all ``PIDS`` that match the
        instance name or None.
        """
        cmd = self._instance_to_cmd(inst)
        self.pu.get_proc_info(self.hostname, ".*" + cmd + ".*",
                              regexp=True)
        _procs = self.pu.processes.values()
        if _procs:
            _pids = []
            for _p in _procs:
                _pids.extend([x.pid for x in _p])
            return _pids
        return None

    def _get_pid(self, inst):
        """
        Get the ``PID`` associated to this instance.
        Implementation note, the pid is read from the
        daemon's lock file.

        This is different than _all_instance_pids in that
        the PID of the last running instance can be retrieved
        with ``_get_pid`` but not with ``_all_instance_pids``
        """
        priv = self._instance_to_privpath(inst)
        lock = self._instance_to_lock(inst)
        if (inst.__class__.__name__ == "Scheduler") and 'sched_priv' in inst.attributes:
            path = os.path.join(inst.attributes['sched_priv'], lock)
        else:
            path = os.path.join(self.pbs_conf['PBS_HOME'], priv, lock)
        rv = self.du.cat(self.hostname, path, sudo=True, logerr=False)
        if ((rv['rc'] == 0) and (len(rv['out']) > 0)):
            pid = rv['out'][0].strip()
        else:
            pid = None
        return pid

    def _validate_pid(self, inst):
        """
        Get pid and validate
        :param inst: inst to update pid
        :type inst: object
        """
        for i in range(30):
            live_pids = self._all_instance_pids(inst)
            pid = self._get_pid(inst)
            if live_pids is not None and pid in live_pids:
                return pid
            time.sleep(1)
        return None

    def _start(self, inst=None, args=None, cmd_map=None, launcher=None):
        """
        Generic service startup

        :param inst: The instance to act upon
        :type inst: str
        :param args: Optional command-line arguments
        :type args: List
        :param cmd_map: Optional dictionary of command line
                        options to configuration variables
        :type cmd_map: Dictionary
        :param launcher: Optional utility to invoke the launch
                         of the service. This option only takes
                         effect on ``Unix/Linux``. The option can
                         be a string or a list.Options may be passed
                         to the launcher, for example to start a
                         service through the valgrind utility
                         redirecting to a log file,launcher could be
                         set to e.g.
                         ``['valgrind', '--log-file=/tmp/vlgrd.out']``
                         or ``'valgrind --log-file=/tmp/vlgrd.out'``
        """
        if launcher is None and self.launcher is not None:
            launcher = self.launcher

        app = self._instance_to_cmd(inst)
        if app is None:
            return
        _m = ['service: starting', app]
        if args is not None:
            _m += ['with args: ']
            _m += args

        as_script = False
        wait_on = True
        if launcher is not None:
            if isinstance(launcher, str):
                launcher = launcher.split()
            if app == 'pbs_server':
                # running the pbs server through valgrind requires a bit of
                # a dance because the pbs_server binary is pbs_server.bin
                # and to run it requires being able to find libraries, so
                # LD_LIBRARY_PATH is set and pbs_server.bin is run as a
                # script
                pexec = inst.pbs_conf['PBS_EXEC']
                ldlib = ['LD_LIBRARY_PATH=' +
                         os.path.join(pexec, 'lib') + ':' +
                         os.path.join(pexec, 'pgsql', 'lib')]
                app = 'pbs_server.bin'
            else:
                ldlib = []
            cmd = ldlib + launcher
            as_script = True
            wait_on = False
        else:
            cmd = []

        cmd += [os.path.join(self.pbs_conf['PBS_EXEC'], 'sbin', app)]
        if args is not None:
            cmd += args
        if not self.default_pbs_conf:
            cmd = ['PBS_CONF_FILE=' + inst.pbs_conf_file] + cmd
            as_script = True
        if cmd_map is not None:
            conf_cmd = self.du.map_pbs_conf_to_cmd(cmd_map,
                                                   pconf=self.pbs_conf)
            cmd.extend(conf_cmd)
            _m += conf_cmd

        self.logger.info(" ".join(_m))

        ret = self.du.run_cmd(self.hostname, cmd, sudo=True,
                              as_script=as_script, wait_on_script=wait_on,
                              level=logging.INFOCLI, logerr=False)
        if ret['rc'] != 0:
            raise PbsServiceError(rv=False, rc=ret['rc'], msg=ret['err'])

        ret_msg = True
        if ret['err']:
            ret_msg = ret['err']
        pid = self._validate_pid(inst)
        if pid is None:
            raise PbsServiceError(rv=False, rc=-1, msg="Could not find PID")
        return ret_msg

    def _stop(self, sig='-TERM', inst=None):
        if inst is None:
            return True
        self._signal(sig, inst)
        pid = self._get_pid(inst)
        chk_pid = self._all_instance_pids(inst)
        if pid is None or chk_pid is None:
            return True
        num_seconds = 0
        while (chk_pid is not None) and (str(pid) in chk_pid):
            if num_seconds > 60:
                m = (self.logprefix + 'could not stop service ' +
                     self._instance_to_servicename(inst))
                raise PbsServiceError(rv=False, rc=-1, msg=m)
            time.sleep(1)
            num_seconds += 1
            chk_pid = self._all_instance_pids(inst)
        return True

    def initialise_service(self):
        """
        Purpose of this method is to override and initialise
        the service
        """

    def log_lines(self, logtype, id=None, n=50, tail=True, starttime=None,
                  endtime=None, host=None):
        """
        Return the last ``<n>`` lines of a PBS log file, which
        can be one of ``server``, ``scheduler``, ``MoM``, or
        ``tracejob``

        :param logtype: The entity requested, an instance of a
                        Scheduler, Server or MoM object, or the
                        string 'tracejob' for tracejob
        :type logtype: str or object
        :param id: The id of the object to trace. Only used for
                   tracejob
        :param n: One of 'ALL' of the number of lines to
                  process/display, defaults to 50.
        :type n: str or int
        :param tail: if True, parse log from the end to the start,
                     otherwise parse from the start to the end.
                     Defaults to True.
        :type tail: bool
        :param day: Optional day in ``YYYMMDD`` format. Defaults
                    to current day
        :type day: int
        :param starttime: date timestamp to start matching
        :param endtime: date timestamp to end matching
        :param host: Hostname
        :type host: str
        :returns: Last ``<n>`` lines of logfile for ``Server``,
                  ``Scheduler``, ``MoM or tracejob``
        """
        logval = None
        lines = []
        sudo = False
        if endtime is None:
            endtime = time.time()
        if starttime is None:
            starttime = self.ctime
        if host is None:
            host = self.hostname
        try:
            if logtype == 'tracejob':
                if id is None:
                    return None
                cmd = [os.path.join(
                       self.pbs_conf['PBS_EXEC'],
                       'bin',
                       'tracejob')]
                cmd += [str(id)]
                lines = self.du.run_cmd(host, cmd)['out']
                if n != 'ALL':
                    lines = lines[-n:]
            else:
                daystart = time.strftime("%Y%m%d", time.localtime(starttime))
                dayend = time.strftime("%Y%m%d", time.localtime(endtime))
                firstday_obj = datetime.datetime.strptime(daystart, '%Y%m%d')
                lastday_obj = datetime.datetime.strptime(dayend, '%Y%m%d')
                if logtype == 'accounting':
                    logdir = os.path.join(self.pbs_conf['PBS_HOME'],
                                          'server_priv', 'accounting')
                    sudo = True
                elif ((self.__class__.__name__ == "Scheduler") and 'sched_log' in self.attributes):
                    # if setup is multi-sched then get logdir from
                    # its attributes
                    logdir = self.attributes['sched_log']
                else:
                    logval = self._instance_to_logpath(logtype)
                    if logval is None:
                        m = 'Invalid logtype'
                        raise PtlLogMatchError(rv=False, rc=-1, msg=m)
                    logdir = os.path.join(self.pbs_conf['PBS_HOME'], logval)
                while firstday_obj <= lastday_obj:
                    day = firstday_obj.strftime("%Y%m%d")
                    filename = os.path.join(logdir, day)
                    if n == 'ALL':
                        day_lines = self.du.cat(
                            host, filename, sudo=sudo,
                            level=logging.DEBUG2)['out']
                    else:
                        if tail:
                            cmd = ['/usr/bin/tail']
                        else:
                            cmd = ['/usr/bin/head']

                        cmd += ['-n']
                        cmd += [str(n), filename]
                        day_lines = self.du.run_cmd(
                            host, cmd, sudo=sudo,
                            level=logging.DEBUG2)['out']
                    lines.extend(day_lines)
                    firstday_obj = firstday_obj + datetime.timedelta(days=1)
                    if n == 'ALL':
                        continue
                    n = n - len(day_lines)
                    if n <= 0:
                        break
        except (Exception, IOError, PtlLogMatchError):
            self.logger.error('error in log_lines ')
            self.logger.error(traceback.print_exc())
            return None

        return lines

    def _log_match(self, logtype, msg, id=None, n=50, tail=True,
                   allmatch=False, regexp=False, max_attempts=None,
                   interval=None, starttime=None, endtime=None,
                   level=logging.INFO, existence=True):
        """
        Match given ``msg`` in given ``n`` lines of log file

        :param logtype: The entity requested, an instance of a
                        Scheduler, Server, or MoM object, or the
                        strings 'tracejob' for tracejob or
                        'accounting' for accounting logs.
        :type logtype: object
        :param msg: log message to match, can be regex also when
                    ``regexp`` is True
        :type msg: str
        :param id: The id of the object to trace. Only used for
                   tracejob
        :type id: str
        :param n: 'ALL' or the number of lines to search through,
                  defaults to 50
        :type n: str or int
        :param tail: If true (default), starts from the end of
                     the file
        :type tail: bool
        :param allmatch: If True all matching lines out of then
                         parsed are returned as a list. Defaults
                         to False
        :type allmatch: bool
        :param regexp: If true msg is a Python regular expression.
                       Defaults to False
        :type regexp: bool
        :param max_attempts: the number of attempts to make to find
                             a matching entry
        :type max_attempts: int
        :param interval: the interval between attempts
        :type interval: int
        :param starttime: If set ignore matches that occur before
                          specified time
        :type starttime: float
        :param endtime: If set ignore matches that occur after
                        specified time
        :type endtime: float
        :param level: The logging level, defaults to INFO
        :type level: int
        :param existence: If True (default), check for existence of
                        given msg, else check for non-existence of
                        given msg.
        :type existence: bool

        :return: (x,y) where x is the matching line
                 number and y the line itself. If allmatch is True,
                 a list of tuples is returned.
        :rtype: tuple
        :raises PtlLogMatchError:
                When ``existence`` is True and given
                ``msg`` is not found in ``n`` line
                Or
                When ``existence`` is False and given
                ``msg`` found in ``n`` line.

        .. note:: The matching line number is relative to the record
                  number, not the absolute line number in the file.
        """
        try:
            from ptl.utils.pbs_logutils import PBSLogUtils
        except:
            _msg = 'error loading ptl.utils.pbs_logutils'
            raise ImportError(_msg)

        if self.logutils is None:
            self.logutils = PBSLogUtils()
        if max_attempts is None:
            max_attempts = self.ptl_conf['max_attempts']
        if interval is None:
            interval = self.ptl_conf['attempt_interval']
        rv = (None, None)
        attempt = 1
        lines = None
        name = self._instance_to_servicename(logtype)
        infomsg = (name + ' ' + self.shortname +
                   ' log match: searching for "' + msg + '"')
        if regexp:
            infomsg += ' - using regular expression '
        if allmatch:
            infomsg += ' - on all matches '
        if existence:
            infomsg += ' - with existence'
        else:
            infomsg += ' - with non-existence'
        attemptmsg = ' - No match'
        while attempt <= max_attempts:
            if attempt > 1:
                attemptmsg = ' - attempt ' + str(attempt)
            lines = self.log_lines(logtype, id, n=n, tail=tail,
                                   starttime=starttime, endtime=endtime)
            rv = self.logutils.match_msg(lines, msg, allmatch=allmatch,
                                         regexp=regexp, starttime=starttime,
                                         endtime=endtime)
            if not existence:
                if rv:
                    _msg = infomsg + ' - but exists'
                    raise PtlLogMatchError(rc=1, rv=False, msg=_msg)
                else:
                    self.logger.log(level, infomsg + attemptmsg + '... OK')
                    break
            if rv:
                self.logger.log(level, infomsg + '... OK')
                break
            else:
                if n != 'ALL':
                    if attempt > max_attempts:
                        # We will do one last attempt to match in case the
                        # number of lines that were provided did not capture
                        # the start or end time of interest
                        max_attempts += 1
                    n = 'ALL'
                self.logger.log(level, infomsg + attemptmsg)
            attempt += 1
            time.sleep(interval)
        try:
            # Depending on whether the hostname is local or remote and whether
            # sudo privileges were required, lines returned by log_lines can be
            # an open file descriptor, we close here but ignore errors in case
            # any were raised for all irrelevant cases
            lines.close()
        except:
            pass
        if (rv is None and existence):
            _msg = infomsg + attemptmsg
            raise PtlLogMatchError(rc=1, rv=False, msg=_msg)
        return rv

    def accounting_match(self, msg, id=None, n=50, tail=True,
                         allmatch=False, regexp=False, max_attempts=None,
                         interval=None, starttime=None, endtime=None,
                         level=logging.INFO, existence=True):
        """
        Match given ``msg`` in given ``n`` lines of accounting log

        :param msg: log message to match, can be regex also when
                    ``regexp`` is True
        :type msg: str
        :param id: The id of the object to trace. Only used for
                   tracejob
        :type id: str
        :param n: 'ALL' or the number of lines to search through,
                  defaults to 50
        :type n: str or int
        :param tail: If true (default), starts from the end of
                     the file
        :type tail: bool
        :param allmatch: If True all matching lines out of then
                         parsed are returned as a list. Defaults
                         to False
        :type allmatch: bool
        :param regexp: If true msg is a Python regular expression.
                       Defaults to False
        :type regexp: bool
        :param max_attempts: the number of attempts to make to find
                             a matching entry
        :type max_attempts: int
        :param interval: the interval between attempts
        :type interval: int
        :param starttime: If set ignore matches that occur before
                          specified time
        :type starttime: int
        :param endtime: If set ignore matches that occur after
                        specified time
        :type endtime: int
        :param level: The logging level, defaults to INFO
        :type level: int
        :param existence: If True (default), check for existence of
                        given msg, else check for non-existence of
                        given msg.
        :type existence: bool

        :return: (x,y) where x is the matching line
                 number and y the line itself. If allmatch is True,
                 a list of tuples is returned.
        :rtype: tuple
        :raises PtlLogMatchError:
                When ``existence`` is True and given
                ``msg`` is not found in ``n`` line
                Or
                When ``existence`` is False and given
                ``msg`` found in ``n`` line.

        .. note:: The matching line number is relative to the record
                  number, not the absolute line number in the file.
        """
        return self._log_match('accounting', msg, id, n, tail, allmatch,
                               regexp, max_attempts, interval, starttime,
                               endtime, level, existence)

    def tracejob_match(self, msg, id=None, n=50, tail=True,
                       allmatch=False, regexp=False, max_attempts=None,
                       interval=None, starttime=None, endtime=None,
                       level=logging.INFO, existence=True):
        """
        Match given ``msg`` in given ``n`` lines of tracejob log

        :param msg: log message to match, can be regex also when
                    ``regexp`` is True
        :type msg: str
        :param id: The id of the object to trace.
        :type id: str
        :param n: 'ALL' or the number of lines to search through,
                  defaults to 50
        :type n: str or int
        :param tail: If true (default), starts from the end of
                     the file
        :type tail: bool
        :param allmatch: If True all matching lines out of then
                         parsed are returned as a list. Defaults
                         to False
        :type allmatch: bool
        :param regexp: If true msg is a Python regular expression.
                       Defaults to False
        :type regexp: bool
        :param max_attempts: the number of attempts to make to find
                             a matching entry
        :type max_attempts: int
        :param interval: the interval between attempts
        :type interval: int
        :param starttime: If set ignore matches that occur before
                          specified time
        :type starttime: float
        :param endtime: If set ignore matches that occur after
                        specified time
        :type endtime: float
        :param level: The logging level, defaults to INFO
        :type level: int
        :param existence: If True (default), check for existence of
                        given msg, else check for non-existence of
                        given msg.
        :type existence: bool

        :return: (x,y) where x is the matching line
                 number and y the line itself. If allmatch is True,
                 a list of tuples is returned.
        :rtype: tuple
        :raises PtlLogMatchError:
                When ``existence`` is True and given
                ``msg`` is not found in ``n`` line
                Or
                When ``existence`` is False and given
                ``msg`` found in ``n`` line.

        .. note:: The matching line number is relative to the record
                  number, not the absolute line number in the file.
        """
        return self._log_match('tracejob', msg, id, n, tail, allmatch,
                               regexp, max_attempts, interval, starttime,
                               endtime, level, existence)

    def _save_config_file(self, dict_conf, fname):
        ret = self.du.cat(self.hostname, fname, sudo=True)
        if ret['rc'] == 0:
            dict_conf[fname] = ret['out']
        else:
            self.logger.error('error saving configuration ' + fname)

    def _load_configuration(self, infile, objtype=None):
        """
        Load configuration as was saved in infile

        :param infile: the file in which configuration
                       was saved
        :type infile: str
        :param objtype: the object type to load configuration
                        for, one of server, scheduler, mom or
                        if None, load all objects in infile
        """
        if os.path.isfile(infile):
            conf = {}
            sconf = {}
            with open(infile, 'r') as f:
                try:
                    sconf = json.load(f)
                except ValueError:
                    self.logger.info("Error loading JSON file: %s"
                                     % infile)
                    return False
            conf = sconf[str(objtype)]
            if objtype == MGR_OBJ_SERVER:
                qmgr = os.path.join(self.client_conf['PBS_EXEC'],
                                    'bin', 'qmgr')
                for k, v in conf.items():
                    # Load server configuration
                    if k.startswith('qmgr_'):
                        fpath = self.du.create_temp_file()
                        print_svr = '\n'.join(v)
                        with open(fpath, 'w') as f:
                            f.write(print_svr)
                        file_qmgr = open(fpath)
                        d = self.du.run_cmd(
                            self.hostname, [qmgr], stdin=file_qmgr, sudo=True,
                            logerr=False, level=logging.DEBUG)
                        err_msg = "Failed to load server configurations"
                        file_qmgr.close()
                        if d['rc'] != 0:
                            self.logger.error("%s" % err_msg)
                            return False
                    # Load pbs.conf file
                    elif k == "pbs_conf":
                        enc_utf = v.encode('UTF-8')
                        dec_b64 = base64.b64decode(enc_utf)
                        cfg_vals = dec_b64.decode('UTF-8')
                        config = ast.literal_eval(cfg_vals)
                        self.du.set_pbs_config(self.hostname, confs=config)
                    # Load hooks
                    elif k == "hooks":
                        fpath = self.du.create_temp_file()
                        print_hooks = '\n'.join(v['qmgr_print_hook'])
                        with open(fpath, 'w') as f:
                            f.write(print_hooks)
                        file_qmgr = open(fpath)
                        d = self.du.run_cmd(
                            self.hostname, [qmgr], stdin=file_qmgr, sudo=True,
                            level=logging.DEBUG)
                        file_qmgr.close()
                        if d['rc'] != 0:
                            self.logger.error("Failed to load site hooks")
                if 'pbsnodes' in conf:
                    nodes = conf['pbsnodes']
                    for node in nodes:
                        node_name = str(node['id'])
                        nodes_created = self.create_pbsnode(node_name, node)
                        if not nodes_created:
                            self.logger.error("Failed to create node: %s"
                                              % node)
                            return False
                return True
            elif objtype == MGR_OBJ_SCHED:
                for k, v in conf.items():
                    fn = self.du.create_temp_file()
                    try:
                        rv = self.du.chmod(path=fn, mode=0o644)
                        if not rv:
                            self.logger.error("Failed to restore " +
                                              "configuration: %s" % k)
                            return False
                        with open(fn, 'w') as fd:
                            fd.write("\n".join(v))
                        rv = self.du.run_copy(
                            self.hostname, src=fn, dest=k, sudo=True)
                        if rv['rc'] != 0:
                            self.logger.error("Failed to restore " +
                                              "configuration: %s" % k)
                            return False
                        rv = self.du.chown(path=k, runas=ROOT_USER,
                                           uid=0, gid=0, sudo=True)
                        if not rv:
                            self.logger.error("Failed to restore " +
                                              "configuration: %s" % k)
                            return False
                    except:
                        self.logger.error("Failed to restore " +
                                          "configuration: %s" % k)
                        return False
                    finally:
                        if os.path.isfile(fn):
                            self.du.rm(path=fn, force=True, sudo=True)
                return True
            elif objtype == MGR_OBJ_NODE:
                nconf = conf[str(self.hostname)]
                for k, v in nconf.items():
                    try:
                        fn = self.du.create_temp_file()
                        rv = self.du.chmod(path=fn, mode=0o644)
                        if not rv:
                            self.logger.error("Failed to restore " +
                                              "configuration: %s" % k)
                            return False
                        with open(fn, 'w') as fd:
                            mom_config_data = "\n".join(v) + "\n"
                            fd.write(mom_config_data)
                        rv = self.du.run_copy(
                            self.hostname, src=fn, dest=k, sudo=True)
                        if rv['rc'] != 0:
                            self.logger.error("Failed to restore " +
                                              "configuration: %s" % k)
                            return False
                        rv = self.du.chown(path=k, runas=ROOT_USER,
                                           uid=0, gid=0, sudo=True)
                        if not rv:
                            self.logger.error("Failed to restore " +
                                              "configuration: %s" % k)
                            return False
                    except:
                        self.logger.error("Failed to restore " +
                                          "configuration: %s" % k)
                        return False
                    finally:
                        if os.path.isfile(fn):
                            self.du.rm(path=fn, force=True, sudo=True)
                return True

    def create_pbsnode(self, node_name, attrs):
        """
        Create node in PBS with given attributes
        """
        qmgr = os.path.join(self.client_conf['PBS_EXEC'],
                            'bin', 'qmgr')
        execcmd = "create node " + node_name
        execcmd += " Port=" + attrs['Port']
        cmd = [qmgr, "-c", execcmd]
        ret = self.du.run_cmd(self.hostname, cmd, sudo=True)
        if ret['rc'] != 0:
            self.logger.info("Failed to create node: %s" % node_name)
            self.logger.error("Error: %s" % ret['err'])
            return False
        # skip all read-only attributes
        skip_atb_list = ['id', 'pbs_version', 'pcpus',
                         'last_state_change_time', 'ntype',
                         'Mom', 'sharing', 'resources_available.vnode',
                         'resources_available.host', 'last_used_time',
                         'resource_assigned', 'resv', 'Port'
                         ]
        for node_atb, val in attrs.items():
            # only offline state of node is read, write attribute
            if(node_atb in skip_atb_list or
               'resources_assigned' in node_atb or
               (node_atb == 'state' and val != 'offline')):
                continue
            k = str(node_atb)
            v = str(val)
            execcmd = "set node %s %s='%s'" % (node_name, k, v)
            cmd = [qmgr, "-c", execcmd]
            ret = self.du.run_cmd(self.hostname, cmd, sudo=True,
                                  level=logging.DEBUG)
            if ret['rc'] != 0:
                self.logger.info("Failed to set node attribute %s=%s" % (k, v))
                return False
        return True

    def get_tempdir(self):
        """
        platform independent call to get a temporary directory
        """
        return self.du.get_tempdir(self.hostname)

    def __str__(self):
        return (self.__class__.__name__ + ' ' + self.hostname + ' config ' +
                self.pbs_conf_file)

    def __repr__(self):
        return (self.__class__.__name__ + '/' + self.pbs_conf_file + '@' +
                self.hostname)

    def cleanup_files(self):
        """
        This function removes any dynamic resource files created by server/mom
        objects
        """
        for dyn_files in self.dyn_created_files:
            self.du.rm(path=dyn_files, sudo=True, force=True)
        self.dyn_created_files = []



