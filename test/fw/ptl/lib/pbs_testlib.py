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


# suppress logging exceptions
logging.raiseExceptions = False

# Various mappings and aliases

MGR_OBJ_VNODE = MGR_OBJ_NODE

VNODE = MGR_OBJ_VNODE
NODE = MGR_OBJ_NODE
HOST = MGR_OBJ_HOST
JOB = MGR_OBJ_JOB
RESV = MGR_OBJ_RESV
SERVER = MGR_OBJ_SERVER
QUEUE = MGR_OBJ_QUEUE
SCHED = MGR_OBJ_SCHED
HOOK = MGR_OBJ_HOOK
RSC = MGR_OBJ_RSC
PBS_HOOK = MGR_OBJ_PBS_HOOK

# the order of these symbols matters, see pbs_ifl.h
(SET, UNSET, INCR, DECR, EQ, NE, GE, GT,
 LE, LT, MATCH, MATCH_RE, NOT, DFLT) = list(range(14))

(PTL_OR, PTL_AND) = [0, 1]

(IFL_SUBMIT, IFL_SELECT, IFL_TERMINATE, IFL_ALTER,
 IFL_MSG, IFL_DELETE, IFL_RALTER) = [0, 1, 2, 3, 4, 5, 6]

(PTL_API, PTL_CLI) = ['api', 'cli']

(PTL_COUNTER, PTL_FILTER) = [0, 1]

PTL_STR_TO_OP = {
    '<': LT,
    '<=': LE,
    '=': EQ,
    '>=': GE,
    '>': GT,
    '!=': NE,
    ' set ': SET,
    ' unset ': UNSET,
    ' match ': MATCH,
    '~': MATCH_RE,
    '!': NOT
}

PTL_OP_TO_STR = {
    LT: '<',
    LE: '<=',
    EQ: '=',
    GE: '>=',
    GT: '>',
    SET: ' set ',
    NE: '!=',
    UNSET: ' unset ',
    MATCH: ' match ',
    MATCH_RE: '~',
    NOT: 'is not'
}

PTL_ATTROP_TO_STR = {PTL_AND: '&&', PTL_OR: '||'}

(RESOURCES_AVAILABLE, RESOURCES_TOTAL) = [0, 1]

EXPECT_MAP = {
    UNSET: 'Unset',
    SET: 'Set',
    EQ: 'Equal',
    NE: 'Not Equal',
    LT: 'Less Than',
    GT: 'Greater Than',
    LE: 'Less Equal Than',
    GE: 'Greater Equal Than',
    MATCH_RE: 'Matches regexp',
    MATCH: 'Matches',
    NOT: 'Not'
}

PBS_CMD_MAP = {
    MGR_CMD_CREATE: 'create',
    MGR_CMD_SET: 'set',
    MGR_CMD_DELETE: 'delete',
    MGR_CMD_UNSET: 'unset',
    MGR_CMD_IMPORT: 'import',
    MGR_CMD_EXPORT: 'export',
    MGR_CMD_LIST: 'list',
}

PBS_CMD_TO_OP = {
    MGR_CMD_SET: SET,
    MGR_CMD_UNSET: UNSET,
    MGR_CMD_DELETE: UNSET,
    MGR_CMD_CREATE: SET,
}

PBS_OBJ_MAP = {
    MGR_OBJ_NONE: 'none',
    SERVER: 'server',
    QUEUE: 'queue',
    JOB: 'job',
    NODE: 'node',
    RESV: 'reservation',
    RSC: 'resource',
    SCHED: 'sched',
    HOST: 'host',
    HOOK: 'hook',
    VNODE: 'node',
    PBS_HOOK: 'pbshook'
}

PTL_TRUE = ('1', 'true', 't', 'yes', 'y', 'enable', 'enabled', 'True', True)
PTL_FALSE = ('0', 'false', 'f', 'no', 'n', 'disable', 'disabled', 'False',
             False)
PTL_NONE = ('None', None)
PTL_FORMULA = '__formula__'
PTL_NOARG = '__noarg__'
PTL_ALL = '__ALL__'

CMD_ERROR_MAP = {
    'alterjob': 'PbsAlterError',
    'holdjob': 'PbsHoldError',
    'sigjob': 'PbsSignalError',
    'msgjob': 'PbsMessageError',
    'rlsjob': 'PbsReleaseError',
    'rerunjob': 'PbsRerunError',
    'orderjob': 'PbsOrderError',
    'runjob': 'PbsRunError',
    'movejob': 'PbsMoveError',
    'delete': 'PbsDeleteError',
    'deljob': 'PbsDeljobError',
    'delresv': 'PbsDelresvError',
    'status': 'PbsStatusError',
    'manager': 'PbsManagerError',
    'submit': 'PbsSubmitError',
    'terminate': 'PbsQtermError',
    'alterresv': 'PbsResvAlterError'
}

from ptl.lib.ptl_exception import *
from ptl.lib.pbs_error import *
from ptl.lib.expect_action import *
from ptl.lib.batch_utils import *
from ptl.lib.pbs_type import *
from ptl.lib.pbsobject import *
from ptl.lib.pbs_init_service import *
from ptl.lib.pbs_service import PBSService





class PtlConfig(object):

    """
    Holds configuration options
    The options can be stored in a file as well as in the OS environment
    variables.When set, the environment variables will override
    definitions in the file.By default, on Unix like systems, the file
    read is ``/etc/ptl.conf``, the environment variable ``PTL_CONF_FILE``
    can be used to set the path to the file to read.

    The format of the file is a series of ``<key> = <value>`` properties.
    A line that starts with a '#' is ignored and can be used for comments

    :param conf: Path to PTL configuration file
    :type conf: str or None
    """
    logger = logging.getLogger(__name__)

    def __init__(self, conf=None):
        self.options = {
            'PTL_SUDO_CMD': 'sudo -H',
            'PTL_RSH_CMD': 'ssh',
            'PTL_CP_CMD': 'scp -p',
            'PTL_MAX_ATTEMPTS': 180,
            'PTL_ATTEMPT_INTERVAL': 0.5,
            'PTL_UPDATE_ATTRIBUTES': True,
        }
        self.handlers = {
            'PTL_SUDO_CMD': DshUtils.set_sudo_cmd,
            'PTL_RSH_CMD': DshUtils.set_rsh_cmd,
            'PTL_CP_CMD': DshUtils.set_copy_cmd,
            'PTL_MAX_ATTEMPTS': PBSObject.set_max_attempts,
            'PTL_ATTEMPT_INTERVAL': PBSObject.set_attempt_interval,
            'PTL_UPDATE_ATTRIBUTES': PBSObject.set_update_attributes
        }
        if conf is None:
            conf = os.environ.get('PTL_CONF_FILE', '/etc/ptl.conf')
        try:
            with open(conf) as f:
                lines = f.readlines()
        except IOError:
            lines = []
        for line in lines:
            line = line.strip()
            if (line.startswith('#') or (line == '')):
                continue
            try:
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip()
                self.options[k] = v
            except:
                self.logger.error('Error parsing line ' + line)
        # below two if block are for backword compatibility
        if 'PTL_EXPECT_MAX_ATTEMPTS' in self.options:
            _o = self.options['PTL_EXPECT_MAX_ATTEMPTS']
            _m = self.options['PTL_MAX_ATTEMPTS']
            _e = os.environ.get('PTL_EXPECT_MAX_ATTEMPTS', _m)
            del self.options['PTL_EXPECT_MAX_ATTEMPTS']
            self.options['PTL_MAX_ATTEMPTS'] = max([int(_o), int(_m), int(_e)])
            _msg = 'PTL_EXPECT_MAX_ATTEMPTS is deprecated,'
            _msg += ' use PTL_MAX_ATTEMPTS instead'
            self.logger.warn(_msg)
        if 'PTL_EXPECT_INTERVAL' in self.options:
            _o = self.options['PTL_EXPECT_INTERVAL']
            _m = self.options['PTL_ATTEMPT_INTERVAL']
            _e = os.environ.get('PTL_EXPECT_INTERVAL', _m)
            del self.options['PTL_EXPECT_INTERVAL']
            self.options['PTL_ATTEMPT_INTERVAL'] = \
                max([int(_o), int(_m), int(_e)])
            _msg = 'PTL_EXPECT_INTERVAL is deprecated,'
            _msg += ' use PTL_ATTEMPT_INTERVAL instead'
            self.logger.warn(_msg)
        for k, v in self.options.items():
            if k in os.environ:
                v = os.environ[k]
            else:
                os.environ[k] = str(v)
            if k in self.handlers:
                self.handlers[k](v)


class PbsAttribute(object):
    """
    Descriptor class for PBS attribute

    :param name: PBS attribute name
    :type name: str
    :param value: Value for the attribute
    :type value: str or int or float
    """
    utils = BatchUtils()

    def __init__(self, name=None, value=None):
        self.set_name(name)
        self.set_value(value)

    def set_name(self, name):
        """
        Set PBS attribute name

        :param name: PBS attribute
        :type name: str
        """
        self.name = name
        if name is not None and '.' in name:
            self.is_resource = True
            self.resource_type, self.resource_name = self.name.split('.')
        else:
            self.is_resource = False
            self.resource_type = self.resource_name = None

    def set_value(self, value):
        """
        Set PBS attribute value

        :param value: Value of PBS attribute
        :type value: str or int or float
        """
        self.value = value
        if isinstance(value, (int, float)) or str(value).isdigit():
            self.is_consumable = True
        else:
            self.is_consumable = False

    def obfuscate_name(self, a=None):
        """
        Obfuscate PBS attribute name
        """
        if a is not None:
            on = a
        else:
            on = self.utils.random_str(len(self.name))

        self.decoded_name = self.name
        if self.is_resource:
            self.set_name(self.resource_name + '.' + on)

    def obfuscate_value(self, v=None):
        """
        Obfuscate PBS attribute value
        """
        if not self.is_consuable:
            self.decoded_value = self.value
            return

        if v is not None:
            ov = v
        else:
            ov = self.utils.random_str(len(self.value))

        self.decoded_value = self.value
        self.set_value(ov)


class Entity(object):

    """
    Abstract representation of a PBS consumer that has an
    external relationship to the PBS system. For example, a
    user associated to an OS identifier (uid) maps to a PBS
    user entity.

    Entities may be subject to policies, such as limits, consume
    a certain amount of resource and/or fairshare usage.

    :param etype: Entity type
    :type etype: str or None
    :param name: Entity name
    :type name: str or None
    """

    def __init__(self, etype=None, name=None):
        self.type = etype
        self.name = name
        self.limits = []
        self.resource_usage = {}
        self.fairshare_usage = 0

    def set_limit(self, limit=None):
        """
        :param limit: Limit to be set
        :type limit: str or None
        """
        for l in self.limits:
            if str(limit) == str(l):
                return
        self.limits.append(limit)

    def set_resource_usage(self, container=None, resource=None, usage=None):
        """
        Set the resource type

        :param resource: PBS resource
        :type resource: str or None
        :param usage: Resource usage value
        :type usage: str or None
        """
        if self.type:
            if container in self.resource_usage:
                if self.resource_usage[self.type]:
                    if resource in self.resource_usage[container]:
                        self.resource_usage[container][resource] += usage
                    else:
                        self.resource_usage[container][resource] = usage
                else:
                    self.resource_usage[container] = {resource: usage}

    def set_fairshare_usage(self, usage=0):
        """
        Set fairshare usage

        :param usage: Fairshare usage value
        :type usage: int
        """
        self.fairshare_usage += usage

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return str(self.limits) + ' ' + str(self.resource_usage) + ' ' + \
            str(self.fairshare_usage)


class Policy(object):

    """
    Abstract PBS policy. Can be one of ``limits``,
    ``access control``, ``scheduling policy``, etc...this
    class does not currently support any operations
    """

    def __init__(self):
        pass


class Limit(Policy):

    """
    Representation of a PBS limit
    Limits apply to containers, are of a certain type
    (e.g., max_run_res.ncpus) associated to a given resource
    (e.g., resource), on a given entity (e.g.,user Bob) and
    have a certain value.

    :param limit_type: Type of the limit
    :type limit_type: str or None
    :param resource: PBS resource
    :type resource: str or None
    :param entity_obj: Entity object
    :param value: Limit value
    :type value: int
    """

    def __init__(self, limit_type=None, resource=None,
                 entity_obj=None, value=None, container=None,
                 container_id=None):
        self.set_container(container, container_id)
        self.soft_limit = False
        self.hard_limit = False
        self.set_limit_type(limit_type)
        self.set_resource(resource)
        self.set_value(value)
        self.entity = entity_obj

    def set_container(self, container, container_id):
        """
        Set the container

        :param container: Container which is to be set
        :type container: str
        :param container_id: Container id
        """
        self.container = container
        self.container_id = container_id

    def set_limit_type(self, t):
        """
        Set the limit type

        :param t: Limit type
        :type t: str
        """
        self.limit_type = t
        if '_soft' in t:
            self.soft_limit = True
        else:
            self.hard_limit = True

    def set_resource(self, resource):
        """
        Set the resource

        :param resource: resource value to set
        :type resource: str
        """
        self.resource = resource

    def set_value(self, value):
        """
        Set the resource value

        :param value: Resource value
        :type value: str
        """
        self.value = value

    def __eq__(self, value):
        if str(self) == str(value):
            return True
        return False

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        l = [self.container_id, self.limit_type, self.resource, '[',
             self.entity.type, ':', self.entity.name, '=', self.value, ']']
        return " ".join(l)


class Holidays():
    """
    Descriptive calss for Holiday file.
    """

    def __init__(self):
        self.year = {'id': "YEAR", 'value': None, 'valid': False}
        self.weekday = {'id': "weekday", 'p': None, 'np': None, 'valid': None,
                        'position': None}
        self.monday = {'id': "monday", 'p': None, 'np': None, 'valid': None,
                       'position': None}
        self.tuesday = {'id': "tuesday", 'p': None, 'np': None, 'valid': None,
                        'position': None}
        self.wednesday = {'id': "wednesday", 'p': None, 'np': None,
                          'valid': None, 'position': None}
        self.thursday = {'id': "thursday", 'p': None, 'np': None,
                         'valid': None, 'position': None}
        self.friday = {'id': "friday", 'p': None, 'np': None, 'valid': None,
                       'position': None}
        self.saturday = {'id': "saturday", 'p': None, 'np': None,
                         'valid': None, 'position': None}
        self.sunday = {'id': "sunday", 'p': None, 'np': None, 'valid': None,
                       'position': None}

        self.days_set = []  # list of set days
        self._days_map = {'weekday': self.weekday, 'monday': self.monday,
                          'tuesday': self.tuesday, 'wednesday': self.wednesday,
                          'thursday': self.thursday, 'friday': self.friday,
                          'saturday': self.saturday, 'sunday': self.sunday}
        self.holidays = []  # list of calendar holidays

    def __str__(self):
        """
        Return the content to write to holidays file as a string
        """
        content = []
        if self.year['valid']:
            content.append(self.year['id'] + "\t" +
                           self.year['value'])

        for i in range(0, len(self.days_set)):
            content.append(self.days_set[i]['id'] + "\t" +
                           self.days_set[i]['p'] + "\t" +
                           self.days_set[i]['np'])

        # Add calendar holidays
        for day in self.holidays:
            content.append(day)

        return "\n".join(content)

class Resource(PBSObject):

    """
    PBS resource referenced by name, type and flag

    :param name: Resource name
    :type name: str or None
    :param type: Type of resource
    """

    def __init__(self, name=None, type=None, flag=None):
        PBSObject.__init__(self, name)
        self.set_name(name)
        self.set_type(type)
        self.set_flag(flag)

    def __del__(self):
        del self.__dict__

    def set_name(self, name):
        """
        Set the resource name
        """
        self.name = name
        self.attributes['id'] = name

    def set_type(self, type):
        """
        Set the resource type
        """
        self.type = type
        self.attributes['type'] = type

    def set_flag(self, flag):
        """
        Set the flag
        """
        self.flag = flag
        self.attributes['flag'] = flag

    def __str__(self):
        s = [self.attributes['id']]
        if 'type' in self.attributes:
            s.append('type=' + self.attributes['type'])
        if 'flag' in self.attributes:
            s.append('flag=' + self.attributes['flag'])
        return " ".join(s)


class EquivClass(PBSObject):

    """
    Equivalence class holds information on a collection of entities
    grouped according to a set of attributes
    :param attributes: Dictionary of attributes
    :type attributes: Dictionary
    :param entities: List of entities
    :type entities: List
    """

    def __init__(self, name, attributes={}, entities=[]):
        self.name = name
        self.attributes = attributes
        self.entities = entities

    def add_entity(self, entity):
        """
        Add entities

        :param entity: Entity to add
        :type entity: str
        """
        if entity not in self.entities:
            self.entities.append(entity)

    def __str__(self):
        s = [str(len(self.entities)), ":", ":".join(self.name)]
        return "".join(s)

    def show(self, showobj=False):
        """
        Show the entities

        :param showobj: If true then show the entities
        :type showobj: bool
        """
        s = " && ".join(self.name) + ': '
        if showobj:
            s += str(self.entities)
        else:
            s += str(len(self.entities))
        print(s)
        return s


class ResourceResv(PBSObject):

    """
    Generic PBS resource reservation, i.e., job or
    ``advance/standing`` reservation
    """

    def execvnode(self, attr='exec_vnode'):
        """
        PBS type execution vnode
        """
        if attr in self.attributes:
            return PbsTypeExecVnode(self.attributes[attr])
        else:
            return None

    def exechost(self):
        """
        PBS type execution host
        """
        if 'exec_host' in self.attributes:
            return PbsTypeExecHost(self.attributes['exec_host'])
        else:
            return None

    def resvnodes(self):
        """
        nodes assigned to a reservation
        """
        if 'resv_nodes' in self.attributes:
            return self.attributes['resv_nodes']
        else:
            return None

    def select(self):
        if hasattr(self, '_select') and self._select is not None:
            return self._select

        if 'schedselect' in self.attributes:
            self._select = PbsTypeSelect(self.attributes['schedselect'])

        elif 'select' in self.attributes:
            self._select = PbsTypeSelect(self.attributes['select'])
        else:
            return None

        return self._select

    @classmethod
    def get_hosts(cls, exechost=None):
        """
        :returns: The hosts portion of the exec_host
        """
        hosts = []
        exechosts = cls.utils.parse_exechost(exechost)
        if exechosts:
            for h in exechosts:
                eh = list(h.keys())[0]
                if eh not in hosts:
                    hosts.append(eh)
        return hosts

    def get_vnodes(self, execvnode=None):
        """
        :returns: The unique vnode names of an execvnode as a list
        """
        if execvnode is None:
            if 'exec_vnode' in self.attributes:
                execvnode = self.attributes['exec_vnode']
            elif 'resv_nodes' in self.attributes:
                execvnode = self.attributes['resv_nodes']
            else:
                return []

        vnodes = []
        execvnodes = PbsTypeExecVnode(execvnode)
        if execvnodes:
            for n in execvnodes:
                ev = list(n.keys())[0]
                if ev not in vnodes:
                    vnodes.append(ev)
        return vnodes

    def walltime(self, attr='Resource_List.walltime'):
        if attr in self.attributes:
            return self.utils.convert_duration(self.attributes[attr])


class Job(ResourceResv):

    """
    PBS Job. Attributes and Resources

    :param username: Job username
    :type username: str or None
    :param attrs: Job attributes
    :type attrs: Dictionary
    :param jobname: Name of the PBS job
    :type jobname: str or None
    """

    dflt_attributes = {
        ATTR_N: 'STDIN',
        ATTR_j: 'n',
        ATTR_m: 'a',
        ATTR_p: '0',
        ATTR_r: 'y',
        ATTR_k: 'oe',
    }
    runtime = 100
    du = DshUtils()

    def __init__(self, username=TEST_USER, attrs={}, jobname=None):
        self.platform = self.du.get_platform()
        self.server = {}
        self.script = None
        self.script_body = None
        if username is not None:
            self.username = str(username)
        else:
            self.username = None
        self.du = None
        self.interactive_handle = None
        if self.platform == 'cray' or self.platform == 'craysim':
            if 'Resource_List.select' in attrs:
                select = attrs['Resource_List.select']
                attrs['Resource_List.select'] = self.add_cray_vntype(select)
            elif 'Resource_List.vntype' not in attrs:
                attrs['Resource_List.vntype'] = 'cray_compute'

        PBSObject.__init__(self, None, attrs, self.dflt_attributes)

        if jobname is not None:
            self.custom_attrs[ATTR_N] = jobname
            self.attributes[ATTR_N] = jobname
        self.set_variable_list(self.username)
        self.set_sleep_time(100)

    def __del__(self):
        del self.__dict__

    def add_cray_vntype(self, select=None):
        """
        Cray specific function to add vntype as ``cray_compute`` to each
        select chunk

        :param select: PBS select statement
        :type select: str or None
        """
        ra = []
        r = select.split('+')
        for i in r:
            select = PbsTypeSelect(i)
            novntype = 'vntype' not in select.resources
            nohost = 'host' not in select.resources
            novnode = 'vnode' not in select.resources
            if novntype and nohost and novnode:
                i = i + ":vntype=cray_compute"
            ra.append(i)
        select_str = ''
        for l in ra:
            select_str = select_str + "+" + l
        select_str = select_str[1:]
        return select_str

    def set_attributes(self, a={}):
        """
        set attributes and custom attributes on this job.
        custom attributes are used when converting attributes to CLI.
        In case of Cray platform if 'Resource_List.vntype' is set
        already then remove it and add vntype value to each chunk of a
        select statement.

        :param a: Attribute dictionary
        :type a: Dictionary
        """
        if isinstance(a, list):
            a = OrderedDict(a)

        self.attributes = OrderedDict(list(self.dflt_attributes.items()) +
                                      list(self.attributes.items()) +
                                      list(a.items()))

        if self.platform == 'cray' or self.platform == 'craysim':
            s = 'Resource_List.select' in a
            v = 'Resource_List.vntype' in self.custom_attrs
            if s and v:
                del self.custom_attrs['Resource_List.vntype']
                select = a['Resource_List.select']
                a['Resource_List.select'] = self.add_cray_vntype(select)

        self.custom_attrs = OrderedDict(list(self.custom_attrs.items()) +
                                        list(a.items()))

    def set_variable_list(self, user=None, workdir=None):
        """
        Customize the ``Variable_List`` job attribute to ``<user>``
        """
        if user is None:
            userinfo = pwd.getpwuid(os.getuid())
            user = userinfo[0]
            homedir = userinfo[5]
        else:
            try:
                homedir = pwd.getpwnam(user)[5]
            except:
                homedir = ""

        self.username = user

        s = ['PBS_O_HOME=' + homedir]
        s += ['PBS_O_LANG=en_US.UTF-8']
        s += ['PBS_O_LOGNAME=' + user]
        s += ['PBS_O_PATH=/usr/bin:/bin:/usr/bin:/usr/local/bin']
        s += ['PBS_O_MAIL=/var/spool/mail/' + user]
        s += ['PBS_O_SHELL=/bin/bash']
        s += ['PBS_O_SYSTEM=Linux']
        if workdir is not None:
            wd = workdir
        else:
            wd = os.getcwd()
        s += ['PBS_O_WORKDIR=' + str(wd)]

        self.attributes[ATTR_v] = ",".join(s)
        self.set_attributes()

    def set_sleep_time(self, duration):
        """
        Set the sleep duration for this job.

        :param duration: The duration, in seconds, to sleep
        :type duration: int
        """
        self.set_execargs('/bin/sleep', duration)

    def set_execargs(self, executable, arguments=None):
        """
        Set the executable and arguments to use for this job

        :param executable: path to an executable. No checks are made.
        :type executable: str
        :param arguments: arguments to executable.
        :type arguments: str or list or int
        """
        msg = ['job: executable set to ' + str(executable)]
        if arguments is not None:
            msg += [' with arguments: ' + str(arguments)]

        self.logger.info("".join(msg))
        self.attributes[ATTR_executable] = executable
        if arguments is not None:
            args = ''
            xml_beginargs = '<jsdl-hpcpa:Argument>'
            xml_endargs = '</jsdl-hpcpa:Argument>'
            if isinstance(arguments, list):
                for a in arguments:
                    args += xml_beginargs + str(a) + xml_endargs
            elif isinstance(arguments, str):
                args = xml_beginargs + arguments + xml_endargs
            elif isinstance(arguments, int):
                args = xml_beginargs + str(arguments) + xml_endargs
            self.attributes[ATTR_Arglist] = args
        else:
            self.unset_attributes([ATTR_Arglist])
        self.set_attributes()

    def create_script(self, body=None, asuser=None, hostname=None):
        """
        Create a job script from a given body of text into a
        temporary location

        :param body: the body of the script
        :type body: str or None
        :param asuser: Optionally the user to own this script,
                      defaults ot current user
        :type asuser: str or None
        :param hostname: The host on which the job script is to
                         be created
        :type hostname: str or None
        """

        if body is None:
            return None

        if isinstance(body, list):
            body = '\n'.join(body)

        if self.platform == 'cray' or self.platform == 'craysim':
            body = body.split("\n")
            for i, line in enumerate(body):
                if line.startswith("#PBS") and "select=" in line:
                    if 'Resource_List.vntype' in self.attributes:
                        self.unset_attributes(['Resource_List.vntype'])
                    line_arr = line.split(" ")
                    for j, element in enumerate(line_arr):
                        select = element.startswith("select=")
                        lselect = element.startswith("-lselect=")
                        if select or lselect:
                            if lselect:
                                sel_str = element[9:]
                            else:
                                sel_str = element[7:]
                            sel_str = self.add_cray_vntype(select=sel_str)
                            if lselect:
                                line_arr[j] = "-lselect=" + sel_str
                            else:
                                line_arr[j] = "select=" + sel_str
                    body[i] = " ".join(line_arr)
            body = '\n'.join(body)

        # If the user has a userhost, the job will run from there
        # so the script should be made there
        if self.username:
            user = PbsUser.get_user(self.username)
            if user.host:
                hostname = user.host
                asuser = user.name

        self.script_body = body
        if self.du is None:
            self.du = DshUtils()
        # First create the temporary file as current user and only change
        # its mode once the current user has written to it
        fn = self.du.create_temp_file(hostname, prefix='PtlPbsJobScript',
                                      asuser=asuser, body=body)
        self.du.chmod(hostname, fn, mode=0o755)
        self.script = fn
        return fn

    def create_subjob_id(self, job_array_id, subjob_index):
        """
        insert subjob index into the square brackets of job array id

        :param job_array_id: PBS parent array job id
        :type job_array_id: str
        :param subjob_index: index of subjob
        :type subjob_index: int
        :returns: subjob id string
        """
        idx = job_array_id.find('[]')
        return job_array_id[:idx + 1] + str(subjob_index) + \
            job_array_id[idx + 1:]

    def create_eatcpu_job(self, duration=None, hostname=None):
        """
        Create a job that eats cpu indefinitely or for the given
        duration of time

        :param duration: The duration, in seconds, to sleep
        :type duration: int
        :param hostname: hostname on which to execute the job
        :type hostname: str or None
        """
        if self.du is None:
            self.du = DshUtils()
        shebang_line = '#!' + self.du.which(hostname, exe='python3')
        body = """
import signal
import sys

x = 0


def receive_alarm(signum, stack):
    sys.exit()

signal.signal(signal.SIGALRM, receive_alarm)

if (len(sys.argv) > 1):
    input_time = sys.argv[1]
    print('Terminating after %s seconds' % input_time)
    signal.alarm(int(input_time))
else:
    print('Running indefinitely')

while True:
    x += 1
"""
        script_body = shebang_line + body
        script_path = self.du.create_temp_file(hostname=hostname,
                                               body=script_body,
                                               suffix='.py')
        if not self.du.is_localhost(hostname):
            d = pwd.getpwnam(self.username).pw_dir
            ret = self.du.run_copy(hosts=hostname, src=script_path, dest=d)
            if ret is None or ret['rc'] != 0:
                raise AssertionError("Failed to copy file %s to %s"
                                     % (script_path, hostname))
        pbs_conf = self.du.parse_pbs_config(hostname)
        shell_path = os.path.join(pbs_conf['PBS_EXEC'],
                                  'bin', 'pbs_python')
        a = {ATTR_S: shell_path}
        self.set_attributes(a)
        mode = 0o755
        if not self.du.chmod(hostname=hostname, path=script_path, mode=mode,
                             sudo=True):
            raise AssertionError("Failed to set permissions for file %s"
                                 " to %s" % (script_path, oct(mode)))
        self.set_execargs(script_path, duration)


class InteractiveJob(threading.Thread):

    """
    An Interactive Job thread

    Interactive Jobs are submitted as a thread that sets the jobid
    as soon as it is returned by ``qsub -I``, such that the caller
    can get back to monitoring the state of PBS while the interactive
    session goes on in the thread.

    The commands to be run within an interactive session are
    specified in the job's interactive_script attribute as a list of
    tuples, where the first item in each tuple is the command to run,
    and the subsequent items are the expected returned data.

    Implementation details:

    Support for interactive jobs is currently done through the
    pexpect module which must be installed separately from PTL.
    Interactive jobs are submitted through ``CLI`` only, there is no
    API support for this operation yet.

    The submission of an interactive job requires passing in job
    attributes,the command to execute ``(i.e. path to qsub -I)``
    and the hostname

    when not impersonating:

    pexpect spawns the ``qsub -I`` command and expects a prompt
    back, for each tuple in the interactive_script, it sends the
    command and expects to match the return value.

    when impersonating:

    pexpect spawns ``sudo -u <user> qsub -I``. The rest is as
    described in non- impersonating mode.
    """

    logger = logging.getLogger(__name__)

    pexpect_timeout = 15
    pexpect_sleep_time = .1
    du = DshUtils()

    def __init__(self, job, cmd, host):
        threading.Thread.__init__(self)
        self.job = job
        self.cmd = cmd
        self.jobid = None
        self.hostname = host
        self._ru = ""
        if self.du.get_platform() == "shasta":
            self._ru = PbsUser.get_user(job.username)
            if self._ru.host:
                self.hostname = self._ru.host

    def __del__(self):
        del self.__dict__

    def run(self):
        """
        Run the interactive job
        """
        try:
            import pexpect
        except:
            self.logger.error('pexpect module is required for '
                              'interactive jobs')
            return None

        job = self.job
        cmd = self.cmd

        self.jobid = None
        self.logger.info("submit interactive job as " + job.username +
                         ": " + " ".join(cmd))
        if not hasattr(job, 'interactive_script'):
            self.logger.debug('no interactive_script attribute on job')
            return None

        try:
            # sleep to allow server to communicate with client
            # this value is set empirically so tweaking may be
            # needed
            _st = self.pexpect_sleep_time
            _to = self.pexpect_timeout
            _sc = job.interactive_script
            current_user = pwd.getpwuid(os.getuid())[0]
            if current_user != job.username:
                if hasattr(job, 'preserve_env') and job.preserve_env is True:
                    cmd = (copy.copy(self.du.sudo_cmd) +
                           ['-E', '-u', job.username] + cmd)
                else:
                    cmd = (copy.copy(self.du.sudo_cmd) +
                           ['-u', job.username] + cmd)

            self.logger.debug(cmd)
            is_local = self.du.is_localhost(self.hostname)
            _p = ""
            if is_local:
                _p = pexpect.spawn(" ".join(cmd), timeout=_to)
            else:
                self.logger.info("Submit interactive job from a remote host")
                if self.du.get_platform() == "shasta":
                    ssh_cmd = self.du.rsh_cmd + \
                        ['-p', self._ru.port,
                         self._ru.name + '@' + self.hostname]
                    _p = pexpect.spawn(" ".join(ssh_cmd), timeout=_to)
                    _p.sendline(" ".join(self.cmd))
                else:
                    ssh_cmd = self.du.rsh_cmd + [self.hostname]
                    _p = pexpect.spawn(" ".join(ssh_cmd), timeout=_to)
                    _p.sendline(" ".join(cmd))
            self.job.interactive_handle = _p
            time.sleep(_st)
            expstr = "qsub: waiting for job "
            expstr += r"(?P<jobid>\d+.[0-9A-Za-z-.]+) to start"
            _p.expect(expstr)
            if _p.match:
                self.jobid = _p.match.group('jobid').decode()
            else:
                _p.close()
                self.job.interactive_handle = None
                return None
            self.logger.debug(_p.after.decode())
            for _l in _sc:
                (cmd, out) = _l
                self.logger.info('sending: ' + cmd)
                _p.sendline(cmd)
                self.logger.info('expecting: ' + out)
                _p.expect(out)
            self.logger.info('sending exit')
            _p.sendline("exit")
            while True:
                try:
                    _p.read_nonblocking(timeout=5)
                except Exception:
                    break
            if _p.isalive():
                _p.close()
            self.job.interactive_handle = None
        except Exception:
            self.logger.error(traceback.print_exc())
            return None
        return self.jobid


class Reservation(ResourceResv):

    """
    PBS Reservation. Attributes and Resources

    :param attrs: Reservation attributes
    :type attrs: Dictionary
    :param hosts: List of hosts for maintenance
    :type hosts: List
    """

    dflt_attributes = {}

    def __init__(self, username=TEST_USER, attrs=None, hosts=None):
        self.server = {}
        self.script = None

        if attrs:
            self.attributes = attrs
        else:
            self.attributes = {}

        if hosts:
            self.hosts = hosts
        else:
            self.hosts = []

        if username is None:
            userinfo = pwd.getpwuid(os.getuid())
            self.username = userinfo[0]
        else:
            self.username = str(username)

        # These are not in dflt_attributes because of the conversion to CLI
        # options is done strictly
        if ATTR_resv_start not in self.attributes and \
           ATTR_job not in self.attributes:
            self.attributes[ATTR_resv_start] = str(int(time.time()) +
                                                   36 * 3600)

        if ATTR_resv_end not in self.attributes and \
           ATTR_job not in self.attributes:
            if ATTR_resv_duration not in self.attributes:
                self.attributes[ATTR_resv_end] = str(int(time.time()) +
                                                     72 * 3600)

        PBSObject.__init__(self, None, self.attributes, self.dflt_attributes)
        self.set_attributes()

    def __del__(self):
        del self.__dict__

    def set_variable_list(self, user, workdir=None):
        pass


class Queue(PBSObject):

    """
    PBS Queue container, holds attributes of the queue and
    pointer to server

    :param name: Queue name
    :type name: str or None
    :param attrs: Queue attributes
    :type attrs: Dictionary
    """

    dflt_attributes = {}

    def __init__(self, name=None, attrs={}, server=None):
        PBSObject.__init__(self, name, attrs, self.dflt_attributes)

        self.server = server
        m = ['queue']
        if server is not None:
            m += ['@' + server.shortname]
        if self.name is not None:
            m += [' ', self.name]
        m += [': ']
        self.logprefix = "".join(m)

    def __del__(self):
        del self.__dict__

    def revert_to_defaults(self):
        """
        reset queue attributes to defaults
        """

        ignore_attrs = ['id', ATTR_count, ATTR_rescassn]
        ignore_attrs += [ATTR_qtype, ATTR_enable, ATTR_start, ATTR_total]
        ignore_attrs += ['THE_END']

        len_attrs = len(ignore_attrs)
        unsetlist = []
        setdict = {}

        self.logger.info(
            self.logprefix +
            "reverting configuration to defaults")
        if self.server is not None:
            self.server.status(QUEUE, id=self.name, level=logging.DEBUG)

        for k in self.attributes.keys():
            for i in range(len_attrs):
                if k.startswith(ignore_attrs[i]):
                    break
            if (i == (len_attrs - 1)) and k not in self.dflt_attributes:
                unsetlist.append(k)

        if len(unsetlist) != 0 and self.server is not None:
            try:
                self.server.manager(MGR_CMD_UNSET, MGR_OBJ_QUEUE, unsetlist,
                                    self.name)
            except PbsManagerError as e:
                self.logger.error(e.msg)

        for k in self.dflt_attributes.keys():
            if (k not in self.attributes or
                    self.attributes[k] != self.dflt_attributes[k]):
                setdict[k] = self.dflt_attributes[k]

        if len(setdict.keys()) != 0 and self.server is not None:
            self.server.manager(MGR_CMD_SET, MGR_OBJ_QUEUE, setdict)


class Hook(PBSObject):

    """
    PBS hook objects. Holds attributes information and pointer
    to server

    :param name: Hook name
    :type name: str or None
    :param attrs: Hook attributes
    :type attrs: Dictionary
    :param server: Pointer to server
    """

    dflt_attributes = {}

    def __init__(self, name=None, attrs={}, server=None):
        PBSObject.__init__(self, name, attrs, self.dflt_attributes)
        self.server = server

class Holidays():
    """
    Descriptive calss for Holiday file.
    """

    def __init__(self):
        self.year = {'id': "YEAR", 'value': None, 'valid': False}
        self.weekday = {'id': "weekday", 'p': None, 'np': None, 'valid': None,
                        'position': None}
        self.monday = {'id': "monday", 'p': None, 'np': None, 'valid': None,
                       'position': None}
        self.tuesday = {'id': "tuesday", 'p': None, 'np': None, 'valid': None,
                        'position': None}
        self.wednesday = {'id': "wednesday", 'p': None, 'np': None,
                          'valid': None, 'position': None}
        self.thursday = {'id': "thursday", 'p': None, 'np': None,
                         'valid': None, 'position': None}
        self.friday = {'id': "friday", 'p': None, 'np': None, 'valid': None,
                       'position': None}
        self.saturday = {'id': "saturday", 'p': None, 'np': None,
                         'valid': None, 'position': None}
        self.sunday = {'id': "sunday", 'p': None, 'np': None, 'valid': None,
                       'position': None}

        self.days_set = []  # list of set days
        self._days_map = {'weekday': self.weekday, 'monday': self.monday,
                          'tuesday': self.tuesday, 'wednesday': self.wednesday,
                          'thursday': self.thursday, 'friday': self.friday,
                          'saturday': self.saturday, 'sunday': self.sunday}
        self.holidays = []  # list of calendar holidays

    def __str__(self):
        """
        Return the content to write to holidays file as a string
        """
        content = []
        if self.year['valid']:
            content.append(self.year['id'] + "\t" +
                           self.year['value'])

        for i in range(0, len(self.days_set)):
            content.append(self.days_set[i]['id'] + "\t" +
                           self.days_set[i]['p'] + "\t" +
                           self.days_set[i]['np'])

        # Add calendar holidays
        for day in self.holidays:
            content.append(day)

        return "\n".join(content)



