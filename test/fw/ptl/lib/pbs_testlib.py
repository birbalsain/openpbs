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
import datetime
import logging
import os
import random
import re
import sys
import time

from ptl.utils.pbs_dshutils import DshUtils

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

from ptl.lib.ptl_error import *
from ptl.lib.ptl_expect_action import *
from ptl.lib.ptl_batchutils import *
from ptl.lib.ptl_types import *
from ptl.lib.ptl_object import *
from ptl.lib.ptl_service import *


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
