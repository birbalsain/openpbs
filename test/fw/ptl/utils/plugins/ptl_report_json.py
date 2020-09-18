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


import re
from ptl.utils.pbs_dshutils import DshUtils
from ptl.utils.plugins.ptl_test_runner import PtlTextTestRunner
import datetime


class PTLJsonData(object):
    """
    The intent of the class is to generate json format of PTL test data
    """

    cur_repeat_count = 1
    def __init__(self, command):
        self.__du = DshUtils()
        self.__cmd = command

    def get_json(self, data, prev_data=None):
        """
        Method to generate test data in accordance to json schema

        :param data: dictionary of a test case details
        :type data: dict
        :param prev_data: dictionary of test run details that ran before
                          the current test
        :type prev_data: dict

        :returns a formatted dictionary of the data
        """
        FMT = '%H:%M:%S.%f'
        run_count = "Tests_run_count: " + str(PtlTextTestRunner.cur_repeat_count)
        data_json = None
        if not prev_data:
            PTLJsonData.cur_repeat_count = 1
            tests_start = str(data['start_time']).split()[1]
            data_json = {
                'command': self.__cmd,
                'user': self.__du.get_current_user(),
                'product_version': data['pbs_version'],
                'run_id': data['start_time'].strftime('%s'),
                'test_conf': {},
                'machine_info': data['machinfo'],
                'testsuites': {},
                'additional_data': {},
                'test_summary': {},
                'avg_measurements': {},
                'result' : {
                    'tests_with_failures': [],
                    'test_suites_with_failures': [],
                    'start' : str(data['start_time'])
                }

            }
            test_summary = {
                'result_summary': {
                    'run': 0,
                    'succeeded': 0,
                    'failed': 0,
                    'errors': 0,
                    'skipped': 0,
                    'timedout': 0
                },
                'test_start_time': str(data['start_time']),
                'tests_with_failures': [],
                'test_suites_with_failures': []
            }
            data_json['test_summary'][run_count] = test_summary
            if data['testparam']:
                for param in data['testparam'].split(','):
                    if '=' in param:
                        par = param.split('=', 1)
                        data_json['test_conf'][par[0]] = par[1]
                    else:
                        data_json['test_conf'][param] = True
        else:
            data_json = prev_data
        print("****outside", PTLJsonData.cur_repeat_count, "   ", PtlTextTestRunner.cur_repeat_count)
        if PTLJsonData.cur_repeat_count != PtlTextTestRunner.cur_repeat_count:
            print("**** inside repeat_changes  ")
            test_summary = {
                'result_summary': {
                    'run': 0,
                    'succeeded': 0,
                    'failed': 0,
                    'errors': 0,
                    'skipped': 0,
                    'timedout': 0
                },
                'test_start_time': str(data['start_time']),
                'tests_with_failures': [],
                'test_suites_with_failures': []
            }
            data_json['test_summary'][run_count] = test_summary
            PTLJsonData.cur_repeat_count = PtlTextTestRunner.cur_repeat_count
        print("**** count ", PTLJsonData.cur_repeat_count) 
        tsname = data['suite']
        tcname = data['testcase']
        jdata = {}
        jdata[run_count] = {
            'status': data['status'],
            'status_data': str(data['status_data']),
            'duration': str(data['duration']),
            'start_time': str(data['start_time']),
            'end_time': str(data['end_time']),
            'measurements': []
        }
        if 'measurements' in data:
            jdata[run_count]['measurements'] = data['measurements']
        if PtlTextTestRunner.cur_repeat_count == 1:
            if tsname not in data_json['testsuites']:
                data_json['testsuites'][tsname] = {
                    'module': data['module'],
                    'file': data['file'],
                    'testcases': {}
                }
            tsdoc = []
            if data['suitedoc']:
                tsdoc = (re.sub(r"[\t\n ]+", " ", data['suitedoc'])).strip()
            data_json['testsuites'][tsname]['docstring'] = tsdoc
            tcdoc = []
            if data['testdoc']:
                tcdoc = (re.sub(r"[\t\n ]+", " ", data['testdoc'])).strip()
            data_json['testsuites'][tsname]['testcases'][tcname] = {
                'docstring' : tcdoc,
                'requirements' : data['requirements'],
                'results' : {}
            }
            if data['testdoc']:
                data_json['testsuites'][tsname]['testcases'][tcname]['tags'] = data['tags']
        data_json['testsuites'][tsname]['testcases'][tcname]['results'][run_count] = jdata[run_count]
        if 'additional_data' in data:
            data_json['additional_data'] = data['additional_data']
        data_json['test_summary'][run_count]['test_end_time'] = str(data['end_time'])
        start = data_json['test_summary'][run_count]['test_start_time'].split()[1]
        end = str(data['end_time']).split()[1]
        dur = str(datetime.datetime.strptime(end, FMT) -
                  datetime.datetime.strptime(start, FMT))
        data_json['test_summary'][run_count]['tests_duration'] = dur
        print("@@@@@@@@@@@@@@   summary  run is ", data_json['test_summary'][run_count]['result_summary']['run'])
        data_json['test_summary'][run_count]['result_summary']['run'] += 1
        print("@@@@@@@@@@@@@@   summary  run is ", data_json['test_summary'][run_count]['result_summary']['run'])
        d_ts = data_json['test_summary'][run_count]
        if data['status'] == 'PASS':
            d_ts['result_summary']['succeeded'] += 1
        elif data['status'] == 'SKIP':
            d_ts['result_summary']['skipped'] += 1
        elif data['status'] == 'TIMEDOUT':
            d_ts['result_summary']['timedout'] += 1
            d_ts['tests_with_failures'].append(data['testcase'])
            if data['suite'] not in d_ts['test_suites_with_failures']:
                d_ts['test_suites_with_failures'].append(data['suite'])
        elif data['status'] == 'ERROR':
            d_ts['result_summary']['errors'] += 1
            d_ts['tests_with_failures'].append(data['testcase'])
            if data['suite'] not in d_ts['test_suites_with_failures']:
                d_ts['test_suites_with_failures'].append(data['suite'])
        elif data['status'] == 'FAIL':
            d_ts['result_summary']['failed'] += 1
            d_ts['tests_with_failures'].append(data['testcase'])
            if data['suite'] not in d_ts['test_suites_with_failures']:
                d_ts['test_suites_with_failures'].append(data['suite'])
        measurement_sum = {
            'avg_measurements':{
                'testsuites': {}}}
        for tsname in data_json['testsuites']:
            measurement_sum['avg_measurements']['testsuites'][tsname] = {}
            measurement_sum['avg_measurements']['testsuites'][tsname]['testcases'] = {}
            for tcname in data_json['testsuites'][tsname]['testcases']:
                measurement_sum['avg_measurements']['testsuites'][tsname]['testcases'][tcname] = []                
                t_sum = []
                count = 0
                for key in data_json['testsuites'][tsname]['testcases'][tcname]['results'].keys():
                    count += 1
                    repeat_count = 'Tests_run_count: ' + str(count)
                    print("************** for measuements", tsname,"   test case name ", tcname)
                    m = data_json['testsuites'][tsname]['testcases'][tcname]['results'][repeat_count]['measurements']
                    m_sum = []
                    for i in range(len(m)):
                        sum_m = 0
                        sum_d = 0
                        sum_min = 0
                        sum_max = 0
                        record = []
                        if count != 1:
                            sum_m =  m[i]["test_data"]['mean'] + t_sum[i][0]
                            sum_d =  m[i]["test_data"]['std_dev'] + t_sum[i][1]
                            sum_min = m[i]["test_data"]['minimum'] + t_sum[i][2]
                            sum_max = m[i]["test_data"]['maximum'] + t_sum[i][3]
                            record = [sum_m, sum_d, sum_min, sum_max]
                        else:
                            sum_m = m[i]["test_data"]['mean']
                            sum_d = m[i]["test_data"]['std_dev']
                            sum_min = m[i]["test_data"]['minimum']
                            sum_max = m[i]["test_data"]['maximum']
                            record = [sum_m, sum_d, sum_min, sum_max]
                        print("**** each data  ", record)
                        m_sum.append(record)
                        print("*** m_sum is testcase data ", m_sum)
                    t_sum = m_sum
                    print("**** total sum  ", t_sum)
                measurement_list = []
                print("*****  total sum ", t_sum)
                for i in range(len(m)):
                    m_data={}
                    m_data['test_measure']=m[i]['test_measure']
                    m_data['unit']=m[i]['unit']
                    m_data['test_data']=m[i]['test_data']
                    m_data['test_data']['mean']=t_sum[i][0]/count
                    m_data['test_data']['std_dev']=t_sum[i][1]/count
                    m_data['test_data']['minimum']=t_sum[i][2]/count
                    m_data['test_data']['maximum']=t_sum[i][3]/count
                    measurement_list.append(m_data)
                measurement_sum['avg_measurements']['testsuites'][tsname]['testcases'][tcname] = measurement_list
                print("*************   measurement_list ",measurement_sum['avg_measurements']['testsuites'][tsname]['testcases'][tcname])
        data_json["avg_measurements"] = measurement_sum['avg_measurements']     
               
        data_json['result']['end'] = str(data['end_time'])
        start = data_json['result']['start'].split()[1]
        end = data_json['result']['end'].split()[1]
        dur = str(datetime.datetime.strptime(end, FMT) -
                  datetime.datetime.strptime(start, FMT))
        fail_tests = []
        fail_ts = []
        for count in range(PtlTextTestRunner.cur_repeat_count):
           repeat_count = 'Tests_run_count: ' + str(count + 1)
           fail_tests.extend(data_json['test_summary'][repeat_count]['tests_with_failures'])
           fail_ts.extend(data_json['test_summary'][repeat_count]['test_suites_with_failures'])
        fail_tests = fail_tests
        fail_ts = fail_ts
        data_json['result']['duration'] = dur
        data_json['result']['tests_with_failures'] = list(set(fail_tests))
        data_json['result']['test_suites_with_failures'] = list(set(fail_ts))
        return data_json
