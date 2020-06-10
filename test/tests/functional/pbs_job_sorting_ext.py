# coding: utf-8

# Copyright (C) 2003-2020 Altair Engineering, Inc. All rights reserved.
# Copyright notice does not imply publication.
#
# ALTAIR ENGINEERING INC. Proprietary and Confidential. Contains Trade Secret
# Information. Not for use or disclosure outside of Licensee's organization.
# The software and information contained herein may only be used internally and
# is provided on a non-exclusive, non-transferable basis. License may not
# sublicense, sell, lend, assign, rent, distribute, publicly display or
# publicly perform the software or other information provided herein,
# nor is Licensee permitted to decompile, reverse engineer, or
# disassemble the software. Usage of the software and other information
# provided by Altair(or its resellers) is only as explicitly stated in the
# applicable end user license agreement between Altair and Licensee.
# In the absence of such agreement, the Altair standard end user
# license agreement terms shall govern.

from tests.functional import *


@tags('scheduling_policy')
class TestJobSorting_ext(TestFunctional):

    """
    This test suite is for job sorting features of PBS
    """

    def test_long_job_sort_formula(self):
        """
        This tests server crash with long job_sort_formula
        """
        # create a very long formula
        formula = ('ncpus+' * 1000).strip('+')
        self.server.manager(MGR_CMD_SET, SERVER, {'job_sort_formula': formula})
        self.scheduler.run_scheduling_cycle()
        rv = self.server.isUp()
        self.assertTrue(rv, "Server crashed")

    def test_express_jobs_sorting(self):
        """
        This tests job sorting in high priority jobs using job_sort_key
        """
        a = {'job_sort_key': '"job_priority HIGH" ALL'}
        self.scheduler.set_sched_config(a)

        wqs = [
            ('expressq2', 500),
            ('expressq3', 520),
            ('expressq4', 200),
            ('expressq5', 1000),
            ('expressq6', 1010),
            ('expressq7', 100),
            ('expressq8', 575)]
        a = {
            'queue_type': 'e',
            'started': 'True',
            'enabled': 'True'}
        for (n, p) in wqs:
            a['Priority'] = p
            self.server.manager(MGR_CMD_CREATE, QUEUE, a, id=n)
        a = {ATTR_rescavail + '.ncpus': 36}
        self.server.manager(MGR_CMD_SET, NODE, a, self.mom.shortname)
        self.server.manager(MGR_CMD_SET, SERVER, {'scheduling': 'False'})
        normal_jobs = {
            'j1': {
                'Resource_List.select': '1:ncpus=2',
                'Priority': 50,
                'queue': 'expressq2'
            },
            'j2': {
                'Resource_List.select': '1:ncpus=3',
                'Priority': 30,
                'queue': 'workq'
            },
            'j3': {
                'Resource_List.select': '1:ncpus=1',
                'Priority': 5,
                'Resource_List.walltime': 100,
                'queue': 'expressq4'
            },
            'j4': {
                'Resource_List.select': '1:ncpus=4',
                'Priority': 100,
                'queue': 'expressq7'
            },
            'j5': {
                'Resource_List.select': '1:ncpus=6',
                'Priority': 29,
                'queue': 'expressq3'
            },
            'j6': {
                'Resource_List.select': '1:ncpus=8',
                'Priority': 180,
                'Resource_List.walltime': 80,
                'queue': 'workq'
            },
            'j7': {
                'Resource_List.select': '1:ncpus=5',
                'Priority': 60,
                'queue': 'expressq5'
            },
            'j8': {
                'Resource_List.select': '1:ncpus=6',
                'Priority': 9,
                'queue': 'expressq8'
            },
            'j9': {
                'Resource_List.select': '1:ncpus=7',
                'Priority': 200,
                'Resource_List.walltime': 200,
                'queue': 'expressq6'
            },
            'j10': {
                'Resource_List.select': '1:ncpus=2',
                'Priority': 7,
                'queue': 'expressq3'
            },
            'j11': {
                'Resource_List.select': '1:ncpus=3',
                'Priority': 3,
                'queue': 'expressq6'
            },
            'j12': {
                'Resource_List.select': '1:ncpus=1',
                'Resource_List.walltime': 100,
                'Priority': 37,
                'queue': 'expressq7'
            },
            'j13': {
                'Resource_List.select': '1:ncpus=4',
                'Priority': 245,
                'queue': 'expressq2'
            },
            'j14': {
                'Resource_List.select': '1:ncpus=6',
                'Priority': 8,
                'queue': 'expressq5'
            },
            'j15': {
                'Resource_List.select': '1:ncpus=8',
                'Resource_List.walltime': 80,
                'queue': 'expressq4'
            },
            'j16': {
                'Resource_List.select': '1:ncpus=5',
                'queue': 'workq'
            },
            'j17': {
                'Resource_List.select': '1:ncpus=6',
                'Priority': 8,
                'queue': 'expressq8'
            },
            'j18': {
                'Resource_List.select': '1:ncpus=7',
                'Resource_List.walltime': 200,
                'Priority': 10,
                'queue': 'expressq2'
            }
        }

        jids = []
        for k in normal_jobs.keys():
            j = Job(TEST_USER)
            j.set_attributes(normal_jobs[k])
            jids.append(self.server.submit(j))
            time.sleep(2)
        for jid in jids:
            self.server.expect(JOB, {'job_state': 'Q'}, id=jid)
        t = time.time()
        self.scheduler.run_scheduling_cycle()
        c = self.scheduler.cycles(lastN=1)[0]
        self.logger.info(c)
        job_order = [jids[8], jids[10], jids[6], jids[13], jids[7], jids[16],
                     jids[4], jids[9], jids[12], jids[0], jids[17], jids[2],
                     jids[14], jids[3], jids[11], jids[5], jids[1], jids[15]]
        self.logger.info("This is length of job_order")
        self.logger.info(len(job_order))
        for i in range(len(job_order)):
            self.assertEqual(job_order[i].split('.')[0], c.political_order[i])

    def test_sorting_of_queues(self):
        """
        This tests sorting of queues based on their priority
        """
        wqs = [
            ('expressq2', 500),
            ('expressq3', 600),
            ('expressq4', 200),
            ('expressq5', 1000),
            ('expressq6', 1023),
            ('expressq7', 100),
            ('expressq8', 400)]
        a = {
            'queue_type': 'e',
            'started': 'True',
            'enabled': 'True'}
        for (n, p) in wqs:
            a['Priority'] = p
            self.server.manager(MGR_CMD_CREATE, QUEUE, a, id=n)
        a = {ATTR_rescavail + '.ncpus': 36}
        self.server.manager(MGR_CMD_SET, NODE, a, self.mom.shortname)
        self.server.manager(MGR_CMD_SET, SERVER, {'scheduling': 'False'})
        normal_jobs = {
            'j1': {
                'Resource_List.select': '1:ncpus=2',
                'queue': 'expressq2'
            },
            'j2': {
                'Resource_List.select': '1:ncpus=3',
                'queue': 'workq'
            },
            'j3': {
                'Resource_List.select': '1:ncpus=1',
                'Resource_List.walltime': 100,
                'queue': 'expressq4'
            },
            'j4': {
                'Resource_List.select': '1:ncpus=4',
                'queue': 'expressq7'
            },
            'j5': {
                'Resource_List.select': '1:ncpus=6',
                'queue': 'expressq3'
            },
            'j6': {
                'Resource_List.select': '1:ncpus=5',
                'queue': 'expressq5'
            },
            'j7': {
                'Resource_List.select': '1:ncpus=6',
                'queue': 'expressq8'
            },
            'j8': {
                'Resource_List.select': '1:ncpus=7',
                'Resource_List.walltime': 200,
                'queue': 'expressq6'
            }
        }

        jids = []
        for k in normal_jobs.keys():
            j = Job(TEST_USER)
            j.set_attributes(normal_jobs[k])
            jids.append(self.server.submit(j))
            time.sleep(2)
        for jid in jids:
            self.server.expect(JOB, {'job_state': 'Q'}, id=jid)
        self.scheduler.run_scheduling_cycle()

        c = self.scheduler.cycles(lastN=1)[0]
        job_order = [jids[7], jids[5], jids[4], jids[0], jids[6], jids[2],
                     jids[3], jids[1]]
        for i in range(len(job_order)):
            self.assertEqual(job_order[i].split('.')[0], c.political_order[i])

    def test_expr_queues_round_robin(self):
        """
        This test verifies round_robin job sorting in express jobs
        """
        self.server.manager(MGR_CMD_SET, SCHED, {'log_events': 2047})
        a = {'job_sort_key': '"job_priority HIGH" ALL'}
        self.scheduler.set_sched_config(a)

        wqs = [
            ('expressq2', 500),
            ('expressq3', 500),
            ('expressq4', 200),
            ('expressq5', 1000),
            ('expressq6', 1000)]
        a = {
            'queue_type': 'e',
            'started': 'True',
            'enabled': 'True'}
        for (n, p) in wqs:
            a['Priority'] = p
            self.server.manager(MGR_CMD_CREATE, QUEUE, a, id=n)
        a = {ATTR_rescavail + '.ncpus': 8}
        self.server.manager(MGR_CMD_SET, NODE, a, self.mom.shortname)
        self.scheduler.set_sched_config({'round_robin': 'True ALL'})
        self.server.manager(MGR_CMD_SET, SERVER, {'scheduling': 'False'})
        normal_jobs = {
            'j1': {
                'queue': 'expressq2'
            },
            'j2': {
                'queue': 'expressq3'
            },
            'j3': {
                'queue': 'expressq4'
            },
            'j4': {
                'Resource_List.walltime': '00:10:00',
                'queue': 'expressq5'
            },
            'j5': {
                'Priority': 50,
                'queue': 'expressq5'
            },
            'j6': {
                'Priority': 20,
                'queue': 'expressq2'
            },
            'j7': {
                'Resource_List.walltime': '00:02:00',
                'queue': 'expressq6'
            },
            'j8': {
                'Priority': 30,
                'queue': 'expressq6'
            }
        }

        jids = []
        for k in normal_jobs.keys():
            j = Job(TEST_USER)
            j.set_attributes(normal_jobs[k])
            jids.append(self.server.submit(j))
        exp_ind = {
            'order1': [jids[7], jids[4], jids[6], jids[3], jids[5],
                       jids[1], jids[0], jids[2]],
            'order2': [jids[7], jids[4], jids[6], jids[3], jids[1],
                       jids[5], jids[0], jids[2]],
            'order3': [jids[4], jids[7], jids[3], jids[6], jids[1],
                       jids[5], jids[0], jids[2]],
            'order4': [jids[4], jids[7], jids[3], jids[6], jids[5],
                       jids[1], jids[0], jids[2]]
            }
        self.scheduler.run_scheduling_cycle()
        c = self.scheduler.cycles(lastN=1)[0]
        found_flag = False
        for od in exp_ind.keys():
            for i in range(8):
                self.logger.info(c.political_order[i])
                try:
                    self.assertEqual(exp_ind[od][i].split('.')[0],
                                     c.political_order[i])
                except AssertionError:
                    break
                found_flag = True
            if found_flag:
                break
        self.assertTrue(found_flag, "Failed to get expected job order")
