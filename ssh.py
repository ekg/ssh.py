# ssh.py
#  an ssh wrapper library
#  author: Erik Garrison <erik@hypervolu.me>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# MODULE INIT

import os
import subprocess
from threading import Thread
import time
import re
import sys
import stat

__parallel_ssh_results = {}
__parallel_scp_results = {}
__parallel_ping_results = {}

# during module load check to see if we have cryptographic keys available
# look in the usual places and set a flag to use it
# if not there then raise an error

KEY='id_rsa'  # standard key name
KEYFILE = None
POSSIBLE_KEY_PATHS = [ os.path.expanduser('~')+'/.ssh/'+KEY ]

for path in POSSIBLE_KEY_PATHS:
    if os.path.exists(path):
        # silence if this works fine; we print a message otherwise
        #print 'found keyfile %s' % path
        KEYFILE = path
        # now make sure the permissions are correct if we don't do this then
        # ssh will refuse to use the key but we must be careful to check that
        # it's not already done and/or we have perms to do so otherwise we spam
        # logfiles when running as an unprivelaged user
         
        if os.access(KEYFILE, os.W_OK | os.R_OK) and not oct(os.stat(KEYFILE)[stat.ST_MODE] & 0777) == '0600':
            if raw_input('change permissions of %s to 600 so it can be used by ssh via ssh.py ? (y/n) ' % KEYFILE) == 'y':
                os.system('chmod 600 %s' % KEYFILE)
            else:
                print 'did not change permissions, per user request'


if KEYFILE is None:  # we haven't found a key anywhere
    print 'Could not find key for use as ssh key'
    print 'tried: %s' % ' '.join(POSSIBLE_KEY_PATHS)
    print


def scp(host, local_path, remote_path, parallel=False):
    """scp a given file or directory to a remote hosts."""
    global __parallel_scp_results
    args = ['scp', '-o', 'StrictHostKeyChecking=no']
    if KEYFILE:
        args.extend(["-i", KEYFILE])
    if os.path.isdir(local_path):
        args.append("-r")
    args.extend([local_path, "%s:%s" % (host, remote_path)])
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = p.communicate()
    if parallel:
        __parallel_scp_results[host] = result
    return (host, result)

def ssh(host, command, fork=False, parallel=False, user="root", debug=False):
    """Run a command via ssh on a given host.  Set fork=True if the command
    should fork."""
    global __parallel_ssh_results
    args = ["ssh", 
            "-o", "StrictHostKeyChecking=no", 
            "-o", "ConnectTimeout=15",
            ]
    if KEYFILE:
        args.extend(["-i", KEYFILE])
    args.append(host)
    if fork:
        command += " </dev/null >/dev/null 2>&1 &"
    args.append(command)
    if debug:
        print 'ssh %s %s' % (host, command)
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = p.communicate()
    if parallel:
        __parallel_ssh_results[host] = result
    if debug:
        print host
        print '\t', 'stdout:', result[0]
        print '\t', 'stderr:', result[1]
    return (host, result)

def ping_host(host, parallel=False):
    """Send one ICMP packet to host"""
    global __parallel_ping_results
    args = ["ping", "-c", "1", host]
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = p.communicate()
    if parallel:
        __parallel_ping_results[host] = result
    return (host, result)

def parallel_ping(host_list):
    """Ping a number of hosts at the same time"""
    global __parallel_ping_results
    __parallel_ping_results = {}
    for host in host_list:
        #print host
        t = Thread(target=ping_host, args=([host, True]))
        t.start()
    start_time = time.time()
    while len(__parallel_ping_results.keys()) < len(host_list) \
            and time.time() - start_time < 30:  # 30s timeout
        time.sleep(0.1)
    return __parallel_ping_results

def serial_scp(host_list, local_path, remote_path):
    """Serially scp the given path across a set of hosts.  Useful when you have
    too many hosts to use the parallel method without severe network and system
    congestion."""
    results = {}
    print "copying", local_path, "to", remote_path, "on", len(host_list), "hosts"
    i = 0
    for host in host_list:
        _progressive_log("%i machines finished, %i to go" % (i, len(host_list) - i))
        results[host] = scp(host, local_path, remote_path)
        i += 1
    return results

def serial_ssh(host_list, command):
    """Serially run a command over ssh across the set of hosts.  Useful when
    you have too many hosts to use the parallel method without severe network
    and system congestion."""
    results = {}
    print "running", command, "on", len(host_list), "hosts"
    i = 0
    for host in host_list:
        _progressive_log("%i machines finished, %i to go" % (i, len(host_list) - i))
        results[host] = ssh(host, command)
        i += 1
    return results

# TODO add chunking to these parallel functions, to help reduce congestion when there are more than 150 hosts

def parallel_scp(host_list, local_path, remote_path):
    """Use python threads to simultaneously copy a given local file or
    directory to a number of remote hosts.  Returns a dict of
    {hostname:result} for each host."""
    global __parallel_scp_results
    __parallel_scp_results = {}
    print "copying", local_path, "to", remote_path, "on", len(host_list), "hosts"
    # some useful debugging output, so we can follow progress
    for host in host_list:
        #print 'scp', local_path, host+':'+remote_path
        t = Thread(target=scp, args=([host, local_path, remote_path, True]))
        t.start()
    start_time = time.time()
    while len(__parallel_scp_results.keys()) < len(host_list):
            #and time.time() - start_time < 30:  # 30s timeout
            # no timeout.  seems to be causing problems.
        _progressive_log("%i machines finished, %i to go" % 
                        (len(__parallel_scp_results.keys()),
                        (len(host_list) - len(__parallel_scp_results.keys()))))
        time.sleep(0.1)
    return __parallel_scp_results

def parallel_ssh(host_list, command, print_output=True, fork=False, timeout=True, progressive_results_dissection=True):
    """Use python threads to run an ssh command on a number of servers.
    Set fork=True if the command should fork and run in the background on
    the hosts.  Returns a dict of {hostname:result} for each host."""
    global __parallel_ssh_results 
    __parallel_ssh_results = {}
    print "running", command, "on", len(host_list), "hosts"
    for host in host_list:
        #print 'ssh', host, command
        t = Thread(target=ssh, args=([host, command, fork, True]))
        t.start()
    start_time = time.time()
    while len(__parallel_ssh_results.keys()) < len(host_list) and not fork:
        _progressive_log("%i machines finished, %i to go" % 
                        (len(__parallel_ssh_results.keys()),
                        (len(host_list) - len(__parallel_ssh_results.keys()))))
        time.sleep(0.1)
        if progressive_results_dissection:
            # give us the unique kinds of results
            pass

    if not fork:
        return __parallel_ssh_results
    else:
        return True

def detect_timeouts(parallel_ssh_results):
    """Returns a list of hosts which timed out (ssh reports failure via
    timeout, this just parses the results and tells us which hosts failed in
    this fashion)."""
    timeouts = []
    for host in parallel_ssh_results:
        stderr = parallel_ssh_results[host][1]
        if re.search("ssh: connect to host %s port 22: Connection timed out" % host, stderr):
            print host, "timed out"
            timeouts.append(host)
    return timeouts
            
def _progressive_log(msg):
    """Log 'progressively', using cr as a line terminator."""
    # first clear the line
    sys.stdout.write(80 * ' ' + '\r')
    sys.stdout.flush()
    sys.stdout.write(msg+'\r')
    sys.stdout.flush()

def unique_ssh_results(results):
    """Takes the output of a parallel_ssh call, and gets the unique results.
    Item for comparison is stdout."""
    r = {}
    for k in results:
        r[results[k][0]] = True
    return r.keys()

def result_stdout(result):
    """Wrapper which clarifies what result[1][0] means"""
    return result[1][0]

def result_stderr(result):
    """Wrapper which clarifies what result[1][1] means"""
    return result[1][1]
