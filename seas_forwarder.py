#!/usr/bin/python -u
#
# “Copyright (c) 2022, Oracle and/or its affiliates. All rights reserved. 
# The Universal Permissive License (UPL), Version 1.0 
#
# Subject to the condition set forth below, permission is hereby granted to any person obtaining a copy of this software,
# associated documentation and/or data (collectively the "Software"), free of charge and under any and all copyright
# rights in the Software, and any and all patent rights owned or freely licensable by each licensor hereunder  covering 
# either (i) the unmodified Software as contributed to or provided by such licensor, or (ii) the Larger Works (as defined below), to deal in both
#
# (a) the Software, and 
# (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if one is included with the Software
# (each a “Larger Work” to which the Software is contributed by such licensors),
#
# without restriction, including without limitation the rights to copy, create derivative works of, display,
# perform, and distribute the Software and make, use, sell, offer for sale, import, export, have made,
# and have sold the Software and the Larger Work(s), and to sublicense the foregoing rights on either these or other terms.
#
# This license is subject to the following condition:
#
# The above copyright notice and either this complete permission notice or at a minimum a reference to the UPL
# must be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT 
# OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
# OTHER DEALINGS IN THE SOFTWARE.”
#
# 12/07/2107    Worley      Created
# 02/18/2022    Skanda     Updated script to support IP-Port mapping
#
""" SEAS SSH Forwarding Module
"""

import ConfigParser
import logging
import logging.handlers
import json
import os
import re
import socket
import sys
import threading
import time
from multiprocessing import Process

# SEAS Forwarder config file
CFG_FILE = "/seas_forwarder.cfg"

# Maximum data to receive on socket
MAX_BUF_LEN = 1024

# Flag used to signal to all threads to exit process
EXIT_FLAG = 0


class WriteThread(threading.Thread):
    """ Thread for writing data to the SEAS client.
    The data read from the SEAS server is passed to STDOUT.
    Data sent to STDOUT is sent to the correct SEAS client by sshd.
    """

    def __init__(self, name, seas_socket):
        """ Initialize WriteThread class """
        threading.Thread.__init__(self)
        self.name = name
        self.socket = seas_socket

    def run(self):
        """ Main loop of thread
        Reads data from the SEAS server and passes the data to STDOUT.
        """
        global EXIT_FLAG

        # Get write thread logger
        log = logging.getLogger('main.write')
        log.log(SeasLog.DEBUG, "WriteThread STARTED")

        # Setup HexTrace logging
        hex_trace = HexTrace(log, 'FROM SERVER: ')

        # STDOUT must be reopened in binary mode.  This will prevent any
        # binary data that matches newline character from being lost.
        sys.stdout = os.fdopen(1, 'wb')

        # Thread loop
        while not EXIT_FLAG:
            try:
                log.log(SeasLog.DEBUG, "BEFORE RECIEVING DATA FROM SEAS SERVER FROM WRITE THREAD")
                # Receive data from SEAS server
                data = self.socket.recv(MAX_BUF_LEN)

                # Pass data to the hex logger
                if data:
                    hex_trace.trace_dump(data)

                # Send data to SEAS client
                sys.stdout.write(data)
                sys.stdout.flush()
            except socket.error, msg:
                if EXIT_FLAG == 0:
                    log.error("recv socket error: %s", msg)
                    EXIT_FLAG = 1

        # Make sure any remaining data is flushed by the hex logger
        hex_trace.trace_dump('', 'FORCE')

        log.log(SeasLog.DEBUG, "WriteThread(send to SEAS client) EXIT")


class ReadThread(threading.Thread):
    """ Thread for reading data from the SEAS client.
    The data, from the SEAS client, is read from stdin and sent to the
    SEAS server.
    """

    def __init__(self, name, seas_socket):
        """ Initialize ReadThread class """
        threading.Thread.__init__(self)
        self.name = name
        self.socket = seas_socket

    def run(self):
        """ Main loop of thread
        Reads data from STDIN and passes the data to the SEAS server.
        """
        global EXIT_FLAG

        # Get read thread logger
        log = logging.getLogger('main.read')
        log.log(SeasLog.DEBUG, "ReadThread STARTED")

        # Setup HexTrace logging
        hex_trace = HexTrace(log, 'FROM CLIENT: ')

        # STDIN must be reopened in binary mode.  This will prevent any
        # binary data that matches newline character from being lost.
        sys.stdin = os.fdopen(0, 'rb', 0)

        # Thread loop
        while not EXIT_FLAG:
            try:
                # Receive data from SEAS client
                data = sys.stdin.read(1)

                # Pass data to the hex logger
                if data:
                    hex_trace.trace_dump(data)
                else:
                    # stdin.read() only returns NULL when an EOF is received
                    log.log(SeasLog.DEBUG,
                            "STDIN from EAGLE SEAS client has closed")
                    EXIT_FLAG = 1

                log.log(SeasLog.DEBUG,"BEFORE SENDING DATA TO SEAS SERVER FROM READ THREAD")
                # Send data to SEAS server
                sent = self.socket.sendall(data)

                # Check for closed connection
                if sent == 0:
                    log.error("Socket connection to server broken")
                    EXIT_FLAG = 1
            except socket.error, msg:
                log.error("send socket error: %s", msg)
                EXIT_FLAG = 1

        # Make sure any remaining data is flushed by the hex logger
        hex_trace.trace_dump('', 'FORCE')

        log.log(SeasLog.DEBUG, "ReadThread(send to SEAS server) EXIT")


class HexTrace:
    """ Class designed to output data in a HEX format """

    # Maximum data to store before writing trace to log
    MAX_BFR_SIZE = 16

    def __init__(self, log, header):
        """ Initialize HexTrace class """
        self.log = log
        self.header = header
        self.data_buffer = ''

    @classmethod
    def filter_nonprintable(cls, element):
        """ Filter non-printable characters.
        Returns: printable characters as is.
        Returns: non-printable characters as a dot.
        """
        try:
            # Get unicode value and verify the element is printable
            if (ord(element) >= 32 and ord(element) <= 126):
                return element
            else:
                return '.'
        except TypeError:
            return '.'

    def trace_dump(self, data, force=''):
        """ Write data to log file
        Write data, in hex format, to the trace log file.
        """
        # Most of the data is received one-byte at a time.  This data is
        # buffered until enough is present to log.
        self.data_buffer += data
        data_output = self.header

        # Log the data after every MAX_BFR_SIZE bytes or
        # when a 'FORCE' flag is specified
        while ((len(self.data_buffer) >= self.MAX_BFR_SIZE)
                or (force == 'FORCE')):
            # Get MAX_BFR_SIZE bytes of data from the buffer and re-adjust buffer
            tmp = self.data_buffer[:self.MAX_BFR_SIZE]
            self.data_buffer = self.data_buffer[self.MAX_BFR_SIZE:]
            # Log the hex value of each byte
            for element in tmp:
                data_output += element.encode('hex') + ' '
            data_output += '  '
            # Log the printable from of each byte.
            for element in tmp:
                data_output += self.filter_nonprintable(element)
            self.log.log(SeasLog.TRACE, '%s', data_output)
            data_output = ''
            if force == 'FORCE':
                break


class SeasParam:
    """ Class used to manage SEAS configuration """

    def __init__(self, config_filename):
        """ Initialize ConfigureSeas class """
        self.config_filename = config_filename
        self.config_parser = ConfigParser.RawConfigParser()

        # default parameter values
        self.log_enable = '1'
        self.log_level = 'INFO'
        self.syslogd_address = '/dev/log'
        self.trace_log_file_dir = os.path.dirname(
            os.path.realpath(__file__)) + '/'
        self.trace_log_file_name = 'seas_forwarder.log.' + str(os.getpid())
        self.trace_log_enable = '0'
        self.trace_backup_count = '5'
        self.trace_log_file_size = '2'
        self.host_name = 'localhost'
        #self.host_port = '4000'
        self.ipMap = ''
        self.server_timeout = '300'

    def read_config_file(self):
        """ Read Configuration File
        """
        error_msg = ''

        # Read config file
        found = self.config_parser.read(self.config_filename)

        # Check to see if the config file is missing
        if len(found) == 0:
            error_msg = "Missing config file: " + self.config_filename
        else:
            # Get log file configuration parameters
            try:
                self.log_enable = self.config_parser.get('SEAS_Log',
                                                         'logEnable')
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

            try:
                self.log_level = self.config_parser.get('SEAS_Log', 'logLevel')
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

            try:
                tmp_syslogd = self.config_parser.get('SEAS_Log',
                                                     'syslogdAddress')
                if tmp_syslogd and os.path.exists(tmp_syslogd):
                    self.syslogd_address = tmp_syslogd
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

            try:
                tmp_dir = self.config_parser.get('SEAS_Log', 'traceLogFileDir')
                if tmp_dir and os.path.isdir(tmp_dir):
                    self.trace_log_file_dir = tmp_dir
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

            try:
                tmp_file_name = self.config_parser.get('SEAS_Log',
                                                       'traceLogFileName')
                if tmp_file_name:
                    self.trace_log_file_name = tmp_file_name
                    self.trace_log_file_name += '.' + str(os.getpid())
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

            try:
                self.trace_log_enable = self.config_parser.get('SEAS_Log',
                                                               'traceLogEnable')
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

            try:
                tmp_count = self.config_parser.get('SEAS_Log',
                                                   'traceBackupCount')
                if (tmp_count and is_int(tmp_count)):
                    self.trace_backup_count = tmp_count
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

            try:
                tmp_file_size = self.config_parser.get('SEAS_Log',
                                                       'traceLogFileSize')
                if (tmp_file_size and is_int(tmp_file_size) and
                        (int(tmp_file_size) >= 1)):
                    self.trace_log_file_size = tmp_file_size
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

            # Get server configuration parameters
            try:
                self.host_name = self.config_parser.get(
                    'SEAS_Server', 'hostName')
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

            '''try:
                self.host_port = self.config_parser.get(
                    'SEAS_Server', 'hostPort')
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)'''

            try:
              self.ipMap = self.config_parser.get(
                    'SEAS_Server', 'ipMap')
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

            try:
                tmp_timeout = self.config_parser.get('SEAS_Server',
                                                     'serverTimeout')
                if (tmp_timeout and is_int(tmp_timeout)):
                    self.server_timeout = tmp_timeout
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

        if error_msg:
            # Get read thread logger
            log = logging.getLogger('main')
            log.error(error_msg)

    def print_params(self):
        """ Print parameters read from config file
        """
        # Use main thread logger
        log = logging.getLogger('main')
        log.log(SeasLog.DEBUG, '*********************************************')
        log.log(SeasLog.DEBUG, 'Configuration Parameter Values:  ')
        log.log(SeasLog.DEBUG, '   logEnable        = %s', self.log_enable)
        log.log(SeasLog.DEBUG, '   logLevel         = %s', self.log_level)
        log.log(SeasLog.DEBUG, '   syslogdAddress   = %s', self.syslogd_address)
        log.log(SeasLog.DEBUG, '   traceLogFileDir  = %s',
                self.trace_log_file_dir)
        log.log(SeasLog.DEBUG, '   traceLogFileName = %s',
                self.trace_log_file_name)
        log.log(SeasLog.DEBUG, '   traceBackupCount = %s',
                self.trace_backup_count)
        log.log(SeasLog.DEBUG, '   traceLogEnable   = %s', self.trace_log_enable)
        log.log(SeasLog.DEBUG, '   traceLogFileSize = %s',
                self.trace_log_file_size)
        log.log(SeasLog.DEBUG, '   hostName         = %s', self.host_name)
        #log.log(SeasLog.DEBUG, '   hostPort         = %s', self.host_port)
        log.log(SeasLog.DEBUG, '   serverTimeout    = %s', self.server_timeout)
        log.log(SeasLog.DEBUG, '*********************************************')


class SeasLog:
    """ Responsible for SEAS logging configuration
    """
    # Custom logging levels
    # TRACE - most verbose log output
    # DEBUG - Provides additional process details
    TRACE = 4
    DEBUG = 5

    def __init__(self, param):
        """ Initialize ConfigureSeas class """
        self.param = param
        self.syslogd_handler = None
        self.trace_handler = None

    def configure_log(self):
        """ Set up logging environment
        """
        # Add support for new logging levels
        logging.addLevelName(self.TRACE, 'TRACE')
        logging.addLevelName(self.DEBUG, 'DBG')

        # Configure the syslogd handler
        self.configure_syslog_handler()

        # Configure the trace handler
        self.configure_trace_handler()

        # Set the log levels
        self.set_log_level()

    def configure_syslog_handler(self):
        """ Setup syslog daemon logging
        """
        # Get the main thread logger
        log = logging.getLogger('main')

        # Configure the log handler for syslogd
        try:
            self.syslogd_handler = logging.handlers.SysLogHandler(
                self.param.syslogd_address)
        except socket.error:
            # Failed to configure log handler.
            self.syslogd_handler = None
            return

        # Add handler to the root logger
        log.addHandler(self.syslogd_handler)

        # Configure and attach the log formatter for the handler
        syslogd_formatter = logging.Formatter(
            '%(filename)s %(levelname)s %(message)s '
            '[%(process)d:%(thread)d:#%(lineno)d]')
        self.syslogd_handler.setFormatter(syslogd_formatter)

    def configure_trace_handler(self):
        """ Setup trace logging
        """
        # Get the main thread logger
        log = logging.getLogger('main')

        # Configure the log handler for TRACE output
        # TRACE output is very verbose.  A separate log file is used to prevent
        # syslogd from being overrun.
        trace_log_file = self.param.trace_log_file_dir + self.param.trace_log_file_name
        self.trace_handler = logging.handlers.RotatingFileHandler(
            filename=trace_log_file,
            maxBytes=(int(self.param.trace_log_file_size)*1024*1024),
            backupCount=int(self.param.trace_backup_count),
            delay=1)

        # Configure and attach the log formatter for the handler
        trace_formatter = logging.Formatter(
            '%(asctime)s %(filename)s %(levelname)s %(message)s '
            '[%(process)d:%(thread)d:#%(lineno)d]',
            '%m%d:%H%M%S')
        self.trace_handler.setFormatter(trace_formatter)

        # Add handler to the root logger
        if self.param.trace_log_enable == '1':
            log.addHandler(self.trace_handler)

    def set_log_level(self):
        """ Set the configured logging level
        """
        # Get the main thread logger
        log = logging.getLogger('main')

        # Set max logging level
        #
        # Logging levels are filter-based and work on a hierarchy.  The root
        # logger, "log", must be set to the most verbose level to allow all log
        # output to flow to the handlers.  The handlers can then set the desired
        # output level to the log files.
        #
        # Setting the log level to CRITICAL will disable all output to
        # a handler.
        #
        # The following is a list of log level used by the script:
        #
        # Log Level     Value
        # CRITICAL      50   Least Verbose(no critical logs generated by script)
        # ERROR         40
        # INFO          20
        # DEBUG         5
        # TRACE         4    Most Verbose
        log.setLevel(self.TRACE)
        if self.param.log_level == 'DEBUG':
            # Allow ERROR, INFO and DEBUG output to syslogd
            if self.syslogd_handler is not None:
                self.syslogd_handler.setLevel(self.DEBUG)
            # Allow no output to the trace log file
            if self.trace_handler is not None:
                self.trace_handler.setLevel(self.DEBUG)
        elif self.param.log_level == 'TRACE':
            # Allow ERROR, INFO and DEBUG output to syslogd
            if self.syslogd_handler is not None:
                self.syslogd_handler.setLevel(self.DEBUG)
            # Allow all output to the trace log file
            if self.trace_handler is not None:
                self.trace_handler.setLevel(self.TRACE)
        else:
            # Default log level
            # Allow ERROR and INFO output to syslogd
            if self.syslogd_handler is not None:
                self.syslogd_handler.setLevel(logging.INFO)
            # Allow no output to the trace log file
            if self.trace_handler is not None:
                self.trace_handler.setLevel(logging.INFO)

        # Enable or disable all logging
        if self.param.log_enable == '0':
            logging.disable(logging.CRITICAL)
        else:
            logging.disable(logging.NOTSET)

    def reconfigure_log(self):
        """ Checks configuration file for any changes to logging
        During run-time, supports the enabling/disabling logging and changing
        the log level.
        """
        # Read config file
        found = self.param.config_parser.read(self.param.config_filename)

        # error message
        error_msg = ''

        # Check to see if the config file is missing
        if len(found) == 0:
            error_msg = "Missing config file: " + self.param.config_filename
        else:
            try:
                # Get log file configuration
                tmp_enable = self.param.config_parser.get(
                    'SEAS_Log', 'logEnable')
                tmp_level = self.param.config_parser.get(
                    'SEAS_Log', 'logLevel')
                tmp_trace_enable = self.param.config_parser.get(
                    'SEAS_Log', 'traceLogEnable')

                # Only make changes, if changes are found
                if ((tmp_enable != self.param.log_enable) or
                    (tmp_level != self.param.log_level) or
                        (tmp_trace_enable != self.param.trace_log_enable)):
                    # Update parameter values
                    self.param.log_enable = tmp_enable
                    self.param.log_level = tmp_level
                    self.param.trace_log_enable = tmp_trace_enable

                    # Get the main thread logger
                    log = logging.getLogger('main')

                    # Add or remmove handler to the root logger
                    if self.param.trace_log_enable == '1':
                        log.addHandler(self.trace_handler)
                    else:
                        log.removeHandler(self.trace_handler)

                    # Reconfigure the log levels
                    self.set_log_level()
            except ConfigParser.Error, msg:
                error_msg = "Missing parameter in config file: " + str(msg)

        if error_msg:
            # Get the main thread logger
            log = logging.getLogger('main')
            log.error(error_msg)


def connect_socket(host_name, host_port, server_timeout):
    """ Handle setting up the connection to the SEAS server
    """
    # Use main thread logger
    log = logging.getLogger('main')

    # Setup connection to SEAS server
    if (host_name and host_port):
        # Connect to the server
        # Set socket timeout
        try:
            sock = create_connection((host_name, host_port),
                                     timeout=server_timeout)
            log.log(SeasLog.DEBUG,
                    "Socket connected: hostname=%s hostport=%d timeout=%d",
                    host_name, host_port, server_timeout)
        except socket.error, msg:
            log.error("Connection Socket Error: %s", msg)
            sys.exit(-1)

        return sock
    else:
        log.error('Invalid hostname/host port specified')
        sys.exit(-1)


def create_connection(address, timeout=None):
    """ Connect to address and return the socket object
    """
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        family, socktype, proto, canonname, sock_addr = res

        # Quiet unused variable complaint
        canonname = canonname

        sock = None
        try:
            sock = socket.socket(family, socktype, proto)
            if timeout is not None:
                sock.settimeout(timeout)
            sock.connect(sock_addr)
            return sock
        except socket.error, msg:
            err = msg
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")


def is_int(int_str):
    """ Verify string is an integer
    """
    try:
        int(int_str)
        return True
    except ValueError:
        return False

def initial_config():
    """Extracting hostport from ipMap parameter from seas_forwarder.cfg file"""  
    # Read config file
    config_filename = os.path.dirname(os.path.realpath(__file__)) + \
            CFG_FILE
    params = SeasParam(config_filename)

    #Print current configuration if DEBUG logging enabled
    params.read_config_file()
    
    # Configure logging
    seas_log = SeasLog(params)
    seas_log.configure_log()
    
    params.print_params()
    
        # Get logger for the "main" thread
    log = logging.getLogger('main')
   
    # Extract IP from which seas subsytem request is received
    ip = os.popen("cat /var/log/secure | grep Accepted | tail -1 | grep -oE \"([0-9]{1,3}[\.]){3}[0-9]{1,3}\"").read().split('\n')[0]

    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if(re.search(regex, ip)):
        log.info(" SSH request accepted from IP - "+ ip)
    else:
        log.info("Invalid Ip address")

    host_port = 0

    # extract the ipMap from config File as string
    ipMap=params.ipMap

    # Convert the ipMap string to Dict
    ipMap=json.loads(ipMap)

    if ipMap.keys():
        log.info(ipMap)
    else:
        log.info("ipMap Is null in seas_forwarder.cfg")

    # Retrieve the port associated with ip from the
    # ipMapping provided in config file  
    if ip in ipMap.keys():
        host_port=ipMap[ip]
    else:
        print("IP mapping not available")
    
    log.info("----------------------------------- logs before socket connection---------------------")
    if host_port.isdigit() == True:
        log.info("Port : "+str(host_port))
    else:
        log.info("Port number must be number")
    log.info("-----------------------------------End of initial config---------------------")

    # return port number for seas to connect to SNAM 
    return host_port
    
        

def main(seas_socket):
    """ Script entry point """
    global EXIT_FLAG

    # Read config file
    config_filename = os.path.dirname(os.path.realpath(__file__)) + \
        CFG_FILE
    params = SeasParam(config_filename)
    params.read_config_file()

    # Configure logging
    seas_log = SeasLog(params)
    #seas_log.configure_log()

    # Get logger for the "main" thread
    log = logging.getLogger('main')

    log.info("========== SEAS Forwarder STARTED ==========")
    

    # Connection to the SEAS server
    seas_socket = connect_socket(params.host_name,
                                 int(seas_socket),
                                 int(params.server_timeout))

    try:
        # Holds list of running threads
        threads = []

        # Create read and write thread objects
        ssh_read_thread = ReadThread("readFromSsh", seas_socket)
        ssh_write_thread = WriteThread("writeToSsh", seas_socket)

        log.log(SeasLog.DEBUG, "Created thread objects")

        # Start threads
        ssh_read_thread.start()
        log.log(SeasLog.DEBUG,"Created thread read")
        ssh_write_thread.start()
        log.log(SeasLog.DEBUG,"Created thread write")

        # Add running threads to thread list
        threads.append(ssh_read_thread)
        threads.append(ssh_write_thread)

        log.log(SeasLog.DEBUG,threads)

        # After the read/write threads are spawned, the main thread will spin in
        # the loop below while the child threads are active.  This allows the
        # main thread to perform other work, if necessary.
        thread_alive = True
        while (thread_alive and (EXIT_FLAG == 0)):
            # Main thread will perform work every 5-seconds.
            time.sleep(5)
            thread_alive = False
            log.log(SeasLog.DEBUG, "Still Alive")

            # Check for logg configuration changes
            seas_log.reconfigure_log()

            # Check to see if child thread are still active
            for thread in threads:
                if thread.isAlive():
                    thread_alive = True

        # Main thread will wait here until all other threads have exited
        log.log(SeasLog.DEBUG, "Begin join(): EXIT_FLAG = %s", str(EXIT_FLAG))
        for thread in threads:
            thread.join(60)

        log.log(SeasLog.DEBUG, "All threads have shutdown")

    except threading.ThreadError, msg:
        log.error("Failed to start threads: %s\n", msg)

    log.info("========== SEAS Forwarder EXITED ==========")


if __name__ == '__main__':
    #params from the config file is read and --- 
    # returns a port on which the STP connects to SNAM
    seas_socket=initial_config()

    # if port is not None -- 
    # passes the port to main where socket connection to SNAM is made
    # For error case port no. it is handled inside initial_config()
    if seas_socket != None:
        main(seas_socket)
