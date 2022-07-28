### Copyright (C) 2022, Oracle and/or its affiliates.  All rights reserved. ###
===============================================================================

This project contains seas forwarder code which is used to connect EAGLE to CCSMR.

This will run on CCSMR machine and requires SSH Deamon to run.


Description
-----------
The SEAS Forwarder is a python script that installs as a SSH daemon subsystem,
similar to how 'sftp-server' installs as an sftp subsystem.  The forwarder
allows the EAGLE SEAS client to connect, via SSH, to the SEAS server running
this script.

The EAGLE SEAS client will connect to the SSH SEAS subsystem.  The SSH daemon
upon seeing the SEAS subsystem request, will start an instance of the SEAS
Forwarder script.  The forwarder will then establish a TCP/IP connection to
the local SEAS server.

After the connections are established, the SEAS Forwarder will act as a
conduit for all IP traffic passed between the EAGLE SEAS client and the SEAS
server.  The traffic that is passed through the SEAS Forwarder is unaltered.


Requirements
------------
Python 2.5.6 and above (Python 3.x not supported)
SSH Daemon


Installation
------------
The SEAS Forwarder zip file will contain the following files:
    - seas_forwarder.py
    - seas_forwarder.cfg
    - README.txt

1. Create the following directory "seas_forwarder".  This directory may be 
   placed anywhere you choose.
2. Install all three files into "<install path>/seas_forwarder/
3. Open seas_forwarder.cfg and verify/update the following settings for
   logging.  See the field descriptions below.
    - logEnable
    - logLevel
    - syslogdAddress
    - traceLogFileDir
    - traceLogFileName
    - traceLogFileSize
    - traceBackupCount
    - traceLogEnable
4. Open seas_forwarder.cfg and verify/update the following settings for the
   SEAS Server.  See the field descriptions below.
    - hostName
    - ipMap
    - serverTimeout
5. Save the changes to seas_forwarder.cfg
6. Add the SEAS subsystem to the SSH daemon:
    - Edit the SSH daemon configuration file: "/etc/ssh/sshd_config"
    - Add the following line:
        Subsystem   seas    /<install path>/seas_forwarder/seas_forwarder.py
    - Save and close the file
7. Restart the SSH daemon to allow sshd_config file changes to take effect
    - From the command line run:
        > service sshd restart
    - The service restart will not affect existing SSH sessions.


SEAS Forwarder Configuration
----------------------------
logEnable - Enable or disable all logging support(syslogd and trace logging)
            Trace logging must still be enabled separately.  If trace logging
            is enabled and logEnable is set to 0, all logging including trace
            logging will be disabled.
    - Valid values:  0 or 1
    - 0 disable all logging
    - 1 (default) enable logging

logLevel - If enabled, set the verbosity of the log output
    - Valid values: INFO, DEBUG, or TRACE
    - INFO (default) The minimum output level.  Logs the start and end of the
                     seas forwarder instance.
    - DEBUG  Provides additional details.  Includes INFO output.
    - TRACE  Very verbose output.  Logs all traffic sent between SEAS server
             and EAGLE SEAS client.  Includes INFO and DEBUG output.

syslogdAddress - Specifies the location of the syslogd log socket
    - Default value:  /dev/log

traceLogFileDir - Destination directory for "logLevel = TRACE" output
    - Default value:  /tmp/

traceLogFileName - Name for "logLevel = TRACE" output file
    - Default value:  seas_forwarder.log

traceLogFileSize - Maximum size of "logLevel = TRACE" output file in MBs.
    - Valid values:   1 or higher
    - Default value:  2

traceBackupCount -  Maximum number of "logLevel = TRACE" backup files.
    - Valid values:   0 or higher
    - Default value:  5

traceLogEnable - Enable or disable trace logging for all instances of the
                      SEAS Forwarder process if logEnable is set to 1.
    - Valid values:  0 or 1
    - 0 (default) disable trace logging
    - 1 enable trace logging

hostName - The name of the SEAS server host. It should be the CCS-MR hostname.
    - Default value:  localhost

ipMap - Mapping of STP IP address and port number. Port number is the one on which CCSMR is listening on.
            It should be in json format as shown in the example below.
            Using this port number and above hostName seas_forwarder script will try to make connection to CCS-MR.
    - Default value:  None
Example.
ipMap = {
    "10.75.147.14" : "10005",
    "10.75.146.107" : "10004",
    "10.75.136.216" :"10000"
    }

serverTimeout - The amount of time the connection between the SEAS
                Forwarder and the SEAS server can remain idle before
                disconnecting.
    - Default value:  300 seconds


LOGGING
-------
There are three supported log levels:  INFO, DEBUG, and TRACE.  Log output for
INFO and DEBUG are written to the syslog daemon(syslogd).  This allows
multiple instances of the SEAS Forwarder to log simultaneously to one log file
location.  On most systems, the output file for syslogd is in
"/var/log/messages".

The TRACE log level is the most verbose.  It logs all data sent between the
SEAS server and the EAGLE SEAS client.  This log output is not sent to syslogd
to prevent the SEAS Forwarder from overrunning the syslogd log file.  Instead
a new log file is created based on the setting of traceLogFileDir,
traceLogFileName, traceLogFileSize, and traceBackupCount.

When TRACE is enabled, INFO and DEBUG log output is written to the trace log
file and to syslogd.

Based on the default values, up to 6 log files will be created at 2MB in size.
This will take the form of:
    - seas_forwarder.log.<process id>   (newest log)
    - seas_forwarder.log.<process id>.1
    - ....
    - seas_forwarder.log.<process id>.5 (oldest log)
The default settings will allow the trace log to consume no more than 12MB of
disk space per instance of the SEAS Forwarder process.

When trace logging is enabled, each instance of the SEAS Forwarder process
will have its own log file.  By default, as mentioned above, each instance
will be limited to using 12MB of disk space.  It is up to the system
administrator to delete these log files.  It is only recommended to enable
trace logging when debugging issues with the SEAS Forwarded since this could
produce several log files.


Need Help?

    Create a GitHub issue.

Contributing

This project welcomes contributions from the community. Before submitting a pull request, please review our contribution guide.
Security

The Security Guide contains information about security vulnerability disclosure process. If you discover a vulnerability, consider filing an issue.