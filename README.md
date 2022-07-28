# Seas Forwarder

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

## Need Help?

* Create a GitHub [issue](https://github.com/oracle-samples/seas-forwarder/issues).

## Contributing

This project welcomes contributions from the community. Before submitting a pull request, please [review our contribution guide](./CONTRIBUTING.md).

## Security

The [Security Guide](./SECURITY.md) contains information about security vulnerability disclosure process. If you discover a vulnerability, consider filing an [issue](https://github.com/oracle-samples/seas-forwarder/issues).

## License

“Copyright (c) 2022, Oracle and/or its affiliates. All rights reserved. 
The Universal Permissive License (UPL), Version 1.0 

Subject to the condition set forth below, permission is hereby granted to any person obtaining a copy of this software, associated documentation and/or data (collectively the "Software"), free of charge and under any and all copyright rights in the Software, and any and all patent rights owned or freely licensable by each licensor #hereunder covering either (i) the unmodified Software as contributed to or provided by such licensor, or (ii) the Larger Works (as defined below), to deal in both

(a) the Software, and 
(b) any piece of software and/or hardware listed in the lrgrwrks.txt file if one is included with the Software (each a “Larger Work” to which the Software is contributed by such licensors),

without restriction, including without limitation the rights to copy, create derivative works of, display, perform, and #distribute the Software and make, use, sell, offer for sale, import, export, have made, and have sold the Software and the Larger Work(s), and to sublicense the foregoing rights on either these or other terms.

This license is subject to the following condition:

The above copyright notice and either this complete permission notice or at a minimum a reference to the UPL must be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
