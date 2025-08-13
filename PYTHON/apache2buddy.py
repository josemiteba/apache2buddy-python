#!/usr/bin/env python3
"""
apache2buddy.py - Apache Performance Analysis Tool

A Python port of apache2buddy.pl that analyzes Apache configuration
and provides memory optimization recommendations.

Author: Converted from Perl version by Richard Forth
License: Apache 2.0
Github: https://github.com/richardforth/apache2buddy
"""

import os
import sys
import re
import subprocess
import argparse
import glob
import time
import socket
import getpass
import pwd
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Union
import math
import random

# Version and constants
VERSION = "0.1.0"
DEFAULT_PORT = 80

class Apache2BuddyError(Exception):
    """Custom exception for Apache2Buddy errors"""
    pass

class Colors:
    """ANSI color codes for terminal output"""
    def __init__(self, no_color=False, light_bg=False):
        if no_color:
            self.RED = ""
            self.GREEN = ""
            self.YELLOW = ""
            self.BLUE = ""
            self.PURPLE = ""
            self.CYAN = ""
            self.ENDC = ""
            self.BOLD = ""
            self.UNDERLINE = ""
        elif light_bg:
            # Bold colors for light backgrounds
            self.RED = "\033[1m"
            self.GREEN = "\033[1m"
            self.YELLOW = "\033[1m"
            self.BLUE = "\033[1m"
            self.PURPLE = "\033[1m"
            self.CYAN = "\033[1m"
            self.ENDC = "\033[0m"
            self.BOLD = "\033[1m"
            self.UNDERLINE = "\033[4m"
        else:
            # Dark background colors
            self.RED = "\033[91m"
            self.GREEN = "\033[92m"
            self.YELLOW = "\033[93m"
            self.BLUE = "\033[94m"
            self.PURPLE = "\033[95m"
            self.CYAN = "\033[96m"
            self.ENDC = "\033[0m"
            self.BOLD = "\033[1m"
            self.UNDERLINE = "\033[4m"

class Apache2Buddy:
    """Main Apache2Buddy analyzer class"""
    
    def __init__(self, args):
        self.args = args
        self.colors = Colors(args.nocolor, args.light_term)
        self.verbose = args.verbose
        
        # Cache for OS platform info
        self._os_platform = None
        
        # Tool paths
        self.ss_path = None
        self.netstat_path = None
        self.pmap_path = None
        self.apachectl_path = None
        
        # Apache info
        self.process_name = None
        self.apache_version = None
        self.apache_root = None
        self.apache_conf_file = None
        self.model = None
        self.config_array = []
        
        # System info
        self.available_mem = 0
        self.servername = ""
        self.public_ip = ""
        
    def log_verbose(self, message: str):
        """Log verbose message if verbose mode is enabled"""
        if self.verbose:
            print("VERBOSE: {}".format(message))
    
    def run_command(self, cmd: str, shell: bool = True) -> Tuple[int, str, str]:
        """Run a shell command and return returncode, stdout, stderr"""
        try:
            result = subprocess.run(
                cmd, 
                shell=shell, 
                capture_output=True, 
                text=True,
                env={"LANGUAGE": "en_GB.UTF-8", **os.environ}
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except Exception as e:
            return 1, "", str(e)
    
    def show_box(self, box_type: str, message: str):
        """Show formatted message boxes"""
        boxes = {
            'debug': "[ {}{}{} ] ".format(self.colors.BOLD, self.colors.BLUE + "??", self.colors.ENDC),
            'advisory': "[ {}{}{} ] ".format(self.colors.BOLD, self.colors.YELLOW + "@@", self.colors.ENDC),
            'info': "[ {}{}{} ] ".format(self.colors.BOLD, self.colors.BLUE + "--", self.colors.ENDC),
            'ok': "[ {}{}{} ] ".format(self.colors.BOLD, self.colors.GREEN + "OK", self.colors.ENDC),
            'warn': "[ {}{}{} ] ".format(self.colors.BOLD, self.colors.YELLOW + ">>", self.colors.ENDC),
            'crit': "[ {}{}{} ] ".format(self.colors.BOLD, self.colors.RED + "!!", self.colors.ENDC),
            'shortok': "[ {}{} ]".format(self.colors.GREEN + "OK", self.colors.ENDC)
        }
        
        if box_type in boxes:
            print("{}{}".format(boxes[box_type], message))
    
    def insert_hrule(self):
        """Print horizontal rule"""
        print("-" * 80)
    
    def get_os_platform(self) -> Tuple[str, str, str]:
        """Get OS platform information: (distro, version, codename)"""
        if self._os_platform:
            return self._os_platform
        
        distro = version = codename = None
        os_info = {}
        
        # Parse /etc/os-release if available
        if Path("/etc/os-release").exists():
            try:
                with open("/etc/os-release", 'r') as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line:
                            key, value = line.split('=', 1)
                            # Remove quotes
                            value = value.strip('"\'')
                            os_info[key] = value
                
                distro = os_info.get('NAME')
                version = os_info.get('VERSION_ID')
                
                # Special handling for Gentoo
                if distro == "Gentoo":
                    codename = "unknown"
                else:
                    codename = os_info.get('VERSION_CODENAME')
                    if not codename and 'VERSION' in os_info:
                        # Extract codename from VERSION field
                        match = re.search(r'\(([^)]+)\)', os_info['VERSION'])
                        if match:
                            codename = match.group(1)
            except Exception:
                pass
        
        # Fallback: /etc/lsb-release
        if not distro and Path("/etc/lsb-release").exists():
            try:
                with open("/etc/lsb-release", 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('DISTRIB_ID='):
                            distro = line.split('=', 1)[1]
                        elif line.startswith('DISTRIB_RELEASE='):
                            version = line.split('=', 1)[1]
                        elif line.startswith('DISTRIB_CODENAME='):
                            codename = line.split('=', 1)[1]
            except Exception:
                pass
        
        # Debian-specific fallback
        if not distro and Path("/etc/debian_version").exists():
            try:
                with open("/etc/debian_version", 'r') as f:
                    version = f.read().strip()
                distro = "Debian"
            except Exception:
                pass
        
        # RedHat/CentOS fallback
        if not distro and Path("/etc/redhat-release").exists():
            try:
                with open("/etc/redhat-release", 'r') as f:
                    line = f.read().strip()
                    match = re.match(r'^(\w+)[^\d]*(\d[\d.]*)', line)
                    if match:
                        distro, version = match.groups()
                    else:
                        distro = line
            except Exception:
                pass
        
        # Gentoo fallback
        if not distro and Path("/etc/gentoo-release").exists():
            try:
                with open("/etc/gentoo-release", 'r') as f:
                    line = f.read().strip()
                    match = re.search(r'Gentoo.*?(\d{4}\.\d+)', line)
                    if match:
                        distro = "Gentoo"
                        version = match.group(1)
                    else:
                        distro = "Gentoo"
            except Exception:
                pass
        
        # macOS (Darwin)
        if not distro and sys.platform == 'darwin':
            try:
                _, distro, _ = self.run_command("sw_vers -productName")
                _, version, _ = self.run_command("sw_vers -productVersion")
            except Exception:
                pass
        
        # Bitnami detection
        if Path("/opt/bitnami").exists():
            base_distro = distro
            distro = "Bitnami"
            if base_distro:
                distro += " ({})".format(base_distro)
        
        # Fallback to Python's platform info
        if not distro:
            distro = sys.platform
        
        # Ensure we return a codename even if there is none
        if not codename:
            codename = 'unknown'
        
        self._os_platform = (distro, version or "", codename)
        return self._os_platform
    
    def check_os_support(self, distro: str, version: str, codename: str) -> bool:
        """Check if the OS is supported"""
        supported_os_list = [
            'Ubuntu', 'ubuntu', 'Debian', 'debian', 'Debian GNU/Linux',
            'Bitnami', 'Bitnami (Debian GNU/Linux)',
            'Red Hat Enterprise Linux', 'Red Hat Enterprise Linux Server',
            'redhat', 'Rocky Linux', 'AlmaLinux', 'Amazon Linux',
            'Oracle Linux Server'
        ]
        
        ubuntu_versions = ['18.04', '20.04', '22.04', '24.04']
        debian_versions = ['12']
        amazon_versions = ['2', '2023']
        oracle_versions = ['8.10', '9.5']
        
        if distro not in supported_os_list:
            if distro == "Gentoo":
                self.show_box('crit', "{}ERROR: Gentoo is not officially supported by apache2buddy.{}".format(self.colors.RED, self.colors.ENDC))
                self.show_box('advisory', "To run anyway (at your own risk), try -O or --skip-os-version-check.")
                return False
            else:
                self.show_box('crit', "{}ERROR: This distro is not supported by apache2buddy.{}".format(self.colors.RED, self.colors.ENDC))
                if not self.args.noinfo:
                    supported_str = "', '".join(supported_os_list)
                    self.show_box('advisory', "{}Supported Distros:{} '{}{}{}'. To run anyway, try -O or --skip-os-version-check.".format(self.colors.YELLOW, self.colors.ENDC, self.colors.CYAN, supported_os_list, self.colors.ENDC))
                return False
        
        if not self.args.no_ok:
            self.show_box('ok', "This distro is supported by apache2buddy.")
        
        # Version-specific checks
        if distro.lower() in ['debian', 'bitnami', 'bitnami (debian gnu/linux)']:
            major_version = version.split('.')[0] if version else ""
            if major_version not in debian_versions:
                self.show_box('crit', "{}ERROR: This distro version ({}{}{}{}) is not supported.{}".format(self.colors.RED, self.colors.CYAN, version, self.colors.ENDC, self.colors.RED, self.colors.ENDC))
                if not self.args.noinfo:
                    versions_str = "', '".join(debian_versions)
                    self.show_box('advisory', "{}Supported Debian versions:{} '{}{}{}'. To run anyway, try -O.".format(self.colors.YELLOW, self.colors.ENDC, self.colors.CYAN, versions_str, self.colors.ENDC))
                return False
        
        elif distro.lower() in ['ubuntu']:
            if version not in ubuntu_versions:
                self.show_box('crit', "{}ERROR: This distro version ({}{}{}{}) is not supported.{}".format(self.colors.RED, self.colors.CYAN, version, self.colors.ENDC, self.colors.RED, self.colors.ENDC))
                if not self.args.noinfo:
                    versions_str = "', '".join(ubuntu_versions)
                    self.show_box('advisory', "{}Supported Ubuntu (LTS ONLY) versions:{} '{}{}{}'. To run anyway, try -O.".format(self.colors.YELLOW, self.colors.ENDC, self.colors.CYAN, versions_str, self.colors.ENDC))
                return False
        
        elif distro in ['Red Hat Enterprise Linux', 'redhat', 'Rocky Linux', 'AlmaLinux']:
            major_version = int(version.split('.')[0]) if version and version.split('.')[0].isdigit() else 0
            if major_version < 7:
                self.show_box('crit', "{}ERROR: This distro version ({}{}{}{}) is not supported.{}".format(self.colors.RED, self.colors.CYAN, version, self.colors.ENDC, self.colors.RED, self.colors.ENDC))
                return False
        
        elif 'Amazon Linux' in distro:
            major_version = version.split('.')[0] if version else ""
            if major_version not in amazon_versions:
                self.show_box('crit', "{}ERROR: This distro version ({}{}{}{}) is not supported.{}".format(self.colors.RED, self.colors.CYAN, version, self.colors.ENDC, self.colors.RED, self.colors.ENDC))
                return False
        
        elif 'Oracle Linux' in distro:
            major_version = int(version.split('.')[0]) if version and version.split('.')[0].isdigit() else 0
            if major_version < 8:
                self.show_box('crit', "{}ERROR: This distro version ({}{}{}{}) is not supported.{}".format(self.colors.RED, self.colors.CYAN, version, self.colors.ENDC, self.colors.RED, self.colors.ENDC))
                return False
        
        if not self.args.no_ok:
            self.show_box('ok', "This distro version is supported by apache2buddy.")
        
        return True
    
    def preflight_checks(self) -> bool:
        """Perform initial system checks"""
        self.log_verbose("Starting preflight checks...")
        
        # Check 1: Root privileges
        if os.geteuid() != 0:
            self.show_box('crit', "This script must be run as root.")
            return False
        elif not self.args.no_ok:
            self.show_box('ok', "This script is being run as root.")
        
        # Check 2: pmap utility - enhanced detection
        pmap_paths = [
            "/usr/bin/pmap",
            "/bin/pmap", 
            "/usr/local/bin/pmap",
            "/sbin/pmap"
        ]
        
        pmap_found = False
        pmap_path = None
        
        # First try 'which pmap'
        returncode, found_pmap, _ = self.run_command("which pmap")
        if returncode == 0 and found_pmap:
            pmap_path = found_pmap
            pmap_found = True
        else:
            # Try common locations
            for path in pmap_paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    pmap_path = path
                    pmap_found = True
                    break
        
        if not pmap_found:
            self.show_box('crit', "Unable to locate the pmap utility. This script requires pmap to analyze Apache's memory consumption.")
            self.show_box('info', "{}To fix this in Kubernetes/Docker containers, try:{}".format(self.colors.YELLOW, self.colors.ENDC))
            self.show_box('info', "{}  apt-get update && apt-get install -y procps procps-ng{}".format(self.colors.CYAN, self.colors.ENDC))
            self.show_box('info', "{}  or: apt-get install -y util-linux psmisc{}".format(self.colors.CYAN, self.colors.ENDC))
            
            # Show debugging info
            self.show_box('debug', "Debug information:")
            returncode, dpkg_output, _ = self.run_command("dpkg -l | grep procps")
            if returncode == 0 and dpkg_output:
                print("  procps packages found:")
                for line in dpkg_output.split('\n'):
                    print("    {}".format(line))
            
            returncode, find_output, _ = self.run_command("find /usr -name 'pmap' 2>/dev/null")
            if returncode == 0 and find_output:
                print("  pmap found at:")
                for line in find_output.split('\n'):
                    if line.strip():
                        print("    {}".format(line))
            
            return False
        elif not self.args.no_ok:
            self.show_box('ok', "The utility 'pmap' exists and is available for use: {}{}{}".format(self.colors.CYAN, pmap_path, self.colors.ENDC))
        
        self.pmap_path = pmap_path
        
        # Check 2.1: ss or netstat - enhanced detection
        ss_found = False
        netstat_found = False
        
        # Try to find ss first
        returncode, ss_path, _ = self.run_command("which ss 2>/dev/null")
        if returncode == 0 and ss_path:
            self.ss_path = ss_path
            ss_found = True
            if not self.args.no_ok:
                self.show_box('ok', "Using 'ss' for socket statistics.")
        else:
            # Try to find netstat
            returncode, netstat_path, _ = self.run_command("which netstat 2>/dev/null")
            if returncode == 0 and netstat_path:
                self.netstat_path = netstat_path
                netstat_found = True
                if not self.args.no_ok:
                    self.show_box('ok', "Using 'netstat' for socket statistics.")
            else:
                # Try common locations for netstat
                netstat_paths = [
                    "/bin/netstat",
                    "/usr/bin/netstat",
                    "/sbin/netstat",
                    "/usr/sbin/netstat"
                ]
                
                for path in netstat_paths:
                    if os.path.exists(path) and os.access(path, os.X_OK):
                        self.netstat_path = path
                        netstat_found = True
                        if not self.args.no_ok:
                            self.show_box('ok', "Using 'netstat' for socket statistics: {}".format(path))
                        break
        
        if not ss_found and not netstat_found:
            self.show_box('crit', "Neither 'ss' nor 'netstat' is available. Please install one of them.")
            self.show_box('info', "{}To fix this make sure either the iproute2 or net-tools package is installed.{}".format(self.colors.YELLOW, self.colors.ENDC))
            
            # Show debugging info
            self.show_box('debug', "Debug information for network tools:")
            returncode, dpkg_output, _ = self.run_command("dpkg -l | grep -E 'iproute2|net-tools'")
            if returncode == 0 and dpkg_output:
                print("  Network packages found:")
                for line in dpkg_output.split('\n'):
                    if line.strip():
                        print("    {}".format(line))
            
            returncode, find_output, _ = self.run_command("find /usr /bin /sbin -name 'netstat' -o -name 'ss' 2>/dev/null")
            if returncode == 0 and find_output:
                print("  Network tools found at:")
                for line in find_output.split('\n'):
                    if line.strip():
                        print("    {}".format(line))
            
            return False
        
        # Check 3: PHP binary
        returncode, php_path, _ = self.run_command("which php")
        if returncode != 0 or not php_path:
            if not self.args.nowarn:
                self.show_box('advisory', "{}Unable to locate the PHP binary. PHP specific checks will be skipped.{}".format(self.colors.YELLOW, self.colors.ENDC))
            self.php_available = False
        else:
            if not self.args.no_ok:
                self.show_box('ok', "'php' exists and is available for use: {}{}{}".format(self.colors.CYAN, php_path, self.colors.ENDC))
            self.php_available = True
        
        # Check 3.1: apachectl or apache2ctl - enhanced detection
        apachectl_found = False
        apachectl_path = None
        
        # Try to find apachectl first
        returncode, found_apachectl, _ = self.run_command("which apachectl")
        if returncode == 0 and found_apachectl:
            self.apachectl_path = found_apachectl
            apachectl_found = True
            if not self.args.no_ok:
                self.show_box('ok', "The utility 'apachectl' exists and is available for use: {}{}{}".format(self.colors.CYAN, found_apachectl, self.colors.ENDC))
        else:
            self.show_box('info', "Unable to locate the apachectl utility. This script requires apachectl to analyze Apache's vhost configurations.")
            self.show_box('info', "Not fatal yet, trying to locate the apache2ctl utility instead.")
            
            # Try to find apache2ctl
            returncode, found_apache2ctl, _ = self.run_command("which apache2ctl")
            if returncode == 0 and found_apache2ctl:
                self.apachectl_path = found_apache2ctl
                apachectl_found = True
                if not self.args.no_ok:
                    self.show_box('ok', "The utility 'apache2ctl' exists and is available for use: {}{}{}".format(self.colors.CYAN, found_apache2ctl, self.colors.ENDC))
            else:
                # Try common locations
                apachectl_paths = [
                    "/usr/sbin/apachectl",
                    "/usr/bin/apachectl", 
                    "/usr/sbin/apache2ctl",
                    "/usr/bin/apache2ctl",
                    "/usr/local/bin/apachectl",
                    "/usr/local/bin/apache2ctl"
                ]
                
                for path in apachectl_paths:
                    if os.path.exists(path) and os.access(path, os.X_OK):
                        self.apachectl_path = path
                        apachectl_found = True
                        if not self.args.no_ok:
                            self.show_box('ok', "Found Apache control utility: {}".format(path))
                        break
        
        if not apachectl_found:
            self.show_box('crit', "Unable to locate the apache2ctl utility. This script now requires apache2ctl to analyze Apache's vhost configurations.")
            self.show_box('info', "{}To fix this in Kubernetes/Docker containers, try:{}".format(self.colors.YELLOW, self.colors.ENDC))
            self.show_box('info', "{}  apt-get update && apt-get install -y apache2-utils{}".format(self.colors.CYAN, self.colors.ENDC))
            self.show_box('info', "{}  or: apt-get install -y httpd-tools{}".format(self.colors.CYAN, self.colors.ENDC))
            
            # Show debugging info
            self.show_box('debug', "Debug information for Apache tools:")
            returncode, dpkg_output, _ = self.run_command("dpkg -l | grep apache")
            if returncode == 0 and dpkg_output:
                print("  Apache packages found:")
                for line in dpkg_output.split('\n'):
                    if line.strip():
                        print("    {}".format(line))
            
            returncode, find_output, _ = self.run_command("find /usr -name 'apachectl' -o -name 'apache2ctl' 2>/dev/null")
            if returncode == 0 and find_output:
                print("  Apache control tools found at:")
                for line in find_output.split('\n'):
                    if line.strip():
                        print("    {}".format(line))
            
            self.show_box('info', "It looks like you might be running something else, other than apache..")
            return False
        
        # Check 4: Valid port
        if self.args.port < 1 or self.args.port > 65534:
            self.show_box('crit', "INVALID PORT: {}. Valid port numbers are 1-65534.".format(self.args.port))
            return False
        elif not self.args.no_ok:
            self.show_box('ok', "The port (port {}{}{}) is a valid port.".format(self.colors.CYAN, self.args.port, self.colors.ENDC))
        
        # Check 5: OS detection and support
        if not self.args.noinfo:
            self.show_box('info', "We are attempting to discover the operating system type and version number ...")
        
        distro, version, codename = self.get_os_platform()
        
        if not self.args.noinfo:
            self.show_box('info', "Distro: {}{}{}".format(self.colors.CYAN, distro, self.colors.ENDC))
            self.show_box('info', "Version: {}{}{}".format(self.colors.CYAN, version, self.colors.ENDC))
            self.show_box('info', "Codename: {}{}{}".format(self.colors.CYAN, codename, self.colors.ENDC))
        
        if not self.args.skip_os_version_check:
            if not self.check_os_support(distro, version, codename):
                return False
        else:
            self.show_box('warn', "{}OS Version Checks were skipped by user directive, you may get errors.{}".format(self.colors.YELLOW, self.colors.ENDC))
        
        return True

    def get_hostname(self) -> str:
        """Get system hostname"""
        returncode, hostname_path, _ = self.run_command("which hostname")
        if returncode != 0 or not hostname_path:
            # Fallback to socket.gethostname() if hostname command not found
            return socket.gethostname()
        
        returncode, servername, _ = self.run_command("{} -f".format(hostname_path))
        if returncode != 0 or not servername:
            servername = socket.gethostname()
        
        return servername
    
    def get_public_ip(self) -> str:
        """Get public IP address"""
        returncode, curl_path, _ = self.run_command("which curl")
        if returncode != 0 or not curl_path:
            self.log_verbose("curl not found, using fallback IP")
            return "x.x.x.x"
        
        # List of IP providers to try
        ip_providers = [
            'myip.dnsomatic.com',
            'ipv4.icanhazip.com',
            'ifconfig.me',
            'api.ipify.org',
            'ipecho.net/plain'
        ]
        
        # Randomize the selection
        random.shuffle(ip_providers)
        
        for provider in ip_providers:
            try:
                returncode, ip, _ = self.run_command("{} -s --connect-timeout 5 --max-time 10 {}".format(curl_path, provider))
                if returncode == 0 and re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                    self.log_verbose("Got IP {} from {}".format(ip, provider))
                    return ip
            except Exception:
                continue
        
        self.log_verbose("All IP providers failed, using fallback")
        return "x.x.x.x"  # fallback
    
    def get_pid(self, port: int) -> int:
        """Get PID of process listening on specified port"""
        pids = []
        
        # Try multiple approaches to find the PID
        commands = []
        
        if self.ss_path:
            commands.append("{} -tlnp | grep ':{}'".format(self.ss_path, port))
            commands.append("{} -ntlp | grep ':{} '".format(self.ss_path, port))
        
        if self.netstat_path:
            commands.append("{} -tlnp | grep ':{}'".format(self.netstat_path, port))
            commands.append("{} -ltnup | grep ':{}'".format(self.netstat_path, port))
            commands.append("{} -an | grep ':{}'".format(self.netstat_path, port))
        
        for cmd in commands:
            self.log_verbose("Trying command: {}".format(cmd))
            returncode, output, _ = self.run_command(cmd)
            self.log_verbose("Command output: '{}'".format(output))
            
            if returncode == 0 and output:
                # Process output to extract PIDs
                for line in output.split('\n'):
                    if line.strip() and 'LISTEN' in line and str(port) in line:
                        # Format: tcp 0 0 0.0.0.0:8080 0.0.0.0:* LISTEN 1/apache2
                        parts = line.split()
                        if len(parts) >= 6:
                            # Look for the PID/program which should be the last field
                            pid_process = parts[-1]  # Last field should be PID/process
                            if '/' in pid_process:
                                pid_str = pid_process.split('/')[0]
                                if pid_str.isdigit():
                                    pids.append(pid_str)
                                    self.log_verbose("Found PID {} from command: {}".format(pid_str, cmd))
                
                # If we found PIDs, break out of the command loop
                if pids:
                    break
        
        # Remove duplicates
        pids = list(set(pids))
        self.log_verbose("{} PIDs found listening on port {}: {}".format(len(pids), port, pids))
        
        if not pids:
            return 0
        
        # Check if all PIDs are the same
        if len(pids) > 1:
            raise Apache2BuddyError("There are multiple PIDs listening on port {}: {}".format(port, pids))
        
        try:
            pid = int(pids[0])
        except ValueError:
            pid = 0
        
        self.log_verbose("Returning PID: {}".format(pid))
        return pid
    
    def get_process_name(self, pid: int) -> str:
        """Get process name from PID"""
        self.log_verbose("Finding process running with PID {}".format(pid))
        
        # Method 1: Try standard ps command
        cmd = "ps ax | grep '^[[:space:]]*{}[[:space:]]' | awk '{{ print $5 }}'".format(pid)
        returncode, process_name, _ = self.run_command(cmd)
        self.log_verbose("Method 1 - ps ax grep returned: '{}' (returncode: {})".format(process_name, returncode))
        
        if returncode == 0 and process_name:
            self.log_verbose("Found process: {}".format(process_name))
            # Normalize common basenames to full paths when possible
            lower_name = process_name.lower()
            if 'apache' in lower_name or 'httpd' in lower_name:
                apache_paths = [
                    '/usr/sbin/apache2',
                    '/usr/sbin/httpd',
                    '/usr/bin/apache2',
                    '/usr/bin/httpd',
                    '/usr/local/bin/httpd',
                    '/opt/apache2/bin/httpd'
                ]
                for path in apache_paths:
                    if os.path.exists(path) and os.access(path, os.X_OK):
                        self.log_verbose("Normalized process basename '{}' to '{}'".format(process_name, path))
                        return path
                # Fallback to sensible defaults by flavor
                if 'apache' in lower_name:
                    self.log_verbose("Using default Apache path for basename '{}': /usr/sbin/apache2".format(process_name))
                    return '/usr/sbin/apache2'
                else:
                    self.log_verbose("Using default httpd path for basename '{}': /usr/sbin/httpd".format(process_name))
                    return '/usr/sbin/httpd'
            return process_name
        
        # Method 2: Try alternative ps command
        cmd = "ps -p {} -o comm=".format(pid)
        returncode, process_name, _ = self.run_command(cmd)
        self.log_verbose("Method 2 - ps -p comm= returned: '{}' (returncode: {})".format(process_name, returncode))
        
        if returncode == 0 and process_name:
            # For container environments, we need to map the process name to full path
            if 'apache' in process_name.lower():
                # Common Apache binary paths
                apache_paths = [
                    '/usr/sbin/apache2',
                    '/usr/sbin/httpd',
                    '/usr/bin/apache2',
                    '/usr/bin/httpd',
                    '/usr/local/bin/httpd',
                    '/opt/apache2/bin/httpd'
                ]
                
                for path in apache_paths:
                    if os.path.exists(path) and os.access(path, os.X_OK):
                        self.log_verbose("Found Apache binary at: {}".format(path))
                        return path
                
                # If we can't find the exact path, return a reasonable default
                self.log_verbose("Using default Apache path based on process name: {}".format(process_name))
                return '/usr/sbin/apache2'  # Default for Debian-based systems
            
            return process_name
        
        # Method 3: Try reading from /proc filesystem directly
        try:
            with open('/proc/{}/comm'.format(pid), 'r') as f:
                comm = f.read().strip()
            self.log_verbose("Method 3 - /proc/{}/comm returned: '{}'".format(pid, comm))
            
            if comm and 'apache' in comm.lower():
                # Map to full path
                apache_paths = [
                    '/usr/sbin/apache2',
                    '/usr/sbin/httpd',
                    '/usr/bin/apache2',
                    '/usr/bin/httpd'
                ]
                
                for path in apache_paths:
                    if os.path.exists(path) and os.access(path, os.X_OK):
                        self.log_verbose("Found Apache binary at: {}".format(path))
                        return path
                
                # Default for containers
                return '/usr/sbin/apache2'
            
            return comm if comm else ""
            
        except Exception as e:
            self.log_verbose("Method 3 - /proc/{}/comm failed: {}".format(pid, e))
        
        # Method 4: Try reading cmdline
        try:
            with open('/proc/{}/cmdline'.format(pid), 'r') as f:
                cmdline = f.read().strip()
            # cmdline has null separators, replace with spaces
            cmdline = cmdline.replace('\x00', ' ').strip()
            self.log_verbose("Method 4 - /proc/{}/cmdline returned: '{}'".format(pid, cmdline))
            
            if cmdline:
                # Extract the first part which should be the binary path
                binary_path = cmdline.split()[0] if cmdline.split() else ""
                if binary_path and ('apache' in binary_path.lower() or 'httpd' in binary_path.lower()):
                    self.log_verbose("Found Apache binary from cmdline: {}".format(binary_path))
                    return binary_path
            
        except Exception as e:
            self.log_verbose("Method 4 - /proc/{}/cmdline failed: {}".format(pid, e))
        
        # Method 5: Container-specific fallback for PID 1
        if pid == 1:
            self.log_verbose("Method 5 - PID 1 container fallback")
            # In containers, Apache is often the main process
            apache_paths = [
                '/usr/sbin/apache2',
                '/usr/sbin/httpd',
                '/usr/bin/apache2',
                '/usr/bin/httpd',
                '/usr/local/bin/httpd',
                '/opt/apache2/bin/httpd'
            ]
            
            for path in apache_paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    self.log_verbose("Container fallback: Found Apache binary at: {}".format(path))
                    return path
            
            # If we detected Apache earlier but can't find the binary, use default
            self.log_verbose("Container fallback: Using default Apache path")
            return '/usr/sbin/apache2'
        
        self.log_verbose("All methods failed to find process name")
        return ""
    
    def test_process(self, process_name: str) -> bool:
        """Test if the process is Apache"""
        # Clean up process name
        process_name = process_name.replace(':', '')
        
        output = []
        
        if process_name == '/usr/sbin/httpd':
            returncode, stdout, _ = self.run_command("{} -V 2>&1 | grep 'Server version'".format(process_name))
            if returncode == 0:
                output = [stdout]
        elif process_name == '/usr/sbin/httpd.worker':
            returncode, stdout, _ = self.run_command("{} -V 2>&1 | grep 'Server version'".format(process_name))
            if returncode == 0:
                output = [stdout]
        elif process_name == '/usr/sbin/apache2':
            # Try multiple approaches for apache2 in containers
            commands = [
                "/usr/sbin/apache2ctl -V 2>&1 | grep 'Server version'",
                "/usr/sbin/apache2 -V 2>&1 | grep 'Server version'",
                "apache2ctl -V 2>&1 | grep 'Server version'",
                "apache2 -V 2>&1 | grep 'Server version'"
            ]
            
            for cmd in commands:
                self.log_verbose("Trying Apache version command: {}".format(cmd))
                returncode, stdout, _ = self.run_command(cmd)
                self.log_verbose("Command returned: '{}' (returncode: {})".format(stdout, returncode))
                if returncode == 0 and stdout and 'Server version' in stdout:
                    output = [stdout]
                    break
            
            # If all commands fail, create a default version for containers
            if not output:
                self.log_verbose("All version commands failed, using container default")
                output = ["Server version: Apache/2.4 (Container)"]
        elif process_name == '/usr/sbin/httpd-prefork':
            returncode, stdout, _ = self.run_command("/usr/sbin/apache2ctl -V 2>&1 | grep 'Server version'")
            if returncode == 0:
                output = [stdout]
        elif process_name == '/usr/local/apache/bin/httpd':
            if not self.args.nowarn:
                self.show_box('warn', "{}Apache seems to have been installed from source, it's technically unsupported, we may get errors{}".format(self.colors.RED, self.colors.ENDC))
            returncode, stdout, _ = self.run_command("{} -V 2>&1 | grep 'Server version'".format(process_name))
            if returncode == 0:
                output = [stdout]
        elif process_name == '/opt/apache2/bin/httpd':
            if not self.args.nowarn:
                self.show_box('warn', "{}Apache seems to have been installed from a self build package, it's technically unsupported, we may get errors{}".format(self.colors.RED, self.colors.ENDC))
            returncode, stdout, _ = self.run_command("{} -V 2>&1 | grep 'Server version'".format(process_name))
            if returncode == 0:
                output = [stdout]
        else:
            return False
        
        if not output or not output[0]:
            # In container environments, commands might fail but Apache is still running
            if process_name == '/usr/sbin/apache2':
                self.log_verbose("Apache version detection failed, but this might be normal in containers")
                # Check if we detected Apache as PID 1 earlier - if so, assume it's valid
                try:
                    with open('/proc/1/comm', 'r') as f:
                        proc1_comm = f.read().strip()
                    if 'apache' in proc1_comm.lower():
                        self.log_verbose("Apache confirmed via /proc/1/comm, treating as valid")
                        return True
                except:
                    pass
                
                # Check if Apache processes are actually running
                returncode, ps_check, _ = self.run_command("ps aux | grep apache2 | grep -v grep | wc -l")
                if returncode == 0 and ps_check and int(ps_check.strip()) > 0:
                    self.log_verbose("Apache processes found via ps, treating as valid")
                    return True
            
            self.show_box('crit', "{}Something went wrong, and I suspect you have a syntax error in your apache configuration.{}".format(self.colors.RED, self.colors.ENDC))
            self.show_box('crit', "{}See \"systemctl status httpd.service\" and \"journalctl -xe\" for details.{}".format(self.colors.YELLOW, self.colors.ENDC))
            raise Apache2BuddyError("Apache configuration error detected")
        
        # Check if output matches Apache
        if re.search(r'^Server version.*Apache\/[0-9]', output[0]):
            return True
        elif re.search(r'^Server version.*Server\/[0-9]', output[0]):
            print("{}Apache server was built with version string \"Server version: Server/....\" and not as usual \"Server version: Apache/....\"${}".format(self.colors.YELLOW, self.colors.ENDC))
            return True
        elif 'Container' in output[0]:
            # Handle our mock output for containers
            self.log_verbose("Accepting mock Apache version for container environment")
            return True
        
        return False
    
    def get_apache_version(self, process_name: str) -> str:
        """Get Apache version string"""
        version = ""
        
        if process_name in ['/usr/sbin/httpd', '/usr/sbin/httpd.worker']:
            returncode, stdout, _ = self.run_command("{} -V 2>&1 | grep 'Server version'".format(process_name))
        elif process_name == '/usr/sbin/apache2':
            # Try multiple approaches for apache2 in containers
            commands = [
                "/usr/sbin/apache2ctl -V 2>&1 | grep 'Server version'",
                "/usr/sbin/apache2 -V 2>&1 | grep 'Server version'",
                "apache2ctl -V 2>&1 | grep 'Server version'",
                "apache2 -V 2>&1 | grep 'Server version'"
            ]
            
            for cmd in commands:
                self.log_verbose("Trying Apache version command: {}".format(cmd))
                returncode, stdout, _ = self.run_command(cmd)
                self.log_verbose("Command returned: '{}' (returncode: {})".format(stdout, returncode))
                if returncode == 0 and stdout and 'Server version' in stdout:
                    break
            else:
                # If all commands fail, create a default version for containers
                self.log_verbose("All version commands failed, using container default")
                stdout = "Server version: Apache/2.4 (Container)"
        else:
            returncode, stdout, _ = self.run_command("{} -V 2>&1 | grep 'Server version'".format(process_name))
        
        if stdout:
            # Extract version from "Server version: Apache/2.4.41 (Ubuntu)"
            match = re.search(r':\s(.*)$', stdout)
            if match:
                version = match.group(1)
        
        return version or "Apache/2.4 (Container)"
    
    def get_apache_root(self, process_name: str) -> str:
        """Get Apache root directory"""
        apache_root = ""
        
        if process_name == "/usr/sbin/apache2":
            commands = [
                'apache2ctl -V 2>&1 | grep "HTTPD_ROOT"',
                '/usr/sbin/apache2ctl -V 2>&1 | grep "HTTPD_ROOT"',
                'apache2 -V 2>&1 | grep "HTTPD_ROOT"',
                '/usr/sbin/apache2 -V 2>&1 | grep "HTTPD_ROOT"'
            ]
        else:
            commands = ['{} -V 2>&1 | grep "HTTPD_ROOT"'.format(process_name)]
        
        for cmd in commands:
            self.log_verbose("Trying Apache root command: {}".format(cmd))
            returncode, stdout, _ = self.run_command(cmd)
            self.log_verbose("Command returned: '{}' (returncode: {})".format(stdout, returncode))
            
            if returncode == 0 and stdout:
                match = re.search(r'="([^"]*)"', stdout)
                if match:
                    apache_root = match.group(1)
                    self.log_verbose("Found Apache root: {}".format(apache_root))
                    break
        
        # Container fallback: Use common Apache root directories
        if not apache_root:
            self.log_verbose("Apache root detection failed, using container fallbacks")
            common_roots = [
                "/etc/apache2",
                "/etc/httpd",
                "/usr/local/apache2",
                "/usr/local/apache",
                "/opt/apache2"
            ]
            
            for root in common_roots:
                if os.path.exists(root):
                    apache_root = root
                    self.log_verbose("Using fallback Apache root: {}".format(apache_root))
                    break
            
            # Final fallback
            if not apache_root:
                apache_root = "/etc/apache2"
                self.log_verbose("Using default Apache root: {}".format(apache_root))
        
        return apache_root
    def get_apache_conf_file(self, process_name: str) -> str:
        """Get Apache configuration file path"""
        if process_name == "/usr/sbin/apache2":
            returncode, stdout, _ = self.run_command('apache2ctl -V 2>&1 | grep "SERVER_CONFIG_FILE"')
        else:
            returncode, stdout, _ = self.run_command('{} -V 2>&1 | grep "SERVER_CONFIG_FILE"'.format(process_name))
        
        if returncode == 0 and stdout:
            match = re.search(r'="([^"]*)"', stdout)
            if match:
                return match.group(1)
        
        return ""
    
    def get_apache_pid_file(self, process_name: str) -> str:
        """Get Apache default PID file"""
        if process_name == "/usr/sbin/apache2":
            returncode, stdout, _ = self.run_command('apache2ctl -V 2>&1 | grep "DEFAULT_PIDLOG"')
        else:
            returncode, stdout, _ = self.run_command('{} -V 2>&1 | grep "DEFAULT_PIDLOG"'.format(process_name))
        
        if returncode == 0 and stdout:
            match = re.search(r'="([^"]*)"', stdout)
            if match:
                return match.group(1)
        
        return ""
    
    def get_apache_model(self, process_name: str) -> str:
        """Determine Apache MPM model - exactly like Perl script"""
        self.log_verbose("Determining Apache MPM model for process: {}".format(process_name))
        
        model = ""
        
        # Follow Perl script logic exactly
        if process_name.startswith('/usr/bin/apache2'):
            # Ubuntu/Debian style - use apache2ctl first
            self.log_verbose("Looking for model, first trying 'apache2ctl'")
            returncode, output, _ = self.run_command("apache2ctl -M 2>&1 | egrep 'worker|prefork|event|itk'")
            
            if returncode == 0 and output.strip():
                model = output.strip()
                self.log_verbose("Found model with apache2ctl: '{}'".format(model))
            else:
                # Fallback to apache2 -M (like Perl script issue #334)
                self.log_verbose("apache2ctl failed, trying apache2 -M")
                returncode, output, _ = self.run_command("apache2 -M 2>&1 | egrep 'worker|prefork|event|itk'")
                if returncode == 0 and output.strip():
                    model = output.strip()
                    self.log_verbose("Found model with apache2 -M: '{}'".format(model))
        else:
            # RedHat/CentOS style - use apachectl first
            returncode, output, _ = self.run_command("apachectl -M 2>&1 | egrep 'worker|prefork|event|itk'")
            
            if returncode == 0 and output.strip():
                model = output.strip()
                self.log_verbose("Found model with apachectl: '{}'".format(model))
            else:
                # Fallback to httpd -M (like Perl script issue #334) 
                self.log_verbose("apachectl failed, trying httpd -M")
                returncode, output, _ = self.run_command("httpd -M 2>&1 | egrep 'worker|prefork|event|itk'")
                if returncode == 0 and output.strip():
                    model = output.strip()
                    self.log_verbose("Found model with httpd -M: '{}'".format(model))
        
        if not model:
            self.log_verbose("No MPM model detected, defaulting to prefork")
            return "prefork"
        
        # Parse the model name from output like "mpm_prefork_module (shared)" or "worker_module"
        model_lower = model.lower()
        
        if 'prefork' in model_lower:
            detected_model = "prefork"
        elif 'worker' in model_lower:
            detected_model = "worker" 
        elif 'event' in model_lower:
            detected_model = "event"
        elif 'itk' in model_lower:
            detected_model = "itk"
        else:
            # Default to prefork if we can't determine
            detected_model = "prefork"
        
        self.log_verbose("Detected Apache MPM model: {}".format(detected_model))
        return detected_model
    
    def get_available_memory(self) -> int:
        """Get available system memory in MB - prioritize container limits"""
        self.log_verbose("Getting available system memory (container-aware)...")
        
        container_memory_mb = 0
        
        # Method 1: Check cgroup v1 memory limit FIRST (containers)
        try:
            with open('/sys/fs/cgroup/memory/memory.limit_in_bytes', 'r') as f:
                limit_bytes = int(f.read().strip())
                # If it's a reasonable limit (not the system max), use it
                if limit_bytes < 9223372036854775807:  # Not unlimited
                    container_memory_mb = limit_bytes // (1024 * 1024)
                    self.log_verbose("Container memory limit (cgroup v1): {} MB".format(container_memory_mb))
                    # Additional validation - if it's reasonable for a container, use it
                    if 128 <= container_memory_mb <= 65536:  # Between 128MB and 64GB
                        self.log_verbose("Using container memory limit: {} MB".format(container_memory_mb))
                        return container_memory_mb
        except (IOError, OSError, ValueError) as e:
            self.log_verbose("Failed to read cgroup v1 memory limit: {}".format(e))
        
        # Method 2: Try cgroup v2
        if container_memory_mb == 0:
            try:
                with open('/sys/fs/cgroup/memory.max', 'r') as f:
                    limit = f.read().strip()
                    if limit != "max":
                        limit_bytes = int(limit)
                        container_memory_mb = limit_bytes // (1024 * 1024)
                        self.log_verbose("Container memory limit (cgroup v2): {} MB".format(container_memory_mb))
                        if 128 <= container_memory_mb <= 65536:
                            self.log_verbose("Using container memory limit: {} MB".format(container_memory_mb))
                            return container_memory_mb
            except (IOError, OSError, ValueError) as e:
                self.log_verbose("Failed to read cgroup v2 memory limit: {}".format(e))
        
        # Method 3: Check Kubernetes memory limits from environment
        if container_memory_mb == 0:
            container_memory = os.environ.get('MEMORY_LIMIT')
            if container_memory:
                try:
                    # Parse values like "512m", "1g", "1024"
                    if container_memory.endswith('m') or container_memory.endswith('M'):
                        container_memory_mb = int(container_memory[:-1])
                    elif container_memory.endswith('g') or container_memory.endswith('G'):
                        container_memory_mb = int(container_memory[:-1]) * 1024
                    elif container_memory.isdigit():
                        container_memory_mb = int(container_memory) // (1024 * 1024)  # bytes to MB
                    else:
                        container_memory_mb = int(container_memory)
                    
                    if container_memory_mb > 0:
                        self.log_verbose("Container memory from environment: {} MB".format(container_memory_mb))
                        if 128 <= container_memory_mb <= 65536:
                            return container_memory_mb
                except ValueError as e:
                    self.log_verbose("Failed to parse MEMORY_LIMIT environment variable: {}".format(e))
        
        # Method 4: Use the same approach as Perl script - free command with EXACTLY the same parameters
        returncode, output, _ = self.run_command("LANGUAGE=en_GB.UTF-8 free | grep '^Mem:' | awk '{print $2}'")
        self.log_verbose("Method 4 - free command (like Perl) returned: '{}' (returncode: {})".format(output, returncode))
        
        if returncode == 0 and output and output.strip().isdigit():
            memory_kb = int(output.strip())
            memory_mb = memory_kb // 1024  # Convert KB to MB exactly like Perl script
            if memory_mb > 0:
                # If this is way larger than expected for a container, it's probably host memory
                if memory_mb > 32768:  # More than 32GB suggests host memory
                    self.log_verbose("Detected host memory ({} MB), looking for container limits")
                    
                    # Try to detect container memory by checking /proc/1/cgroup
                    try:
                        with open('/proc/1/cgroup', 'r') as f:
                            cgroup_content = f.read()
                        if 'docker' in cgroup_content or 'kubepods' in cgroup_content:
                            # We're in a container, try to estimate reasonable memory
                            # Look for memory pressure indicators
                            try:
                                # Check current memory usage
                                returncode, mem_usage, _ = self.run_command("free | grep '^Mem:' | awk '{print $3}'")
                                if returncode == 0 and mem_usage.strip().isdigit():
                                    used_kb = int(mem_usage.strip())
                                    used_mb = used_kb // 1024
                                    # Estimate container memory as 2-4x current usage (conservative)
                                    estimated_container_mb = max(512, min(8192, used_mb * 3))
                                    self.log_verbose("Estimated container memory based on usage: {} MB".format(estimated_container_mb))
                                    return estimated_container_mb
                            except:
                                pass
                    except:
                        pass
                
                self.log_verbose("Available memory from free command: {} MB".format(memory_mb))
                return memory_mb
        
        # Method 5: Try /proc/meminfo approach - exactly like Perl fallback
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            
            for line in meminfo.split('\n'):
                if line.startswith('MemTotal:'):
                    parts = line.split()
                    if len(parts) >= 2:
                        memory_kb = int(parts[1])
                        memory_mb = memory_kb // 1024
                        self.log_verbose("Available memory from /proc/meminfo: {} MB".format(memory_mb))
                        
                        # Same check for host vs container memory
                        if memory_mb > 32768:
                            self.log_verbose("Large memory detected, likely host memory, estimating container limits")
                            # Conservative estimate for containers
                            return min(8192, memory_mb // 8)  # Use 1/8 of host memory as conservative estimate
                        
                        return memory_mb
        except (IOError, OSError, ValueError) as e:
            self.log_verbose("Failed to read /proc/meminfo: {}".format(e))
        
        # Final fallback - use conservative container default
        fallback_memory = 512  # 512MB default for containers
        self.log_verbose("Using absolute fallback memory: {} MB".format(fallback_memory))
        return fallback_memory
    
    def find_included_files(self, master_list: List[str], find_includes_in: List[str], apache_root: str) -> List[str]:
        """Find all files that need to be included in Apache configuration"""
        master_config_array = []
        
        while find_includes_in:
            file_path = find_includes_in.pop(0)
            
            self.log_verbose("Processing {}".format(file_path))
            
            # If it's a directory, add glob
            if os.path.isdir(file_path) and not file_path.endswith('*'):
                self.log_verbose("Adding glob to {}, is a directory".format(file_path))
                if not file_path.endswith('/'):
                    file_path += '/'
                file_path += '*'
            
            try:
                # Handle glob patterns
                if '*' in file_path:
                    files = glob.glob(file_path)
                    for f in files:
                        if os.path.isfile(f) and os.access(f, os.R_OK):
                            master_list.append(f)
                            find_includes_in.append(f)
                else:
                    if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            file_content = f.readlines()
                            master_config_array.extend(file_content)
                            
                            # Search for include directives
                            for line in file_content:
                                line = line.strip()
                                
                                # Handle Include directive
                                include_match = re.match(r'^\s*include\s+(.+)\s*$', line, re.IGNORECASE)
                                if include_match:
                                    include_path = include_match.group(1).strip('\'"')
                                    
                                    # Make absolute path if relative
                                    if not include_path.startswith('/'):
                                        include_path = os.path.join(apache_root, include_path)
                                    
                                    if os.path.isdir(include_path) and not include_path.endswith('*'):
                                        if not include_path.endswith('/'):
                                            include_path += '/'
                                        include_path += '*'
                                    
                                    if '*' in include_path:
                                        files = glob.glob(include_path)
                                        sane_files = [f for f in files if os.path.isfile(f) and os.access(f, os.R_OK)]
                                        master_list.extend(sane_files)
                                        find_includes_in.extend(sane_files)
                                    else:
                                        if os.path.isfile(include_path) and os.access(include_path, os.R_OK):
                                            master_list.append(include_path)
                                            find_includes_in.append(include_path)
                                
                                # Handle IncludeOptional directive (Apache 2.4)
                                include_opt_match = re.match(r'^\s*includeoptional\s+(.+)\s*$', line, re.IGNORECASE)
                                if include_opt_match:
                                    include_path = include_opt_match.group(1).strip('\'"')
                                    
                                    if not include_path.startswith('/'):
                                        include_path = os.path.join(apache_root, include_path)
                                    
                                    if os.path.isdir(include_path) and not include_path.endswith('*'):
                                        if not include_path.endswith('/'):
                                            include_path += '/'
                                        include_path += '*'
                                    
                                    if '*' in include_path:
                                        files = glob.glob(include_path)
                                        sane_files = [f for f in files if os.path.isfile(f) and os.access(f, os.R_OK)]
                                        master_list.extend(sane_files)
                                        find_includes_in.extend(sane_files)
                                    else:
                                        if os.path.isfile(include_path) and os.access(include_path, os.R_OK):
                                            master_list.append(include_path)
                                            find_includes_in.append(include_path)
                            
            except (IOError, OSError) as e:
                self.log_verbose("Error processing {}: {}".format(file_path, e))
                continue
        
        return master_config_array
    
    def build_config_array(self, base_apache_config: str, apache_root: str) -> List[str]:
        """Build an array holding the content of all Apache configuration files"""
        master_list = [base_apache_config]
        find_includes_in = [base_apache_config]
        
        return self.find_included_files(master_list, find_includes_in, apache_root)
    
    def find_master_value(self, config_array: List[str], model: str, config_element: str) -> str:
        """Find configuration value from Apache config - exactly like Perl script"""
        self.log_verbose("Searching Apache configuration for the {} directive".format(config_element))
        
        results = []
        ignore = False
        ignore_by_model = False
        ifmodule_count = 0
        
        # MPM models to ignore (exactly like Perl script)
        if 'worker' in model.lower():
            ignore_model1, ignore_model2, ignore_model3 = "prefork", "event", "itk"
        elif 'event' in model.lower():
            ignore_model1, ignore_model2, ignore_model3 = "worker", "prefork", "itk"
        else:  # default to prefork
            ignore_model1, ignore_model2, ignore_model3 = "worker", "event", "itk"
        
        for line in config_array:
            line = line.strip()
            
            # Skip comments (exactly like Perl script)
            if line.startswith('#'):
                continue
            
            # Handle IfModule blocks (like Perl script)
            if '<IfModule' in line:
                ifmodule_count += 1
                # Check if this is an MPM module we should ignore
                if any(model_name in line.lower() for model_name in [ignore_model1, ignore_model2, ignore_model3]):
                    ignore_by_model = True
                continue
            elif '</IfModule' in line:
                ifmodule_count -= 1
                if ifmodule_count == 0:
                    ignore_by_model = False
                continue
            
            # Handle VirtualHost blocks (like Perl script)
            if '<VirtualHost' in line or '<virtualhost' in line:
                ignore = True
                continue
            elif '</VirtualHost' in line or '</virtualhost' in line:
                ignore = False
                continue
            
            # Skip if we're in a VirtualHost or ignored MPM block
            if ignore or ignore_by_model:
                continue
            
            # Look for our configuration element (case insensitive like Perl script)
            if config_element.lower() in line.lower():
                # Extract the value after the directive name
                parts = line.split()
                if len(parts) >= 2 and parts[0].lower() == config_element.lower():
                    value = parts[1]
                    # Remove quotes if present (like Perl script)
                    value = value.strip('"\'')
                    results.append(value)
                    self.log_verbose("Found {} = {}".format(config_element, value))
        
        # Return the last occurrence (like Perl script)
        if results:
            result = results[-1]
        else:
            result = "CONFIG NOT FOUND"
        
        self.log_verbose("Final result for {}: {}".format(config_element, result))
        
        # Handle Ubuntu/Debian envvars (like Perl script) - Enhanced variable resolution
        if config_element.lower() in ['user', 'group', 'pidfile'] and result.startswith('$'):
            if os.path.exists('/etc/debian_version') and os.path.exists('/etc/apache2/envvars'):
                self.log_verbose("Checking envvars for variable: {}".format(result))
                
                # Remove the $ prefix to get the variable name
                var_name = result[1:]  # Remove the '$'
                
                # If it's ${VAR_NAME}, extract just the variable name
                if var_name.startswith('{') and var_name.endswith('}'):
                    var_name = var_name[1:-1]
                
                self.log_verbose("Looking for variable name: {}".format(var_name))
                
                try:
                    with open('/etc/apache2/envvars', 'r') as f:
                        for line in f:
                            line = line.strip()
                            # Look for export VAR_NAME=value or VAR_NAME=value
                            if '=' in line:
                                # Handle both "export VAR=value" and "VAR=value" formats
                                if line.startswith('export '):
                                    var_line = line[7:]  # Remove 'export '
                                else:
                                    var_line = line
                                
                                if var_line.startswith(var_name + '='):
                                    var_value = var_line.split('=', 1)[1].strip().strip('"\'')
                                    self.log_verbose("Found in envvars: {} = {}".format(var_name, var_value))
                                    return var_value
                except Exception as e:
                    self.log_verbose("Error reading envvars: {}".format(e))
                
                # If not found in envvars, try environment variables
                env_value = os.environ.get(var_name)
                if env_value:
                    self.log_verbose("Found in environment: {} = {}".format(var_name, env_value))
                    return env_value
                
                # Fallback: common defaults for Apache variables
                defaults = {
                    'APACHE_RUN_USER': 'www-data',
                    'APACHE_RUN_GROUP': 'www-data',
                    'APACHE_PID_FILE': '/var/run/apache2/apache2.pid',
                    'APACHE_RUN_DIR': '/var/run/apache2',
                    'APACHE_LOCK_DIR': '/var/lock/apache2',
                    'APACHE_LOG_DIR': '/var/log/apache2'
                }
                
                if var_name in defaults:
                    self.log_verbose("Using default value for {}: {}".format(var_name, defaults[var_name]))
                    return defaults[var_name]
                
                self.log_verbose("Variable {} not found, returning original value".format(var_name))
                return result  # Return original if we can't resolve it
        
        return result
    
    def get_memory_usage(self, process_name: str, apache_user: str, search_type: str) -> int:
        """Get memory usage statistics for Apache processes"""
        self.log_verbose("Get '{}' memory usage".format(search_type))
        
        # Enhanced approach for containers: try multiple methods to get PIDs
        pids = []
        
        # Method 1: Standard ps aux approach
        cmd = "ps aux | grep {} | grep '^{}' | awk '{{ print $2 }}'".format(process_name, apache_user)
        returncode, output, _ = self.run_command(cmd)
        self.log_verbose("Method 1 - ps aux approach returned: '{}' (returncode: {})".format(output, returncode))
        
        if returncode == 0 and output:
            pids.extend([line.strip() for line in output.split('\n') if line.strip() and line.strip().isdigit()])
        
        # Method 2: Alternative ps command for containers
        if not pids:
            cmd = "ps -ef | grep {} | grep {} | awk '{{ print $2 }}'".format(process_name, apache_user)
            returncode, output, _ = self.run_command(cmd)
            self.log_verbose("Method 2 - ps -ef approach returned: '{}' (returncode: {})".format(output, returncode))
            
            if returncode == 0 and output:
                pids.extend([line.strip() for line in output.split('\n') if line.strip() and line.strip().isdigit()])
        
        # Method 3: Try with process basename only
        if not pids:
            process_basename = os.path.basename(process_name)
            cmd = "ps aux | grep {} | grep '^{}' | awk '{{ print $2 }}'".format(process_basename, apache_user)
            returncode, output, _ = self.run_command(cmd)
            self.log_verbose("Method 3 - ps aux basename approach returned: '{}' (returncode: {})".format(output, returncode))
            
            if returncode == 0 and output:
                pids.extend([line.strip() for line in output.split('\n') if line.strip() and line.strip().isdigit()])
        
        # Method 4: Container fallback - find all processes and filter
        if not pids:
            self.log_verbose("Standard ps commands failed, trying container fallback...")
            
            # Try to find processes using /proc filesystem
            try:
                proc_pids = []
                for pid_dir in os.listdir('/proc'):
                    if pid_dir.isdigit():
                        try:
                            with open('/proc/{}/comm'.format(pid_dir), 'r') as f:
                                comm = f.read().strip()
                            if 'apache' in comm.lower() or 'httpd' in comm.lower():
                                # Check if it matches our user
                                try:
                                    with open('/proc/{}/status'.format(pid_dir), 'r') as f:
                                        status = f.read()
                                    # Look for Uid line in status
                                    for line in status.split('\n'):
                                        if line.startswith('Uid:'):
                                            uid = line.split()[1]  # Real UID
                                            try:
                                                import pwd
                                                user_info = pwd.getpwuid(int(uid))
                                                if user_info.pw_name == apache_user or apache_user.startswith(user_info.pw_name[:7]):
                                                    proc_pids.append(pid_dir)
                                                    self.log_verbose("Found Apache process PID {} for user {}".format(pid_dir, user_info.pw_name))
                                                    break
                                            except (KeyError, ValueError):
                                                pass
                                except (IOError, OSError):
                                    pass
                        except (IOError, OSError):
                            continue
                pids.extend(proc_pids)
            except OSError:
                pass
        
        # Method 5: Final fallback - use any Apache processes we can find
        if not pids:
            self.log_verbose("All methods failed, trying final fallback...")
            cmd = "ps aux | grep -E '(apache|httpd)' | grep -v grep | awk '{{ print $2 }}'"
            returncode, output, _ = self.run_command(cmd)
            self.log_verbose("Method 5 - final fallback returned: '{}' (returncode: {})".format(output, returncode))
            
            if returncode == 0 and output:
                pids.extend([line.strip() for line in output.split('\n') if line.strip() and line.strip().isdigit()])
        
        # Remove duplicates and invalid PIDs
        pids = list(set([pid for pid in pids if pid.isdigit()]))
        self.log_verbose("Final list of PIDs: {}".format(pids))
        
        if not pids:
            self.show_box('crit', "Error getting a list of PIDs")
            print("DEBUG -> Process Name: {}".format(process_name))
            print("DEBUG -> Apache_user: {}".format(apache_user))
            print("DEBUG -> Search Type: {}".format(search_type))
            self.show_box('crit', "Failed to get Apache process PIDs")
            
            # In container environments, this might be normal - provide a reasonable fallback
            self.log_verbose("Using container memory fallback")
            if search_type == "high":
                return 64  # 64MB fallback for largest process
            elif search_type == "low":
                return 32  # 32MB fallback for smallest process
            else:  # average
                return 48  # 48MB fallback for average process
        
        proc_mem_usages = []
        
        # Get memory usage for each process
        for pid in pids:
            self.log_verbose("Getting memory for PID: {}".format(pid))
            
            # Try multiple methods to get memory usage
            memory_kb = 0
            
            # Method 1: Use pmap if available
            if self.pmap_path:
                distro, _, _ = self.get_os_platform()
                
                if distro.lower() == "suse linux enterprise server":
                    cmd = "{} -d {} | egrep 'writable-private' | awk '{{ print $1 }}'".format(self.pmap_path, pid)
                else:
                    cmd = "{} -d {} | egrep 'writeable/private' | awk '{{ print $4 }}'".format(self.pmap_path, pid)
                
                returncode, mem_usage, _ = self.run_command(cmd)
                self.log_verbose("pmap command returned: '{}' (returncode: {})".format(mem_usage, returncode))
                
                if returncode == 0 and mem_usage:
                    # Remove 'K' and convert to int
                    mem_usage = mem_usage.replace('K', '').strip()
                    try:
                        memory_kb = int(mem_usage)
                        self.log_verbose("Memory usage by PID {} is {}K (pmap)".format(pid, memory_kb))
                    except ValueError:
                        memory_kb = 0
            
            # Method 2: Fallback to /proc/pid/status if pmap fails
            if memory_kb == 0:
                try:
                    with open('/proc/{}/status'.format(pid), 'r') as f:
                        status = f.read()
                    for line in status.split('\n'):
                        if line.startswith('VmRSS:'):
                            # VmRSS is in kB
                            memory_kb = int(line.split()[1])
                            self.log_verbose("Memory usage by PID {} is {}K (VmRSS)".format(pid, memory_kb))
                            break
                except (IOError, OSError, ValueError):
                    pass
            
            # Method 3: Fallback to ps command
            if memory_kb == 0:
                cmd = "ps -p {} -o rss= 2>/dev/null".format(pid)
                returncode, rss, _ = self.run_command(cmd)
                if returncode == 0 and rss and rss.strip().isdigit():
                    memory_kb = int(rss.strip())
                    self.log_verbose("Memory usage by PID {} is {}K (ps rss)".format(pid, memory_kb))
            
            # Add to list if we got a valid value
            if memory_kb > 0:
                proc_mem_usages.append(memory_kb)
            else:
                self.log_verbose("Could not get memory for PID {}, skipping".format(pid))
        
        if not proc_mem_usages:
            self.log_verbose("No memory usage data collected, using container defaults")
            # Container fallback values
            if search_type == "high":
                return 64  # 64MB fallback
            elif search_type == "low":
                return 32  # 32MB fallback
            else:  # average
                return 48  # 48MB fallback
        
        # Calculate result based on search type
        if search_type == "high":
            result = max(proc_mem_usages) / 1024  # Convert KB to MB
        elif search_type == "low":
            result = min(proc_mem_usages) / 1024
        elif search_type == "average":
            result = sum(proc_mem_usages) / len(proc_mem_usages) / 1024
        else:
            result = 0
        
        result_mb = max(1, round(result))  # Ensure at least 1MB
        self.log_verbose("Final {} memory usage: {} MB".format(search_type, result_mb))
        return result_mb
    
    def get_apache_uptime(self, pid: int) -> Tuple[int, int, int, int]:
        """Get Apache uptime from parent PID"""
        cmd = "ps -eo '%p %t' | grep '^[[:space:]]*{} ' | awk '{{ print $2 }}'".format(pid)
        returncode, uptime_str, _ = self.run_command(cmd)
        
        self.log_verbose("PID passed to uptime function: {}".format(pid))
        self.log_verbose("Raw uptime: {}".format(uptime_str))
        
        days = hours = minutes = seconds = 0
        
        if returncode == 0 and uptime_str:
            uptime_str = uptime_str.strip()
            
            # Parse different uptime formats
            if '-' in uptime_str and ':' in uptime_str:
                # Format: days-hours:minutes:seconds
                parts = uptime_str.split('-')
                days = int(parts[0])
                time_part = parts[1]
                time_components = time_part.split(':')
                hours = int(time_components[0])
                minutes = int(time_components[1])
                seconds = int(time_components[2])
            elif uptime_str.count(':') == 2:
                # Format: hours:minutes:seconds
                time_components = uptime_str.split(':')
                hours = int(time_components[0])
                minutes = int(time_components[1])
                seconds = int(time_components[2])
            elif uptime_str.count(':') == 1:
                # Format: minutes:seconds
                time_components = uptime_str.split(':')
                minutes = int(time_components[0])
                seconds = int(time_components[1])
        
        return days, hours, minutes, seconds
    
    def detect_additional_services(self) -> Dict[str, int]:
        """Detect additional services and their memory usage"""
        self.log_verbose("Begin detecting additional services...")
        services = {}
        
        # Detect MySQL
        returncode, output, _ = self.run_command("ps -C mysqld -o rss | grep -v RSS")
        if returncode == 0 and output:
            self.log_verbose("MySQL Detected")
            memory_usage = self.get_service_memory_usage("mysqld")
            services['mysql'] = memory_usage
            if not self.args.noinfo:
                self.show_box('info', "{}MySQL{} Detected => Using {}{} MB{} of memory.".format(self.colors.CYAN, self.colors.ENDC, self.colors.CYAN, memory_usage, self.colors.ENDC))
        else:
            services['mysql'] = 0
        
        # Detect Java
        returncode, output, _ = self.run_command("ps -C java -o rss | grep -v RSS")
        if returncode == 0 and output:
            self.log_verbose("Java Detected")
            memory_usage = self.get_service_memory_usage("java")
            services['java'] = memory_usage
            if not self.args.noinfo:
                self.show_box('info', "{}Java{} Detected => Using {}{} MB{} of memory.".format(self.colors.CYAN, self.colors.ENDC, self.colors.CYAN, memory_usage, self.colors.ENDC))
        else:
            services['java'] = 0
        
        # Detect Varnish
        returncode, output, _ = self.run_command("ps -C varnishd -o rss | grep -v RSS")
        if returncode == 0 and output:
            self.log_verbose("Varnish Detected")
            memory_usage = self.get_service_memory_usage("varnishd")
            services['varnish'] = memory_usage
            if not self.args.noinfo:
                self.show_box('info', "{}Varnish{} Detected => Using {}{} MB{} of memory.".format(self.colors.CYAN, self.colors.ENDC, self.colors.CYAN, memory_usage, self.colors.ENDC))
        else:
            services['varnish'] = 0
        
        # Detect Redis
        returncode, output, _ = self.run_command("ps -C redis-server -o rss | grep -v RSS")
        if returncode == 0 and output:
            self.log_verbose("Redis Detected")
            memory_usage = self.get_service_memory_usage("redis-server")
            services['redis'] = memory_usage
            if not self.args.noinfo:
                self.show_box('info', "{}Redis{} Detected => Using {}{} MB{} of memory.".format(self.colors.CYAN, self.colors.ENDC, self.colors.CYAN, memory_usage, self.colors.ENDC))
        else:
            services['redis'] = 0
        
        # Detect Memcache
        returncode, output, _ = self.run_command("ps -C memcached -o rss | grep -v RSS")
        if returncode == 0 and output:
            self.log_verbose("Memcache Detected")
            memory_usage = self.get_service_memory_usage("memcached")
            services['memcache'] = memory_usage
            if not self.args.noinfo:
                self.show_box('info', "{}Memcache{} Detected => Using {}{} MB{} of memory.".format(self.colors.CYAN, self.colors.ENDC, self.colors.CYAN, memory_usage, self.colors.ENDC))
        else:
            services['memcache'] = 0
        
        # Detect PHP-FPM
        returncode1, output1, _ = self.run_command("ps -C php-fpm -o rss | grep -v RSS")
        returncode2, output2, _ = self.run_command("ps -C php5-fpm -o rss | grep -v RSS")
        
        if (returncode1 == 0 and output1) or (returncode2 == 0 and output2):
            self.log_verbose("PHP-FPM Detected")
            if returncode1 == 0 and output1:
                memory_usage = self.get_service_memory_usage("php-fpm")
                if not self.args.noinfo:
                    self.show_box('info', "{}PHP-FPM{} Detected => Using {}{} MB{} of memory.".format(self.colors.CYAN, self.colors.ENDC, self.colors.CYAN, memory_usage, self.colors.ENDC))
            else:
                memory_usage = self.get_service_memory_usage("php5-fpm")
                if not self.args.noinfo:
                    self.show_box('info', "{}PHP5-FPM{} Detected => Using {}{} MB{} of memory.".format(self.colors.CYAN, self.colors.ENDC, self.colors.CYAN, memory_usage, self.colors.ENDC))
            services['phpfpm'] = memory_usage
        else:
            services['phpfpm'] = 0
        
        # Detect Gluster
        returncode, output, _ = self.run_command("ps -C glusterd -o rss | grep -v RSS")
        if returncode == 0 and output:
            self.log_verbose("Gluster Detected")
            glusterd_mem = self.get_service_memory_usage("glusterd")
            glusterfs_mem = self.get_service_memory_usage("glusterfs")

            glusterfsd_mem = self.get_service_memory_usage("glusterfsd")
            memory_usage = glusterd_mem + glusterfs_mem + glusterfsd_mem
            services['gluster'] = memory_usage
            if not self.args.noinfo:
                self.show_box('info', "{}Gluster{} Detected => Using {}{} MB{} of memory.".format(self.colors.CYAN, self.colors.ENDC, self.colors.CYAN, memory_usage, self.colors.ENDC))
        else:
            services['gluster'] = 0
        
        if all(v == 0 for v in services.values()):
            if not self.args.no_ok:
                self.show_box('ok', "{}No additional services were detected.{}".format(self.colors.GREEN, self.colors.ENDC))
        
        self.log_verbose("End detecting additional services...")
        return services
    
    def get_service_memory_usage(self, service_name: str) -> int:
        """Get memory usage for a specific service"""
        if service_name == "varnishd":
            # Handle varnish differently due to vcache user in 4.1+
            try:
                pwd.getpwnam("vcache")
                cmd = "ps -U vcache -C varnishd -o rss | grep -v RSS"
            except KeyError:
                cmd = "ps -C {} -o rss | grep -v RSS".format(service_name)
        else:
            cmd = "ps -C {} -o rss | grep -v RSS".format(service_name)
        
        returncode, output, _ = self.run_command(cmd)
        if returncode != 0 or not output:
            return 0
        
        total_memory = 0
        for line in output.split('\n'):
            if line.strip():
                try:
                    memory_kb = int(line.strip())
                    total_memory += memory_kb
                except ValueError:
                    continue
        
        return round(total_memory / 1024)  # Convert KB to MB
    
    def get_php_memory_limit(self) -> str:
        """Get PHP memory limit setting"""
        if not hasattr(self, 'php_available') or not self.php_available:
            return "N/A"
        
        returncode, php_path, _ = self.run_command("which php")
        if returncode != 0:
            return "N/A"
        # Fast path: use ini_get with timeout to avoid heavy phpinfo processing
        returncode, output, _ = self.run_command("timeout 6s {} -r \"echo ini_get('memory_limit');\"".format(php_path))
        if returncode == 0 and output:
            return output.strip()

        # Fallback to phpinfo with timeout
        returncode, output, _ = self.run_command("timeout 6s {} -i | grep -i '^memory_limit' | head -1".format(php_path))
        if returncode == 0 and output:
            parts = output.split()
            if len(parts) >= 2:
                return parts[-1].strip()

        return "N/A"
    
    def check_maxclients_hits(self, model: str, process_name: str) -> bool:
        """Check for MaxClients/MaxRequestWorkers hits in logs"""
        if "/opt/bitnami/" in process_name:
            if not self.args.nowarn:
                self.show_box('warn', "Skipping checking logs for MaxClients/MaxRequestWorkers hits, Bitnami sends these to stdout.")
            return False
        
        if model.lower() != "prefork":
            if not self.args.nowarn:
                self.show_box('warn', "Skipping checking logs for MaxClients/MaxRequestWorkers Hits, we can only do this if apache is running in prefork.")
            return False
        
        # Determine log file based on process name
        log_files = {
            "/usr/sbin/httpd": "/var/log/httpd/error_log",
            "/opt/rh/httpd24/root/usr/sbin/httpd": "/var/log/httpd24/error_log",
            "/usr/local/apache/bin/httpd": "/usr/local/apache/logs/error_log",
            "/usr/sbin/httpd-prefork": "/var/log/apache2/error.log"
        }
        
        log_file = log_files.get(process_name, "/var/log/apache2/error.log")
        
        if "/opt/apache2/" in process_name:
            # Find the most recent error log
            returncode, log_file, _ = self.run_command("find /opt/apache2/logs -name 'error*' | tail -1")
            if returncode != 0:
                log_file = "/opt/apache2/logs/error_log"
        
        cmd = "timeout 8s sh -c \"grep -i reached {} 2>/dev/null | egrep -v 'mod' | tail -5\"".format(log_file)
        returncode, output, _ = self.run_command(cmd)
        
        if returncode == 0 and output:
            if not self.args.nowarn:
                self.show_box('warn', "{}MaxClients has been hit recently (maximum of 5 results shown), consider the dates and times below:{}".format(self.colors.YELLOW, self.colors.ENDC))
                print(output)
            return True
        else:
            if not self.args.no_ok:
                self.show_box('ok', "{}MaxClients has not been hit recently.{}".format(self.colors.GREEN, self.colors.ENDC))
                if not self.args.nowarn:
                    self.show_box('warn', "{}Apache only logs maxclients/maxrequestworkers hits once in a lifetime, if no restart has happened this event may have been rotated away.{}".format(self.colors.YELLOW, self.colors.ENDC))
                    self.show_box('warn', "{}As a backup check, please compare number of running apache processes (minus 1 for parent) against maxclients/maxrequestworkers.{}".format(self.colors.YELLOW, self.colors.ENDC))
            return False
    
    def check_php_fatal_errors(self, model: str, process_name: str) -> bool:
        """Check for PHP fatal errors in logs"""
        if "/opt/bitnami/" in process_name:
            if not self.args.nowarn:
                self.show_box('warn', "Skipping checking logs for PHP Fatal Errors, Bitnami sends these to stdout.")
            return False
        
        if model.lower() != "prefork":
            if not self.args.nowarn:
                self.show_box('warn', "Skipping checking logs for PHP Fatal Errors, we can only do this if apache is running in prefork and with mod_php running under apache.")
            return False
        
        self.log_verbose("Checking logs for PHP Fatal Errors, this can take some time...")
        
        # Determine scan directories
        scan_dirs = {
            "/usr/sbin/httpd": "/var/log/httpd/",
            "/opt/rh/httpd24/root/usr/sbin/httpd": "/var/log/httpd24/",
            "/usr/local/apache/bin/httpd": "/usr/local/apache/logs/"
        }
        
        scan_dir = scan_dirs.get(process_name, "/var/log/apache2/")
        
        logfile_counts = {}
        self.grep_php_fatal(scan_dir, logfile_counts)
        
        # Also check PHP-FPM logs if detected
        if hasattr(self, 'phpfpm_detected') and self.phpfpm_detected:
            self.grep_php_fatal("/var/log/php-fpm/", logfile_counts)
        
        if logfile_counts:
            if not self.args.nowarn:
                self.show_box('crit', "{}PHP Fatal errors were found, see summaries below.{}".format(self.colors.RED, self.colors.ENDC))
                self.show_box('advisory', "{}Check the logs manually.{}".format(self.colors.YELLOW, self.colors.ENDC))
                for log_file, count in logfile_counts.items():
                    self.show_box('advisory', " - {}{}{}: {}{}{}".format(self.colors.YELLOW, log_file, self.colors.ENDC, self.colors.CYAN, count, self.colors.ENDC))
            return True
        else:
            if not self.args.no_ok:
                self.show_box('ok', "{}No PHP Fatal Errors were found.{}".format(self.colors.GREEN, self.colors.ENDC))
            return False
    
    def grep_php_fatal(self, scan_dir: str, logfile_counts: Dict[str, int]):
        """Search for PHP fatal errors in a directory"""
        if not os.path.exists(scan_dir):
            return
        
        # Limits to avoid long scans in containers or large hosts
        max_files_to_scan = 200
        max_file_size_mb = 20
        time_limit_seconds = 12 if not self.verbose else 8
        start_time = time.time()
        files_scanned = 0

        for root, dirs, files in os.walk(scan_dir):
            for file in files:
                if files_scanned >= max_files_to_scan:
                    self.log_verbose("PHP fatal scan: file limit reached, stopping early")
                    return

                file_path = os.path.join(root, file)
                if not os.path.isfile(file_path):
                    continue

                # Skip very large log files
                try:
                    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
                    if file_size_mb > max_file_size_mb:
                        self.log_verbose("PHP fatal scan: skipping large file {} ({} MB)".format(file_path, round(file_size_mb, 1)))
                        continue
                except (IOError, OSError):
                    continue

                # Stop if we exceed time limit
                if time.time() - start_time > time_limit_seconds:
                    self.log_verbose("PHP fatal scan: time limit reached ({}s), stopping early".format(time_limit_seconds))
                    return

                try:
                    files_scanned += 1
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        fatal_count = 0
                        for line in f:
                            if 'php fatal' in line.lower():
                                fatal_count += 1
                        if fatal_count > 0:
                            logfile_counts[file_path] = fatal_count
                except (IOError, OSError):
                    continue
    
    def calculate_recommendations(self, model: str, maxclients: int, available_mem: int, 
                                services: Dict[str, int], apache_proc_highest: int) -> Dict[str, any]:
        """Calculate MaxClients/MaxRequestWorkers recommendations"""
        if model.lower() != "prefork":
            return {
                'model': model,
                'recommendation': 'N/A',
                'message': "Apache appears to be running in {} mode. Please check manually for backend processes such as PHP-FPM and pm.max_children. Apache2buddy ONLY calculates maxclients for prefork model.".format(model)
            }
        
        # Calculate remaining memory after services
        memory_remaining = available_mem - sum(services.values())
        
        if memory_remaining <= 0:
            raise Apache2BuddyError("Memory Overload Error: Remaining RAM in negative numbers! Available: {}MB, Services using: {}MB".format(available_mem, sum(services.values())))
        
        # Calculate recommended MaxClients
        max_rec_maxclients = int(memory_remaining / apache_proc_highest)
        tolerance = 0.90
        min_rec_maxclients = int(max_rec_maxclients * tolerance)
        
        # Calculate potential memory usage
        max_potential_usage = maxclients * apache_proc_highest
        max_potential_usage_pct_avail = round((max_potential_usage / available_mem) * 100, 2)
        max_potential_usage_pct_remain = round((max_potential_usage / memory_remaining) * 100, 2)
        
        # Determine status
        if min_rec_maxclients <= maxclients <= max_rec_maxclients:
            status = "OK"
        elif maxclients < min_rec_maxclients:
            status = "TOO_LOW"
        else:
            status = "TOO_HIGH"
        
        return {
            'model': model,
            'status': status,
            'current_maxclients': maxclients,
            'recommended_min': min_rec_maxclients,
            'recommended_max': max_rec_maxclients,
            'max_potential_usage': max_potential_usage,
            'max_potential_usage_pct_avail': max_potential_usage_pct_avail,
            'max_potential_usage_pct_remain': max_potential_usage_pct_remain,
            'memory_remaining': memory_remaining
        }
    
    def generate_report(self, apache_info: Dict[str, any], system_info: Dict[str, any], 
                       recommendations: Dict[str, any], services: Dict[str, int]):
        """Generate the final report"""
        print("\n")
        self.insert_hrule()
        print("{}### GENERAL FINDINGS & RECOMMENDATIONS ###{}".format(self.colors.BOLD, self.colors.ENDC))
        self.insert_hrule()
        
        print("Apache2buddy.py report for server: {}{}{} ({}{}{}):".format(self.colors.CYAN, system_info['hostname'], self.colors.ENDC, self.colors.CYAN, system_info['public_ip'], self.colors.ENDC))
        print("")
        
        print("Settings considered for this report:")
        
        # Check for low uptime warning
        if not self.args.no_check_pid and system_info['uptime_days'] == 0:
            if not self.args.nowarn:
                self.show_box('crit', "{}*** LOW UPTIME ***.{}".format(self.colors.RED, self.colors.ENDC))
                self.show_box('advisory', "{}The following recommendations may be misleading - apache has been restarted within the last 24 hours.{}\n".format(self.colors.YELLOW, self.colors.ENDC))
        
        print("\tYour server's physical RAM:\t\t\t\t {}{} MB{}".format(self.colors.CYAN, system_info['available_mem'], self.colors.ENDC))
        
        memory_remaining = system_info['available_mem'] - sum(services.values())
        print("{}\tRemaining Memory after other services considered:\t {}{} MB{}".format(self.colors.BOLD, self.colors.CYAN, memory_remaining, self.colors.ENDC))
        
        if "2.4" in apache_info['version']:
            print("\tApache's MaxRequestWorkers directive:\t\t\t {}{}{} <--------- Current Setting".format(self.colors.CYAN, apache_info['maxclients'], self.colors.ENDC))
        else:
            print("\tApache's MaxClients directive:\t\t\t\t {}{}{} <--------- Current Setting".format(self.colors.CYAN, apache_info['maxclients'], self.colors.ENDC))
        
        print("\tApache MPM Model:\t\t\t\t\t {}{}{}".format(self.colors.CYAN, apache_info['model'], self.colors.ENDC))
        
        if not self.args.noinfo:
            print("\tLargest Apache process (by memory):\t\t\t {}{} MB{}".format(self.colors.CYAN, apache_info['memory_highest'], self.colors.ENDC))
        
        # Handle recommendations based on model
        if recommendations['model'].lower() == "prefork":
            self.show_prefork_recommendations(recommendations, apache_info, system_info)
        else:
            print("\t{}{}{}".format(self.colors.CYAN, recommendations['message'], self.colors.ENDC))
        
        # Log file entry
        self.write_log_entry(apache_info, system_info, recommendations)
        
        self.insert_hrule()
        if not self.args.noinfo:
            print("A log file entry has been made in: /var/log/apache2buddy.log for future reference.\n")
            print("Last 5 entries:\n")
            try:
                returncode, entries, _ = self.run_command("tail -5 /var/log/apache2buddy.log")
                if returncode == 0:
                    print(entries + "\n")
            except:
                pass
    
    def show_prefork_recommendations(self, recommendations: Dict[str, any], 
                                   apache_info: Dict[str, any], system_info: Dict[str, any]):
        """Show recommendations for prefork model"""
        status = recommendations['status']
        current = recommendations['current_maxclients']
        min_rec = recommendations['recommended_min']
        max_rec = recommendations['recommended_max']
        max_usage = recommendations['max_potential_usage']
        pct_avail = recommendations['max_potential_usage_pct_avail']
        pct_remain = recommendations['max_potential_usage_pct_remain']
        
        if status == "OK":
            if not self.args.no_ok:
                if "2.4" in apache_info['version']:
                    self.show_box('shortok', "\t{}Your MaxRequestWorkers setting is within an acceptable range.{}".format(self.colors.GREEN, self.colors.ENDC))
                else:
                    self.show_box('shortok', "\t{}Your MaxClients setting is within an acceptable range.{}".format(self.colors.GREEN, self.colors.ENDC))
        elif status == "TOO_LOW":
            if "2.4" in apache_info['version']:
                self.show_box('crit', "\t{}Your MaxRequestWorkers setting is too low.{}".format(self.colors.RED, self.colors.ENDC))
            else:
                self.show_box('crit', "\t{}Your MaxClients setting is too low.{}".format(self.colors.RED, self.colors.ENDC))
        else:  # TOO_HIGH
            if "2.4" in apache_info['version']:
                self.show_box('crit', "\t{}Your MaxRequestWorkers setting is too high.{}".format(self.colors.RED, self.colors.ENDC))
            else:
                self.show_box('crit', "\t{}Your MaxClients setting is too high.{}".format(self.colors.RED, self.colors.ENDC))
        
        # Show recommended range
        if "2.4" in apache_info['version']:
            print("{}\tYour recommended MaxRequestWorkers setting (based on available memory) is between {} and {}{}. <-- Acceptable Range (90-100% of Remaining RAM)".format(self.colors.YELLOW, min_rec, max_rec, self.colors.ENDC))
        else:
            print("{}\tYour recommended MaxClients setting (based on available memory) is between {} and {}{}. <-- Acceptable Range (90-100% of Remaining RAM)".format(self.colors.YELLOW, min_rec, max_rec, self.colors.ENDC))
        
        # Show potential memory usage
        color = self.colors.RED if pct_remain > 100 else self.colors.CYAN
        print("\tMax potential memory usage:\t\t\t\t {}{} MB{}".format(color, max_usage, self.colors.ENDC))
        print("\tPercentage of TOTAL RAM allocated to Apache:\t\t {}{}%{}".format(color, pct_avail, self.colors.ENDC))
        print("\tPercentage of REMAINING RAM allocated to Apache:\t {}{}%{}".format(color, pct_remain, self.colors.ENDC))
    
    def write_log_entry(self, apache_info: Dict[str, any], system_info: Dict[str, any], 
                       recommendations: Dict[str, any]):
        """Write entry to log file"""
        try:
            with open("/var/log/apache2buddy.log", "a") as f:
                timestamp = time.strftime("%Y/%m/%d %H:%M:%S")
                uptime = "{}d {}h {}m {}s".format(system_info['uptime_days'], system_info['uptime_hours'], system_info['uptime_minutes'], system_info['uptime_seconds'])
                
                if recommendations['model'].lower() == "prefork":
                    if "2.4" in apache_info['version']:
                        f.write('{} Uptime: "{}" Model: "Prefork" Memory: "{} MB" MaxRequestWorkers: "{}" Recommended: "{}" Smallest: "{} MB" Avg: "{} MB" Largest: "{} MB" Highest Pct Remaining RAM: "{}%" ({}% TOTAL RAM)\n'.format(
                            timestamp, uptime, system_info["available_mem"], apache_info["maxclients"], 
                            recommendations["recommended_max"], apache_info["memory_lowest"], 
                            apache_info["memory_average"], apache_info["memory_highest"],
                            recommendations["max_potential_usage_pct_remain"], recommendations["max_potential_usage_pct_avail"]))
                    else:
                        f.write('{} Uptime: "{}" Model: "Prefork" Memory: "{} MB" Maxclients: "{}" Recommended: "{}" Smallest: "{} MB" Avg: "{} MB" Largest: "{} MB" Highest Pct Remaining RAM: "{}%" ({}% TOTAL RAM)\n'.format(
                            timestamp, uptime, system_info["available_mem"], apache_info["maxclients"], 
                            recommendations["recommended_max"], apache_info["memory_lowest"], 
                            apache_info["memory_average"], apache_info["memory_highest"],
                            recommendations["max_potential_usage_pct_remain"], recommendations["max_potential_usage_pct_avail"]))
                else:
                    f.write('{} Uptime: "{}" Model: "{}" Memory: "{} MB" Maxclients: "{}" Recommended: "N/A" Smallest: "{} MB" Avg: "{} MB" Largest: "{} MB"\n'.format(
                        timestamp, uptime, recommendations["model"], system_info["available_mem"], 
                        apache_info["maxclients"], apache_info["memory_lowest"], 
                        apache_info["memory_average"], apache_info["memory_highest"]))
        except IOError:
            pass  # Silently fail if we can't write to log
    
    def main(self):
        """Main execution function"""
        try:
            # Show header
            if not self.args.noheader:
                self.servername = self.get_hostname()
                self.public_ip = self.get_public_ip()
                print("{}{}{}".format(self.colors.GREEN, '#' * 80, self.colors.ENDC))
                print("apache2buddy.py report for {} ({})".format(self.servername, self.public_ip))
                print("{}{}{}".format(self.colors.GREEN, '#' * 80, self.colors.ENDC))
            
            # Preflight checks
            if not self.preflight_checks():
                return 1
            
            # Get PID and process information
            if self.args.pid:
                pid = self.args.pid
            else:
                pid = self.get_pid(self.args.port)
                if pid == 0:
                    if not self.args.nowarn:
                        self.show_box('warn', "{}Nothing seems to be listening on port {}.{} Falling back to process list...".format(self.colors.YELLOW, self.args.port, self.colors.ENDC))
                    
                    # Enhanced fallback to process list
                    apache_processes = [
                        "ps -C httpd -f | grep '^root'",
                        "ps -C apache2 -f | grep '^root'", 
                        "ps -C httpd.worker -f | grep '^root'",
                        "ps -C httpd-prefork -f | grep '^root'",
                        "ps aux | grep -E '(httpd|apache2)' | grep -v grep | grep '^root'"
                    ]
                    
                    pid = 0
                    process_found = False
                    
                    for cmd in apache_processes:
                        returncode, output, _ = self.run_command(cmd)
                        if returncode == 0 and output:
                            lines = output.split('\n')
                            for line in lines:
                                if line.strip():
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        try:
                                            pid = int(parts[1])
                                            process_found = True
                                            self.log_verbose("Found Apache process with PID {} using: {}".format(pid, cmd))
                                            break
                                        except (ValueError, IndexError):
                                            continue
                        if process_found:
                            break
                    
                    # Special case: Check if Apache is running as PID 1 (common in containers)
                    if not process_found:
                        self.log_verbose("Checking if Apache is running as PID 1 (container main process)...")
                        
                        # Method 1: Check if PID 1 is apache directly
                        returncode, pid1_check, _ = self.run_command("ps -p 1 -o comm= 2>/dev/null")
                        self.log_verbose("Method 1 - ps -p 1 -o comm= returned: '{}' (returncode: {})".format(pid1_check, returncode))
                        if returncode == 0 and pid1_check and 'apache' in pid1_check.lower():
                            pid = 1
                            process_found = True
                            self.log_verbose("Found Apache as PID 1 using direct PID check: {}".format(pid1_check))
                            if not self.args.nowarn:
                                self.show_box('info', "Apache detected as PID 1 (container main process)")
                        
                        if not process_found:
                            # Method 2: Check full command line for PID 1
                            returncode, pid1_cmd, _ = self.run_command("ps -p 1 -o cmd= 2>/dev/null")
                            self.log_verbose("Method 2 - ps -p 1 -o cmd= returned: '{}' (returncode: {})".format(pid1_cmd, returncode))
                            if returncode == 0 and pid1_cmd and 'apache' in pid1_cmd.lower():
                                pid = 1
                                process_found = True
                                self.log_verbose("Found Apache as PID 1 using command line check: {}".format(pid1_cmd))
                                if not self.args.nowarn:
                                    self.show_box('info', "Apache detected as PID 1 (container main process)")
                        
                        if not process_found:
                            # Method 3: Alternative ps command
                            returncode, ps_alt, _ = self.run_command("ps aux | head -2 | tail -1")
                            self.log_verbose("Method 3 - ps aux head/tail returned: '{}' (returncode: {})".format(ps_alt, returncode))
                            if returncode == 0 and ps_alt and 'apache' in ps_alt.lower():
                                # Extract PID from the line to verify it's PID 1
                                parts = ps_alt.split()
                                if len(parts) >= 2 and parts[1] == '1':
                                    pid = 1
                                    process_found = True
                                    self.log_verbose("Found Apache as PID 1 using alternative ps: {}".format(ps_alt))
                                    if not self.args.nowarn:
                                        self.show_box('info', "Apache detected as PID 1 (container main process)")
                        
                        if not process_found:
                            # Method 4: Check /proc/1/comm directly
                            try:
                                with open('/proc/1/comm', 'r') as f:
                                    proc1_comm = f.read().strip()
                                self.log_verbose("Method 4 - /proc/1/comm contains: '{}'".format(proc1_comm))
                                if 'apache' in proc1_comm.lower():
                                    pid = 1
                                    process_found = True
                                    self.log_verbose("Found Apache as PID 1 using /proc/1/comm: {}".format(proc1_comm))
                                    if not self.args.nowarn:
                                        self.show_box('info', "Apache detected as PID 1 (container main process)")
                            except Exception as e:
                                self.log_verbose("Method 4 - /proc/1/comm failed: {}".format(e))
                        
                        if not process_found:
                            # Method 5: Check /proc/1/cmdline directly
                            try:
                                with open('/proc/1/cmdline', 'r') as f:
                                    proc1_cmdline = f.read().strip()
                                self.log_verbose("Method 5 - /proc/1/cmdline contains: '{}'".format(proc1_cmdline))
                                if 'apache' in proc1_cmdline.lower():
                                    pid = 1
                                    process_found = True
                                    self.log_verbose("Found Apache as PID 1 using /proc/1/cmdline: {}".format(proc1_cmdline))
                                    if not self.args.nowarn:
                                        self.show_box('info', "Apache detected as PID 1 (container main process)")
                            except Exception as e:
                                self.log_verbose("Method 5 - /proc/1/cmdline failed: {}".format(e))
                        
                        if not process_found:
                            # Method 6: Force PID 1 if we have strong evidence
                            # Since we found Apache binary and netstat commands aren't working,
                            # but we're in a container environment, let's assume PID 1
                            self.log_verbose("Method 6 - Forcing PID 1 assumption for container environment")
                            if not self.args.nowarn:
                                self.show_box('warn', "Could not detect Apache process normally, assuming PID 1 in container environment")
                            pid = 1
                            process_found = True
            
            # Get process name and test if it's Apache
            self.process_name = self.get_process_name(pid)
            if not self.process_name:
                self.show_box('crit', "Unable to determine the name of the process. Is apache running on this server?")
                return 1
            
            if not self.args.noinfo:
                self.show_box('info', "The process listening on port {}{}{} is {}{}{}".format(self.colors.CYAN, self.args.port, self.colors.ENDC, self.colors.CYAN, self.process_name, self.colors.ENDC))
            
            # Test if process is Apache
            if not self.test_process(self.process_name):
                self.show_box('crit', "The process is not Apache.")
                return 1
            
            # Get Apache information
            self.apache_version = self.get_apache_version(self.process_name)
            self.apache_root = self.get_apache_root(self.process_name)
            self.apache_conf_file = self.get_apache_conf_file(self.process_name)
            self.model = self.get_apache_model(self.process_name)
            
            if not self.args.noinfo:
                self.show_box('info', "The process running on port {}{}{} is {}{}{}.".format(self.colors.CYAN, self.args.port, self.colors.ENDC, self.colors.CYAN, self.apache_version, self.colors.ENDC))
                self.show_box('info', "Apache is using {}{}{} model.".format(self.colors.CYAN, self.model, self.colors.ENDC))
            
            # Build configuration array
            full_config_path = self.apache_conf_file
            if not os.path.isabs(self.apache_conf_file):
                full_config_path = os.path.join(self.apache_root, self.apache_conf_file)
            
            if not os.path.exists(full_config_path):
                self.show_box('crit', "Apache configuration file does not exist: {}".format(full_config_path))
                return 1
            
            if not self.args.noinfo:
                self.show_box('info', "The full path to the Apache config file is: {}{}{}".format(self.colors.CYAN, full_config_path, self.colors.ENDC))
            
            self.config_array = self.build_config_array(full_config_path, self.apache_root)
            
            # Get Apache user and other settings
            apache_user = self.find_master_value(self.config_array, self.model, 'user')
            if apache_user == "CONFIG NOT FOUND":
                if os.path.exists("/etc/apache2/envvars"):
                    returncode, apache_user, _ = self.run_command("grep 'export APACHE_RUN_USER=' /etc/apache2/envvars | awk -F'=' '{print $2}'")
                    apache_user = apache_user.strip()
            
            # Get MaxClients/MaxRequestWorkers
            if "2.4" in self.apache_version:
                maxclients = self.find_master_value(self.config_array, self.model, 'maxrequestworkers')
                if maxclients == "CONFIG NOT FOUND":
                    maxclients = self.find_master_value(self.config_array, self.model, 'maxclients')
            else:
                maxclients = self.find_master_value(self.config_array, self.model, 'maxclients')
            
            try:
                maxclients = int(maxclients) if maxclients != "CONFIG NOT FOUND" else 256
            except ValueError:
                maxclients = 256
            
            # Get memory information
            self.available_mem = self.get_available_memory()
            if not self.args.noinfo:
                self.show_box('info', "Your server has {}{} MB{} of PHYSICAL memory.".format(self.colors.CYAN, self.available_mem, self.colors.ENDC))
            
            # Get memory usage statistics
            apache_proc_highest = self.get_memory_usage(self.process_name, apache_user, 'high')
            apache_proc_lowest = self.get_memory_usage(self.process_name, apache_user, 'low')
            apache_proc_average = self.get_memory_usage(self.process_name, apache_user, 'average')
            
            if not self.args.noinfo and self.model.lower() == "prefork":
                self.show_box('info', "The smallest apache process is using {}{} MB{} of memory".format(self.colors.CYAN, apache_proc_lowest, self.colors.ENDC))
                self.show_box('info', "The average apache process is using {}{} MB{} of memory".format(self.colors.CYAN, apache_proc_average, self.colors.ENDC))
                self.show_box('info', "The largest apache process is using {}{} MB{} of memory".format(self.colors.CYAN, apache_proc_highest, self.colors.ENDC))
            
            # Get uptime
            if not self.args.no_check_pid:
                pid_file = self.find_master_value(self.config_array, self.model, 'pidfile')
                if pid_file != "CONFIG NOT FOUND" and os.path.exists(pid_file):
                    with open(pid_file, 'r') as f:
                        parent_pid = int(f.read().strip())
                    uptime_days, uptime_hours, uptime_minutes, uptime_seconds = self.get_apache_uptime(parent_pid)
                    if not self.args.noinfo:
                        self.show_box('info', "Apache has been running {}{}{}d {}{}{}h {}{}{}m {}{}{}s.".format(self.colors.CYAN, uptime_days, self.colors.ENDC, self.colors.CYAN, uptime_hours, self.colors.ENDC, self.colors.CYAN, uptime_minutes, self.colors.ENDC, self.colors.CYAN, uptime_seconds, self.colors.ENDC))
                else:
                    uptime_days = uptime_hours = uptime_minutes = uptime_seconds = 0
            else:
                uptime_days = uptime_hours = uptime_minutes = uptime_seconds = 0
            
            # Detect additional services
            services = self.detect_additional_services()
            
            # Check for issues
            if not self.args.skip_maxclients:
                self.check_maxclients_hits(self.model, self.process_name)
            
            if not self.args.skip_php_fatal and hasattr(self, 'php_available') and self.php_available:
                self.check_php_fatal_errors(self.model, self.process_name)
            
            # Display PHP memory limit
            if hasattr(self, 'php_available') and self.php_available and not self.args.noinfo:
                php_memory_limit = self.get_php_memory_limit()
                self.show_box('info', "Your PHP Memory Limit (Per-Process) is {}{}{}.".format(self.colors.CYAN, php_memory_limit, self.colors.ENDC))
            
            # Generate recommendations
            recommendations = self.calculate_recommendations(
                self.model, maxclients, self.available_mem, services, apache_proc_highest
            )
            
            # Prepare data structures for report
            apache_info = {
                'version': self.apache_version,
                'model': self.model,
                'maxclients': maxclients,
                'memory_highest': apache_proc_highest,
                'memory_lowest': apache_proc_lowest,
                'memory_average': apache_proc_average
            }

            
            system_info = {
                'hostname': self.servername if hasattr(self, 'servername') else socket.gethostname(),
                'public_ip': self.public_ip if hasattr(self, 'public_ip') else "x.x.x.x",
                'available_mem': self.available_mem,
                'uptime_days': uptime_days,
                'uptime_hours': uptime_hours,
                'uptime_minutes': uptime_minutes,
                'uptime_seconds': uptime_seconds
            }
            
            # Generate final report
            self.generate_report(apache_info, system_info, recommendations, services)
            
            # Show important message
            if not self.args.noinfo and not self.args.nonews:
                print("\n{}** IMPORTANT MESSAGE **\n\napache2buddy is not a troubleshooting tool.\nDo not use it to try and determine why your site\nwent down or why it was slow.\n\nPerform some proper investigations first, and\nonly if you found that you were hitting the\nMaxRequestWorkers limit, or if your server was\nrunning out of memory (primarily due to\nexcessive memory usage by Apache), should you\nrun this script and refer to its output..{}\n".format(self.colors.RED, self.colors.ENDC))
            
            return 0
            
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            return 1
        except Apache2BuddyError as e:
            self.show_box('crit', str(e))
            return 1
        except Exception as e:
            self.show_box('crit', "Unexpected error: {}".format(e))
            if self.verbose:
                import traceback
                traceback.print_exc()
            return 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Apache2Buddy - Apache Performance Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Key:
    [ -- ]  = Information
    [ @@ ]  = Advisory  
    [ >> ]  = Warning
    [ !! ]  = Critical
        """
    )
    
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT,
                       help='Specify an alternate port to check (default: 80)')
    parser.add_argument('--pid', type=int, default=0,
                       help='Specify a PID to bypass multiple PIDs error')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Use verbose output (noisy, for debugging)')
    parser.add_argument('-n', '--nocolor', action='store_true',
                       help='Use default terminal colors')
    parser.add_argument('-H', '--noheader', action='store_true',
                       help='Do not show header title bar')
    parser.add_argument('-N', '--noinfo', action='store_true',
                       help='Do not show informational messages')
    parser.add_argument('-K', '--no-ok', action='store_true',
                       help='Do not show OK messages')
    parser.add_argument('-W', '--nowarn', action='store_true',
                       help='Do not show warning messages')
    parser.add_argument('-L', '--light-term', action='store_true',
                       help='Show colors for light background terminal')
    parser.add_argument('-r', '--report', action='store_true',
                       help='Report mode (implies other flags)')
    parser.add_argument('-P', '--no-check-pid', action='store_true',
                       help="Don't check parent PID file size")
    parser.add_argument('--skip-maxclients', action='store_true',
                       help='Skip checking maxclients hits')
    parser.add_argument('--skip-php-fatal', action='store_true',
                       help='Skip checking for PHP fatal errors')
    parser.add_argument('--skip-updates', action='store_true',
                       help='Skip checking for package updates')
    parser.add_argument('-O', '--skip-os-version-check', action='store_true',
                       help='Skip OS version check (not recommended)')
    parser.add_argument('--nonews', action='store_true',
                       help='Do not show news messages')
    
    args = parser.parse_args()
    
    # Handle report mode
    if args.report:
        args.noheader = True
        args.noinfo = True
        args.nonews = True
        args.nowarn = True
        args.no_ok = True
        args.skip_maxclients = True
        args.skip_php_fatal = True
        args.skip_updates = True
    
    try:
        buddy = Apache2Buddy(args)
        exit_code = buddy.main()
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print("Error: {}".format(e))
        sys.exit(1)