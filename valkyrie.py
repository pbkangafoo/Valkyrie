#!/usr/bin/env python
# -*- coding: utf8 -*-

"""

      /( /\ )\
      |/'\/`\|  ___ ___ _______ _____   __  __ ___ ___ ______ _______ _______
      |-.__.-| |   |   |   _   |     |_|  |/  |   |   |   __ \_     _|    ___|
      |"-,,-"| |   |   |       |       |     < \     /|      <_|   |_|    ___|
      |  ||  |  \_____/|___|___|_______|__|\__| |___| |___|__|_______|_______|
      `._||_.'
   
		VALKYRIE - 0.5
		
		Written by Peter Bartels
		
		https://www.kangafoo.de
		
		Valkyrie is a tiny tool which assists with local privilege escalation.
        The current version supports finding kernel exploits and suid bins.
        
        Attention
        
        Initial pre-release, some functionality is still missing.
        Database will be extended.
        Future functionality will be added.
        
        Version 0.5:
            + bugfix in subprocess to support different versions of python
            + new entries to exploit database
            + new entries to readable files
        
        Version 0.4:
            + scans binaries in binary paths for capabilities
        
        Version 0.3:
            + scans for installed tools and versions, suggests local exploits for
            + minor fixes

        Version 0.2:
            + added more exploits to db
            + scan for writeable directories
            + added more interesting files to check for read permission
            
        Version 0.1:
            + initial release


"""

import sys
import argparse
import os
import platform
import json
import re
import subprocess


binpaths = ["/usr/bin","/usr/sbin","/bin","/sbin"]

intfiles = ["/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/sudoers",
            "/etc/issue",
            "/etc/motd",
            "/etc/shells",
            "/etc/networks",
            "/etc/hostname",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/crontab"]

bintools = ["sudo","screen"]

tooldb = '''
[
    {
        "program" : "screen",
        "name" : "GNU screen privilege escalation",
        "description" : "GNU screen v4.9.0 - Privilege Escalation (Arch / FreeBSD)",
        "cve" : "2023-24626",
        "details" : "https://nvd.nist.gov/vuln/detail/CVE-2023-24626",
        "download" : "https://www.exploit-db.com/raw/51252",
        "language" : "python",
        "minver" : "4.9.0",
        "maxver" : "4.9.0"
    },
    {
        "program" : "screen",
        "name" : "GNU screen privilege escalation",
        "description" : "GNU screen v4.5.0 - Privilege Escalation",
        "cve" : "none",
        "details" : "https://www.exploit-db.com/exploits/41154",
        "download" : "https://www.exploit-db.com/raw/41154",
        "language" : "c",
        "minver" : "4.5.0",
        "maxver" : "4.5.0"
    },
    {
        "program" : "sudo",
        "name" : "sudo privilege escalation",
        "description" : "sudo 1.8.0 to 1.9.12p1 - Privilege Escalation",
        "cve" : "2023-22809",
        "details" : "https://nvd.nist.gov/vuln/detail/CVE-2023-22809",
        "download" : "https://www.exploit-db.com/raw/51217",
        "language" : "python",
        "minver" : "1.8.0",
        "maxver" : "1.9.12"
    },
    {
        "program" : "sudo",
        "name" : "sudo security bypass",
        "description" : "sudo to 1.8.27 - Security Bypass",
        "cve" : "2019-14287",
        "details" : "https://nvd.nist.gov/vuln/detail/CVE-2019-14287",
        "download" : "https://www.exploit-db.com/exploits/47502",
        "language" : "bash",
        "minver" : "0.0.0",
        "maxver" : "1.8.27"
    }
]'''

#database for vulnerable kernels, perhaps extern file in future?
datadb = '''
[
    {
        "name" : "Dirty Pipe",
        "description" : "Linux Kernel 5.8 < 5.16.11 - Local Privilege Escalation (DirtyPipe)",
        "cve" : "2022-0847",
        "details" : "https://dirtypipe.cm4all.com/",
        "download" : "https://packetstormsecurity.com/files/download/166229/write_anything.c",
        "language" : "c",
        "minver" : "5.8",
        "maxver" : "5.16.11"
    },
    {
        "name" : "Netfilter Local Privilege Escalation",
        "description" : "Linux Kernel 2.6.19 < 5.9 - Netfilter Local Privilege Escalation",
        "cve" : "2021-22555",
        "details" : "https://nvd.nist.gov/vuln/detail/CVE-2021-22555",
        "download" : "https://www.exploit-db.com/raw/50135",
        "language" : "c",
        "minver" : " 2.6.19",
        "maxver" : "5.8.0"
    },
    {
        "name" : "PTRACE_TRACEME local root",
        "description" : "Linux Kernel 4.10 < 5.1.17 - PTRACE_TRACEME pkexec Local Privilege Escalation",
        "cve" : "2019-13272",
        "details" : "https://bugs.chromium.org/p/project-zero/issues/detail?id=1903",
        "download" : "https://raw.githubusercontent.com/jas502n/CVE-2019-13272/master/CVE-2019-13272.c",
        "language" : "c",
        "minver" : "4.10",
        "maxver" : "5.1.17"
    },
    {
        "name" : "io_uring Offload of sendmsg()",
        "description" : "Linux 5.3 - Privilege Escalation via io_uring Offload of sendmsg() onto Kernel Thread with Kernel Creds",
        "cve" : "2019-19241",
        "details" : "https://bugs.chromium.org/p/project-zero/issues/detail?id=1975",
        "download" : "https://dl.packetstormsecurity.net/1912-exploits/GS20191216153944.txt",
        "language" : "c",
        "minver" : "5.3",
        "maxver" : "5.4.2"
    },
    {
        "name" : "map_write() CAP_SYS_ADMIN",
        "description" : "Linux Kernel 4.15.x - 4.19.2 - map_write() CAP_SYS_ADMIN Local Privilege Escalation (dbus Method)",
        "cve" : "2018-18955",
        "details" : "http://www.securityfocus.com/bid/105941",
        "download" : "https://www.exploit-db.com/download/47165",
        "language" : "bash",
        "minver" : "4.15.0",
        "maxver" : "4.19.1"
    },
    {
        "name" : "mq_notify: double sock_put()",
        "description" : "Linux Kernel 2.6.0 - 4.11.8 - mq_notify double sock_put() Local Privilege Escalation",
        "cve" : "2017-11176",
        "details" : "https://www.securityfocus.com/bid/99919",
        "download" : "https://www.exploit-db.com/download/45553",
        "language" : "c",
        "minver" : "2.6.0",
        "maxver" : "4.11.9"
    },
    {
        "name" : "local memory corruption vulnerability",
        "description" : "Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation",
        "cve" : "2017-16995",
        "details" : "https://www.securityfocus.com/bid/102288",
        "download" : "https://www.exploit-db.com/download/45010",
        "language" : "c",
        "minver" : "2.6.0",
        "maxver" : "4.14.6"
    },
    {
        "name" : "AF_PACKET Race Condition Privilege Escalation",
        "description" : "Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x64)",
        "cve" : "2016-8655",
        "details" : "https://nvd.nist.gov/vuln/detail/CVE-2016-8655",
        "download" : "https://packetstormsecurity.com/files/download/140063/chocobo_root.c",
        "language" : "c",
        "minver" : "4.4.0",
        "maxver" : "4.4.0"
    }
]'''


def clear():
    """
    
    clear() -> no return
    
    just clear screen for linux and windows
    
    """
    os.system("cls" if os.name == "nt" else "clear")	



def get_filename(url):
    """
    
    get_filename(string) -> string

    extracts the filename from a given url
    
    """
    pos = (url.rfind('/')+1)
    return url[pos:]



def download_file(url):
    """

    download_file(string) -> no return
    
    downloads a file from a given url and stores it with the same name
    
    """
    

def fix_directory_path(directory):
    """

    fix_directory_path(string) -> string

    checks whether the last character is a slash and adds it when missing

    """
    if directory[-1] != os.path.sep:
        directory += os.path.sep
    return directory


def get_kernel_version():
    """
    
    get_kernel_version() -> string
    
    returns the version of kernel, equal to uname -r
    
    """
    kernel = ""
    kernel = platform.release()
    kernel = kernel[0:kernel.find('-')]
    return kernel



def version_to_tuple(version):
    """
    
    version_to_tuple(string) -> tuple
    
    converts a version as string to tuple, to make versions comparable
    
    string to tuple: https://www.codespeedy.com/comma-separated-string-to-tuple-in-python/
    
    """
    splitted = []
    if version != "":
        for subnum in version.split('.'):
            splitted.append(int(subnum))
    return tuple(splitted)


def is_vulnerable(myversion,minversion,maxversion):
    """

    is_vulnerable(tuple,tuple,tuple) -> boolean
    
    function checks whether a given kernel version is in a certain range of vulnerable kernel versions

    """
    if ((minversion <= myversion) and (maxversion >= myversion)):
        return True
    else:
        return False


def check_for_vuln_tool(program,myversion,mydb):
    """

    check_for_vuln_tool(string,tuple,json) -> no return, just output

    Function checks the given program and its version against the database looking for potential exploits
    
    """
    for item in mydb:
        #print (item['program'])
        if (program == item['program']):
            if is_vulnerable(myversion,version_to_tuple(item['minver']),version_to_tuple(item['maxver'])):
                print("\n[~] Name: "+item['name']+" (CVE: "+item['cve']+")")
                print("[~] Description: "+item['description'])
                print("[~] Details: "+item['details'])
                print("[~] Download: "+item['download']+"\n")
                #print(" -- "+get_filename(item['download']))

def check_for_vuln(myversion,mydb):
    """

    check_for_vuln(tuple,json) -> no return, just output

    Function checks the given kernel version against the database looking for potential exploits
    
    """
    for item in mydb:
        if is_vulnerable(myversion,version_to_tuple(item['minver']),version_to_tuple(item['maxver'])):
            print("\n[~] Name: "+item['name']+" (CVE: "+item['cve']+")")
            print("[~] Description: "+item['description'])
            print("[~] Details: "+item['details'])
            print("[~] Download: "+item['download'])
            #print(" -- "+get_filename(item['download']))


def get_installed_program_version(program_name):
    """
    get_installed_program_version(string) -> string

    Executes a given program and returns the version number of it.
    """
    if not program_name:
        return "Error: Program name is empty"
    
    try:
        # Check if the Python version is 3.7+ and use 'text' if available
        if sys.version_info >= (3, 7):
            version_info = subprocess.check_output([program_name, '--version'], stderr=subprocess.STDOUT, text=True)
        else:
            version_info = subprocess.check_output([program_name, '--version'], stderr=subprocess.STDOUT, universal_newlines=True)
        
        # Use regular expressions to extract the version number
        version_match = re.search(r'(\d+\.\d+(\.\d+)?)', version_info)
        
        if version_match:
            return version_match.group(1)
        else:
            return "Version not found"
    except subprocess.CalledProcessError as e:
        # Handle the case when the program doesn't exist or --version is not supported
        return f"Error: CalledProcessError {e.returncode}\n{e.output}"
    except FileNotFoundError:
        # Handle the case when the program is not found
        return f"Error: {program_name} not found"
    except Exception as e:
        # Catch all other possible exceptions
        return f"An unexpected error occurred: {e}"


def scan_for_local(proglist,dbtool):
    for item in proglist:
        version = get_installed_program_version(item)
        print("Version of "+item+": "+version)
        check_for_vuln_tool(item,version_to_tuple(version),dbtool)

def is_directory_writable(directory):
    """

    is_directory_writeable(string) -> boolean

    function checks whether there are permissions to write files there

    """
    return os.access(directory, os.W_OK)


def scan_writable_directories(root_directory):
    """

    scan_writeable_directories(string) -> no return, print directly

    Scan all subdirectories of a given directory and check if they are writable.

    """
    for dirpath, dirnames, filenames in os.walk(root_directory):
        for dirname in dirnames:
            full_dir_path = os.path.join(dirpath, dirname)
            if is_directory_writable(full_dir_path):
                print("[~] writeable: "+full_dir_path)


def is_suid(checkfile):
	""" checks whether a file has suid/sgid flag, minimum value is 4

	is_suid(input string) -> return boolean

	"""
	permission = oct(os.stat(checkfile).st_mode)[-4:]
	suidperm = permission[0]
	if int(suidperm) >= 4:
		return True
	return False

def check_paths_for_suid():
    """

    check_paths_for_suid() -> no return, prints directly

    """
    for binpath in binpaths:
        for root, dirs, files in os.walk(binpath):
            for file in files:
                sfile = os.path.join(root,file)
                if is_suid(sfile):
                    print("[~] suid: "+sfile)
				#else: for debug purposes
					#print("not suid: "+sfile)
                    
def check_files_reading(readlist):
    """

    check_files_reading(list) -> no return, direct print

    function processes a list of files and returns whether they are readable

    """
    for readfile in readlist:
        if os.access(readfile, os.R_OK):
            print("[~] Readable: "+readfile)


def get_capabilities(binary_path):
    """

    get_capabilities(string) -> string

    function executes getcap and returns capabilities

    """
    try:
        result = subprocess.run(['getcap', binary_path], capture_output=True, text=True, check=True)
        capabilities = result.stdout.strip()
        return capabilities
    except subprocess.CalledProcessError:
        return f"Error: Could not get capabilities for {binary_path}"


def check_paths_for_caps():
    """

    check_paths_for_caps() -> no return, prints directly

    """
    for binpath in binpaths:
        for root, dirs, files in os.walk(binpath):
            for file in files:
                sfile = os.path.join(root,file)
                capabilities = get_capabilities(sfile)
                if capabilities:
                    print(f"Capabilities for {sfile}:\n{capabilities}\n")


def infoheader():
    """
    
    infoheader() -> no return
    
    prints header logo and avatar target name and CID
    
    """
    clear()
    print(" /( /\ )\                                                                  ")
    print(" |/'\/`\|  ___ ___ _______ _____   __  __ ___ ___ ______ _______ _______   ")
    print(" |-.__.-| |   |   |   _   |     |_|  |/  |   |   |   __ \_     _|    ___|  ")
    print(" |\"-,,-\"| |   |   |       |       |     < \     /|      <_|   |_|    ___|")
    print(" |  ||  |  \_____/|___|___|_______|__|\__| |___| |___|__|_______|_______|  ")
    print(" `._||_.'     V       A       L      K       Y       R      I       E    \n")



if __name__=="__main__":
    parser = argparse.ArgumentParser(prog="valkyrie.py",usage="%(prog)s [options] arg1 arg2")
    parser.add_argument("-d", "--detect", dest="detect",default=False, action="store_true",help="automatically gets the kernel version and checks for exploits")
    parser.add_argument("-m", "--manual", dest="manual",default="0.0.0",help="specify the kernel version e.g. 2.6.18 and check for exploits")
    parser.add_argument("-l", "--local", dest="lsploit",default=False, action="store_true",help="automatically gets the version of installed tools and checks for exploits")
    parser.add_argument("-s", "--suid",dest="suidfile",default=False, action="store_true",help="find suid binary files in default bin dirs")
    parser.add_argument("-c", "--cap",dest="capas",default=False, action="store_true",help="display capabilities of files in default bin dirs")
    parser.add_argument("-r", "--read",dest="readint",default=False, action="store_true",help="find interesting readable files")
    parser.add_argument("-w", "--write", dest="wdir",default="",help="specify the root directory to scan for writeable directories")
    options = parser.parse_args()
    if len(sys.argv) < 2:
        infoheader()
        parser.print_help()
        quit()
    else:
        detect = options.detect
        kernel = options.manual
        ldetect = options.lsploit
        sfile = options.suidfile
        rdir = options.wdir
        tbase = json.loads(tooldb)
        dbase = json.loads(datadb)
        infoheader()
        print("[~] Kernel Exploits in DB: "+str(len(dbase)))
        print("[~] Local Exploits in DB: "+str(len(tbase)))
        if options.detect:
            detected_kernel = get_kernel_version()
            print("[~] Kernel version found: "+detected_kernel)
            check_for_vuln(version_to_tuple(detected_kernel),dbase)
        elif kernel != "0.0.0":
            print("[~] Kernel version given: "+kernel)
            check_for_vuln(version_to_tuple(kernel),dbase)
        if options.lsploit:
            print("\n[~] Scanning for local exploits among installed tools..\n")
            scan_for_local(bintools,tbase)
        if options.suidfile:
            print("\n[~] Scanning for suid binaries..\n")
            check_paths_for_suid()
        if options.capas:
            print("\n[~] Scanning binaries for capabilities..\n")
            check_paths_for_caps()
        if options.readint:
            print("\n[~] Scanning for interesting readable files..\n")
            check_files_reading(intfiles)
        if options.wdir:
            print("\n[~] Scanning for writeable directories..")
            print("[~] Rootdir: "+rdir+"\n")
            scan_writable_directories(fix_directory_path(rdir))