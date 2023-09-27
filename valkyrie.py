#!/usr/bin/env python
# -*- coding: utf8 -*-

"""

      /( /\ )\
      |/'\/`\|  ___ ___ _______ _____   __  __ ___ ___ ______ _______ _______
      |-.__.-| |   |   |   _   |     |_|  |/  |   |   |   __ \_     _|    ___|
      |"-,,-"| |   |   |       |       |     < \     /|      <_|   |_|    ___|
      |  ||  |  \_____/|___|___|_______|__|\__| |___| |___|__|_______|_______|
      `._||_.'
   
		VALKYRIE - 0.1
		
		Written by Peter Bartels
		
		https://www.kangafoo.de
		
		Valkyrie is a tiny tool which assists with local privilege escalation.
        The current version supports finding kernel exploits and suid bins.
        
        Attention
        
        Initial pre-release, some functionality is still missing.
        Database will be extended.
        Future functionality will be added.


"""

import sys
import argparse
import os
import pwd
import grp
import platform
import json

binpaths = ["/usr/bin","/usr/sbin","/bin","/sbin"]

intfiles = ["/etc/passwd","/etc/shadow","/etc/group","/etc/sudoers"]

#database for vulnerable kernels, perhaps extern file in future?
datadb = '''
[
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
    for readfile in readlist:
        if os.access(readfile, os.R_OK):
            print("[~] Readable: "+readfile)

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
    parser = argparse.ArgumentParser("%prog [options] arg1 arg2")
    parser.add_argument("-d", "--detect", dest="detect",default=False, action="store_true",help="automatically gets the kernel version")
    parser.add_argument("-m", "--manual", dest="manual",default="0.0.0",help="specify the kernel version e.g. 2.6.18")
    parser.add_argument("-s", "--suid",dest="suidfile",default=False, action="store_true",help="find suid binary files in default bin dirs")
    parser.add_argument("-r", "--read",dest="readint",default=False, action="store_true",help="find interesting readable files")
    options = parser.parse_args()
    if len(sys.argv) < 2:
        infoheader()
        parser.print_help()
        quit()
    else:
        detect = options.detect
        kernel = options.manual
        sfile = options.suidfile
        dbase = json.loads(datadb)
        infoheader()
        print("[~] Exploits in DB: "+str(len(dbase)))
        if options.detect:
            detected_kernel = get_kernel_version()
            print("[~] Kernel version found: "+detected_kernel)
            check_for_vuln(version_to_tuple(detected_kernel),dbase)
        elif kernel != "0.0.0":
            print("[~] Kernel version given: "+kernel)
            check_for_vuln(version_to_tuple(kernel),dbase)
        if options.suidfile:
            print("\n[~] Scanning for suid binaries..\n")
            check_paths_for_suid()
        if options.readint:
            print("\n[~] Scanning for interesting readable files..\n")
            check_files_reading(intfiles)