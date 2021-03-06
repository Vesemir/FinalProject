#ported using win32 implementations of some linux tools from idea:#
###################################################################################
#http://blog.michaelboman.org/2014/01/making-virtualbox-nearly-undetectable.html  #
###################################################################################
#which is based on#
########################################################################
#http://blog.prowling.nu/2012/10/modifying-virtualbox-settings-for.html#
########################################################################
#which was "bluntly stolen" from#
##########################################################################################
#https://itsultra.wordpress.com/2011/12/07/how-to-play-maplestory-using-virtualbox-4-1-x/#
##########################################################################################
import os
import re
import sys
from subprocess import Popen, PIPE, STDOUT

CURDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(CURDIR, os.pardir))

from PyCommands.settings import VBOXMANAGE, DEPLOY_DIR

ACPI = os.path.join(CURDIR, 'acpidump.exe')
DMI = os.path.join(CURDIR, 'dmidecode.exe')
HDPARM = os.path.join(CURDIR, 'hdparm.exe')
ENUMCD = os.path.join(CURDIR, 'EnumCD.exe')
VENDORRE = re.compile(r"Vendor: ([A-Za-z0-9 .,]+)")
VERSIONRE = re.compile(r"Version: ([A-Za-z0-9 \(\).,]+)")
RELEASEDATERE = re.compile(r"Release Date: ([0-9/-]+)")
MANUFRE = re.compile(r"Manufacturer: ([A-Za-z0-9 .,]+)")
PRODUCTRE = re.compile(r"Product Name: ([A-Za-z0-9 -.,]+)")
SERIALRE = re.compile(r"Serial Number: ([A-Za-z0-9 -]+)")
SKURE = re.compile(r"SKU Number: ([A-Za-z0-9 -.]+)")
FAMILYRE = re.compile(r"Family: ([A-Za-z0-9 -.]+)")
UUIDRE = re.compile(r"UUID: ([A-Fa-f0-9-]+)")
TYPERE = re.compile(r"Type: ([A-Za-z 0-9]+)")
HDRE = re.compile(r'Model=([A-Z0-9- ]+), FwRev=([A-Z0-9.]+), SerialNo=\s+([A-Z0-9-]+)', flags=re.IGNORECASE)
CDRE = re.compile(r'Vendor ID\s*:\s*([A-Z0-9 ]+)\r\nProduct ID\s*:\s*([A-Z0-9 -]+)\s*\r\nProduct Rev:\s*([0-9.]+)\s*', flags=re.MULTILINE | re.IGNORECASE)
CHASSIS = [  
    "Other",   
    "Unknown",  
    "Desktop",  
    "Low Profile Desktop",  
    "Pizza Box",  
    "Mini Tower",  
    "Tower",  
    "Portable",  
    "Laptop",  
    "Notebook",  
    "Hand Held",  
    "Docking Station",  
    "All In One",  
    "Sub Notebook",  
    "Space-saving",  
    "Lunch Box",  
    "Main Server Chassis",  
    "Expansion Chassis",  
    "Sub Chassis",  
    "Bus Expansion Chassis",  
    "Peripheral Chassis",  
    "RAID Chassis",  
    "Rack Mount Chassis",  
    "Sealed-case PC",  
    "Multi-system",  
    "CompactPCI",  
    "AdvancedTCA",  
    "Blade",  
    "Blade Enclosing"  
    ]

BAT_TEMPLATE =\
"""@reg copy HKLM\HARDWARE\ACPI\DSDT\VBOX__ HKLM\HARDWARE\ACPI\DSDT\<VENDORNAME> /s /f
@reg delete HKLM\HARDWARE\ACPI\DSDT\VBOX__ /f

@reg copy HKEY_LOCAL_MACHINE\HARDWARE\ACPI\DSDT\<VENDORNAME>\VBOXBIOS HKEY_LOCAL_MACHINE\HARDWARE\ACPI\DSDT\<VENDORNAME>\<VENDOR>BIOS /s /f
@reg delete HKEY_LOCAL_MACHINE\HARDWARE\ACPI\DSDT\<VENDORNAME>\VBOXBIOS /f

@reg copy HKEY_LOCAL_MACHINE\HARDWARE\ACPI\FADT\<VENDORNAME>\VBOXFACP HKEY_LOCAL_MACHINE\HARDWARE\ACPI\FADT\<VENDORNAME>\<VENDOR>FACP /s /f
@reg delete HKEY_LOCAL_MACHINE\HARDWARE\ACPI\FADT\<VENDORNAME>\VBOXFACP /f

@reg copy HKEY_LOCAL_MACHINE\HARDWARE\ACPI\RSDT\<VENDORNAME>\VBOXRSDT HKEY_LOCAL_MACHINE\HARDWARE\ACPI\RSDT\<VENDORNAME>\<VENDOR>RSDT /s /f
@reg delete HKEY_LOCAL_MACHINE\HARDWARE\ACPI\RSDT\<VENDORNAME>\VBOXRSDT /f

@reg add HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System /v VideoBiosVersion /t REG_MULTI_SZ /d "VGA BIOS v1.14" /f

@reg delete HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\SystemBiosDate /f
@reg add HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System /v SystemBiosDate /t REG_SZ /d "15/10/2011" /f
"""

from random import randint


intel_bytes =b'\xDC\xA9\x71'
command = 'acpidump -n DSDT -b'
command2 = 'dmidecode -t%d'

def popen(*args):
    process = Popen(args=args, stdout=PIPE)
    buff = process.stdout.read()
    process.terminate()
    process.wait()
    return buff


def randomMAC():
    addr = [0x00, 0x02, 0xb3, #intel reserved
            randint(0x00, 0x7f),
            randint(0x00, 0xff),
            randint(0x00, 0xff)]
    return ''.join(hex(byte).split('x')[1].zfill(2) for byte in addr)


def getacpi():
    popen(ACPI, '-n', 'DSDT', '-b') # -b dumps table to dsdt.dat
    retval = os.path.join(CURDIR, 'dsdt.dat')
    assert os.path.isfile(retval)
    return os.altsep.join(retval.split(os.sep))


def gethd():
    hd = dict()
    buff = popen(HDPARM, '-i', '/dev/sda').decode('ascii')
    res = HDRE.search(buff)
    hd['SerialNumber'] = 'string:' + res.group(3).strip()
    hd['FirmwareRevision'] = res.group(2).strip()
    hd['ModelNumber'] = res.group(1).strip()
    return hd


def getcd():
    cd = dict()
    buff = popen(ENUMCD).decode('ascii')
    results = CDRE.findall(buff)
    candy = results.pop()
    try:
        while 'virtual' in candy[1].lower():
            candy = results.pop()
    except:
        print("ALL YOUR CDs ARE VIRTUAL! BYE!")
        sys.exit(1)

    cd['ATAPIVendorId'] = candy[0].strip()
    cd['ATAPIProductId'] = candy[1].strip()
    cd['ATAPIRevision'] = candy[2].strip()
    cd['ATAPISerialNumber'] = 'string:' + str(randint(1, 10**19))
    return cd


def genbat(vendor='GBT'):
    vendorname = vendor.ljust(6, '_')
    dump = BAT_TEMPLATE.replace('<VENDORNAME>', vendorname)
    dump = dump.replace('<VENDOR>', vendor)
    with open(os.path.join(DEPLOY_DIR, 'modreg.bat'), 'w') as outp:
        outp.write(dump)
        

def getdmi():
    dmi = dict()
    buff = popen(DMI, '-t0').decode('ascii')
    dmi['DmiBIOSVendor'] = VENDORRE.search(buff).group(1)
    dmi['DmiBIOSVersion'] = "string:" + VERSIONRE.search(buff).group(1)
    dmi['DmiBIOSReleaseDate'] = RELEASEDATERE.search(buff).group(1)

    buff = popen(DMI, '-t1').decode('ascii')
    dmi['DmiSystemVendor'] = MANUFRE.search(buff).group(1)
    dmi['DmiSystemProduct'] = PRODUCTRE.search(buff).group(1)
    dmi['DmiSystemVersion'] = 'string:' + VERSIONRE.search(buff).group(1)#*
    dmi['DmiSystemSerial'] = 'string:' + SERIALRE.search(buff).group(1)#*
    dmi['DmiSystemSKU'] = SKURE.search(buff).group(1)#*
    dmi['DmiSystemFamily'] = FAMILYRE.search(buff).group(1)#*
    dmi['DmiSystemUuid'] = UUIDRE.search(buff).group(1)#* empty on mine PC

    buff = popen(DMI, '-t2').decode('ascii')
    dmi['DmiBoardVendor'] = MANUFRE.search(buff).group(1)
    dmi['DmiBoardProduct'] = PRODUCTRE.search(buff).group(1)
    dmi['DmiBoardVersion'] = 'Not Available'#*
    dmi['DmiBoardAssetTag'] = 'Not Specified'#*
    dmi['DmiBoardLocInChass'] = 'Not Specified'#*
    dmi['DmiBoardSerial'] = 'string:' + str(randint(1, 10**19))#*

    buff = popen(DMI, '-t3').decode('ascii')
    dmi['DmiChassisVendor'] = MANUFRE.search(buff).group(1)
    dmi['DmiChassisType'] = str(CHASSIS.index(TYPERE.search(buff).group(1)) + 1)
    dmi['DmiChassisVersion'] = 'Not Available'#*
    dmi['DmiChassisSerial'] = 'string:' + str(randint(1, 10**19))#*
    dmi['DmiChassisAssetTag'] = 'No Asset Information'#*

    buff = popen(DMI, '-t4').decode('ascii')
    dmi['DmiProcManufacturer'] = MANUFRE.search(buff).group(1)
    dmi['DmiProcVersion'] = 'string:' + VERSIONRE.search(buff).group(1)
    
    real = dict()
    for key, val in dmi.items():
        val = val.strip()
        if not(val is None or val == 'string:' or val == ''):
            real[key] = val
    return real


def main():
    for target in sys.argv[1:]:
        print("[!] Patching {} machine ...".format(target))
        dmi = getdmi()
        print("[!] Patching DMI ...")
        for key, value in dmi.items():
            print('[!] Patching {} with value {}'.format(key, value))
            popen(VBOXMANAGE, 'setextradata', target, 'VBoxInternal/Devices/pcbios/0/Config/' + key, value)
        print("[!] Patching ACPI ...")
        dsdt = getacpi()
        popen(VBOXMANAGE, 'setextradata', target, 'VBoxInternal/Devices/acpi/0/Config/CustomTable', dsdt)
        
        newmac = randomMAC()
        print("[!] Patching MAC with new value {}...".format(newmac))
        popen(VBOXMANAGE, 'modifyvm', target, '--macaddress1', newmac)
        print("[!] Patching HDD info ...")
        hd = gethd()
        for key, value in hd.items():
            popen(VBOXMANAGE, 'setextradata', target, 'VBoxInternal/Devices/ahci/0/Config/Port0/' + key, value)
        print("[!] Patching CD info ...")
        cd = getcd()
        for key, value in cd.items():
            popen(VBOXMANAGE, 'setextradata', target, 'VBoxInternal/Devices/piix3ide/0/Config/PrimaryMaster/' + key, value)
        print("[!] Patching OEM info ...")            
        popen(VBOXMANAGE, 'setextradata', target, 'VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxVer', '<EMPTY>')
        popen(VBOXMANAGE, 'setextradata', target, 'VBoxInternal/Devices/pcbios/0/Config/DmiOEMVBoxRev', '<EMPTY>')
        print("[!] Generating regmod script ...")
        genbat()
        print("[+] Succesfully done patching on {}".format(target))
        
  

if __name__ == '__main__':
    if not len(sys.argv) > 1:
        print("%usage: camouflage.py <virtualmachine_name> [<..more_names..>]")
        sys.exit(1)
    main()
    

