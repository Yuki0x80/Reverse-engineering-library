'''
Created on 2014/03/26

@author: saiyuki1919
'''
# -*- coding: utf-8 -*-
import binascii
import sys
import os.path
import pefile
import pydasm
from pydbg import *
from pydbg.defines import *
from ctypes import *
#from __future__ import print_function

import_list={}
export_list={}

######################################
#import_list key is PEB address
#          () first is address 
#          () second is winAPI 
######################################

def search_all_address(exe_path,assmble):
    find_assmble=[]
    pe=pefile.PE(exe_path)
    all_address_size=os.path.getsize(exe_path)
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()[ep:all_address_size]
    data_list=exchange_binary_data(data)
    data_size=len(data_list)
    offset = 0
    while offset < len(data):
        i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
        address_as=pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL,0)
        address = ep_ava+offset
        if assmble == address_as:
            find_assmble.append(address)
        if address_as is None:
            print "[*] 0x%08x : "%address,data_list[offset+1],"\t\t\t\t",address_as
            offset+=1
            data_size-=1
        else :
            if data_size-i.length == -1:
                break
            data_size-=i.length
            new_one=[data_list[count+offset] for count in range(1,i.length+1)]
            if i.length == 1:
                print "[*] 0x%08x : "%address,",".join(new_one),"\t\t\t\t",address_as
            elif i.length== 2:
                print "[*] 0x%08x : "%address,",".join(new_one),"\t\t\t",address_as
            elif i.length==3:
                print "[*] 0x%08x : "%address,",".join(new_one),"\t\t\t",address_as
            elif i.length==4:
                print "[*] 0x%08x : "%address,",".join(new_one),"\t\t\t",address_as
            elif i.length>=10:
                print "[*] 0x%08x : "%address,",".join(new_one),address_as
            else:
                print "[*] 0x%08x : "%address,",".join(new_one),"\t\t",address_as
            offset += i.length
    for count in range(0,len(find_assmble)):
        print "[*] %s"%assmble,"(address:0x%08x)"%find_assmble[count]
    if len(find_assmble) == 0:
        print "Noting"
        return None
    return find_assmble

def api_address(exe_path):
    global import_list
    global export_list
    im_list={}
    pe=pefile.PE(exe_path)
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size != 0:
        print "[*] IMAGE_DIRECTORY_ENTRY_EXPORT Size = %s bytes." % \
            hex(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size)
        #print "----- EXPORTS -----"
        for ex in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            #print "\t%s at 0x%08x" % (ex.name, ex.address)
            export_list[ex.address]=ex.name
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size != 0:
        print "[*] IMAGE_DIRECTORY_ENTRY_IMPORT Size = %s bytes." % \
            hex(pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size)
        #print "----- IMPORTS -----"
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            #print entry.dll
            for imp in entry.imports:
                #print "\t%s at 0x%08x" % (imp.name, imp.address)
                im_list[imp.address]=imp.name,entry.dll
                import_list[imp.address]=(dbg.func_resolve(im_list[imp.address][1],im_list[imp.address][0])
                                          ,im_list[imp.address])
                
#address is list
def search_address(exe_path,assmble,list_t,step):
    find_assmble=[]
    pe=pefile.PE(exe_path)
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
    all_address_size=os.path.getsize(exe_path)
    for add in range(0,len(list_t)):
        num=list_t[add]-pe.OPTIONAL_HEADER.ImageBase
        yu=num+step
        data = pe.get_memory_mapped_image()[num:yu]
        data_list=exchange_binary_data(data)
        data_size=len(data_list)
        offset = 0
        print"=================================================================================="
        while offset < len(data):
            i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
            address_as=pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, list_t[add]+offset)
            address = list_t[add]+offset
            #print "[*] 0x%08x : "%address,address_as
            if not address == all_address_size+ep_ava:
                if address_as is None:
                    print "[*] 0x%08x : "%address,data_list[offset+1],"\t\t\t\t",address_as
                    offset+=1
                else :
                    if data_size-i.length < i.length or data_size-offset-i.length <0:
                            break
                    new_one=[data_list[count+offset] for count in range(0,i.length)]
                    if i.length == 1:
                        print "[*] 0x%08x : "%address,",".join(new_one),"\t\t\t\t",address_as
                    elif i.length== 2:
                        print "[*] 0x%08x : "%address,",".join(new_one),"\t\t\t",address_as
                    elif i.length==3:
                        print "[*] 0x%08x : "%address,",".join(new_one),"\t\t\t",address_as
                    elif i.length==4:
                        print "[*] 0x%08x : "%address,",".join(new_one),"\t\t\t",address_as
                    elif i.length>=10:
                        print "[*] 0x%08x : "%address,",".join(new_one),address_as
                    else:
                        print "[*] 0x%08x : "%address,",".join(new_one),"\t\t",address_as
                    offset += i.length
                if assmble == address_as:
                    find_assmble.append(address)
            else:
                print "Address finished"
                break
        print"=================================================================================="
    for count in range(0,len(find_assmble)):
        print "[*] %s"%assmble,"(address:0x%08x)"%find_assmble[count]
    if len(find_assmble) == 0:
        print "Noting"
        return None
    print "\n"
    return find_assmble
       
def find_badapi_address(api_t):
    for y in import_list.keys():
        if import_list[y][1][0] == api_t:
            print "[*]Find 0x%08x :"%import_list[y][0],api_t
            return import_list[y][0]

def disassmble(buffer_t):
    offset = 0
    data_t=exchange_binary_data(str(buffer_t))
    data_size=len(data_t)
    print "============================================================================"
    while offset < len(buffer_t):
        i = pydasm.get_instruction(buffer_t[offset:], pydasm.MODE_32)
        dis_as=pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)
        if dis_as is None:
            print "[*] ",data_t[offset+1],"\t\t\t\t",dis_as
            offset+=1
        else:    
            if data_size-i.length < i.length or data_size-offset-i.length <0:
                            break
            new_one=[data_t[count+offset] for count in range(0,i.length)] 
            if i.length == 1:
                print "[*] ",",".join(new_one),"\t\t\t\t",dis_as
            elif i.length== 2:
                print "[*] ",",".join(new_one),"\t\t\t\t",dis_as
            elif i.length==3:
                print "[*] ",",".join(new_one),"\t\t\t\t",dis_as
            elif i.length==4:
                print "[*] ",",".join(new_one),"\t\t\t",dis_as
            elif i.length==5:
                print "[*] ",",".join(new_one),"\t\t\t",dis_as
            elif i.length==6:
                print  "[*] ",",".join(new_one),"\t\t\t",dis_as
            elif i.length>=10:
                print "[*] ",",".join(new_one),"\t",dis_as
            else:
                print "[*] ",",".join(new_one),"\t\t",dis_as
            offset += i.length
    print "============================================================================\n"
    
def binary_data(exe_path):
    f=open(exe_path,"rb")
    r=f.read()
    f=str(binascii.hexlify(r))
    counter=0
    before=0
    provisional_list=[]
    #list_t = [(i+j) for (i,j) in zip(f[::2],f[1::2])]
    print"================================================"
    for (i,j) in zip(f[::2],f[1::2]):
        provisional_list.append(i+j)
        counter+=1
        if (counter%15.0) == 0.0:
            back=counter/15
            val=0
            while val<15:
                sys.stdout.write(provisional_list[before:15*back][val])
                val+=1
            before=15*back
            print "\n"
            return 0
    print"\n=========================================\n"
    print "finish","byte:%d"%counter

def exchange_binary_data(data):
    provisional_list=[]
    counter=0
    binary=str(binascii.hexlify(data))
    for (i,j) in zip(binary[::2],binary[1::2]):
        provisional_list.append(i+j)
        counter+=1
    return provisional_list  
    
    
    
dbg=pydbg()
exe_path=""