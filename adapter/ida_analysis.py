import idaapi
import idautils
import idc
import os
import logging
from idc import *
from idaapi import *
import ConfigParser
import pickle

idc.auto_wait()


def get_insts():
    ### Nmemonics histogram
    insts = [] 
    mnemonics = dict()

    # For each of the segments
    for seg_ea in Segments():

        # For each of the defined elements
        for head in Heads(seg_ea, SegEnd(seg_ea)):

            # If it's an instruction
            if isCode(GetFlags(head)):
                insts.append(head)
                mnem = GetMnem(head)
                mnemonics[mnem] = mnemonics.get(mnem, 0)+1
    return insts


if __name__ == "__main__":
    print "In the ida analysis script"
    try:
        extern_start = idaapi.get_segm_by_name("extern").startEA
        extern_end = idaapi.get_segm_by_name("extern").endEA
    except:
        extern_start = -1
        extern_end = -1
    if len(idc.ARGV)<3:
        print "lack parameters, exit"
        exit(0)
    print "number of arguments %d"%len(idc.ARGV)
    suffix = idc.ARGV[1]
    bin_path = idc.ARGV[2]

    arm_codes = []
    thumb_codes = []
    all_insts = {}

    result = {}
    result["instruction"] = {}
    result["function"] = {}

    insts = get_insts()
    for inst in insts:
        if inst >= extern_start and inst <= extern_end:
            continue
        if GetReg(inst,'T') == 1:
            thumb_codes.append(inst)
        if GetReg(inst,'T') == 0:
            arm_codes.append(inst)
        all_insts[inst] = {}
        all_insts[inst]["disasm"] = GetDisasm(inst)
        all_insts[inst]["size"] = ItemSize(inst)
    result["instruction"]["detail"] = all_insts
    result["instruction"]["arm"] = arm_codes
    result["instruction"]["thumb"] = thumb_codes

    for fva in idautils.Functions():
        function = idaapi.get_func(fva)
        if function.startEA >= extern_start and function.startEA <= extern_start:
            continue
        if function.startEA in result["function"].keys():
            print "IDA generate duplicate function"
        result["function"][function.startEA] = {}
    pickle.dump(result,open(bin_path+suffix,'w'))
    qexit(0) 

