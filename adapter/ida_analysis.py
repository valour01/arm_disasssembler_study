import idaapi
import idautils
import os
import idc
import logging
from idc import *
from idaapi import *
import configparser
import pickle

idc.auto_wait()


def get_insts():
    ### Nmemonics histogram
    insts = [] 
    mnemonics = dict()

    # For each of the segments
    for seg_ea in Segments():

        # For each of the defined elements
        for head in Heads(seg_ea, idc.get_segm_end(seg_ea)):

            # If it's an instruction
            if idc.is_code(get_full_flags(head)):
                insts.append(head)
                mnem = print_insn_mnem(head)
                mnemonics[mnem] = mnemonics.get(mnem, 0)+1
    return insts

def print_all_bbs(fva):
    global f
    tif = tinfo_t()
    function = idaapi.get_func(fva)
    get_tinfo2(function.startEA, tif)
    funcdata = func_type_data_t()
    tif.get_func_details(funcdata)
    #return type
    tif.get_rettype()
    for i in xrange(funcdata.size()):
        f.write("Signature Func: %d Arg: %d; Name: %s; Type: %s;\n" % (function.startEA, i, funcdata[i].name,print_tinfo('', 0, 0, PRTYPE_1LINE, funcdata[i].type, '', ''),))
    flowchart = idaapi.FlowChart(function)
    f.write("function:%d\n"% function.startEA)
    for bb in flowchart:
        f.write("function:%d;block:%d\n"%(function.startEA,bb.startEA))
        for succ in bb.succs():
            f.write("block:%d;successor:%d\n"%(bb.startEA,succ.startEA))


def format_bb(bb):
    bbtype = {0: "fcb_normal", 1: "fcb_indjump", 2: "fcb_ret", 3: "fcb_cndret",
              4: "fcb_noret", 5: "fcb_enoret", 6: "fcb_extern", 7: "fcb_error"}
    return("ID: %d, Start: 0x%x, End: 0x%x, Last instruction: 0x%x, Size: %d, "
           "Type: %s\n" % (bb.id, bb.startEA, bb.endEA, idc.PrevHead(bb.endEA),
                         (bb.endEA - bb.startEA), bbtype[bb.type]))

def generate_cg(path):
    print ("generate the cg to %s"%path)
    idc.GenCallGdl(path, 'Call Gdl', idc.CHART_GEN_GDL)


if __name__ == "__main__":
    print ("In the ida analysis script")
    try:
        extern_start = idaapi.get_segm_by_name("extern").startEA
        extern_end = idaapi.get_segm_by_name("extern").endEA
    except:
        extern_start = -1
        extern_end = -1
    if len(idc.ARGV)<4:
        print ("lack parameters, exit")
        exit(0)
    print ("number of arguments %d"%len(idc.ARGV))
    suffix = idc.ARGV[1]
    cg_suffix = idc.ARGV[2]
    bin_path = idc.ARGV[3]

    arm_codes = []
    thumb_codes = []
    cfg_nodes = []
    cfg_edges = []
    funcs = []
    all_insts = {}
    cg_edges = []
    func_name = {}

    result = {}
    result["instruction"] = {}
    result["function"] = {}
    result["cfg"] = {}
    result["cg"] = {}

    insts = get_insts()
    for inst in insts:
        if inst >= extern_start and inst <= extern_end:
            continue
        if get_sreg(inst,84) == 1:
            thumb_codes.append(inst)
        if get_sreg(inst,84) == 0:
            arm_codes.append(inst)
        all_insts[inst] = {}
        all_insts[inst]["disasm"] = GetDisasm(inst)
        all_insts[inst]["size"] = idc.get_item_size(inst)
    result["instruction"]["detail"] = all_insts
    result["instruction"]["arm"] = arm_codes
    result["instruction"]["thumb"] = thumb_codes

    for fva in idautils.Functions():
        tif = tinfo_t()
        function = idaapi.get_func(fva)
        if function.startEA >= extern_start and function.startEA <= extern_start:
            continue
        if function.startEA in result["function"].keys():
            print ("IDA generate duplicate function")
        result["function"][function.startEA] = {}
        function_name = GetFunctionName(function.startEA)
        func_name[function_name] = function.startEA
        funcs.append(function.startEA)

        get_tinfo2(function.startEA, tif)
        funcdata = func_type_data_t()
        tif.get_func_details(funcdata)
        #return type
        rettype = tif.get_rettype()
        parameters = []
        for i in xrange(funcdata.size()):
            parameters.append(print_tinfo('', 0, 0, PRTYPE_1LINE, funcdata[i].type, '', ''))
        #funcs_sig.append('func:'+str(function.startEA)+'; ret:'+str(rettype)+'; parameters:'+str(parameters))
        result["function"][function.startEA]["args_num"] = len(parameters)
        result["function"][function.startEA]["rettype"] = str(rettype)
        flowchart = idaapi.FlowChart(function)

        for bb in flowchart:
            cfg_nodes.append(bb.startEA)

            for succ in bb.succs():
                cfg_edges.append(str(bb.startEA)+'->'+str(succ.startEA))


    generate_cg(bin_path+cg_suffix)
    f = open(bin_path+cg_suffix,'r')
    lines = f.readlines()
    cg_nodes = {}
    for line in lines:
        if line.strip().startswith("node:"):
            node_title = line[line.find("title")+6:line.find("label")].strip()
            node_label = line[line.find("label")+6:line.find("color")].strip()[1:-1]
            print ("node_title %s node_label %s" %(node_title,node_label))
            if node_label in func_name.keys():
                node_addr = func_name[node_label]
                cg_nodes[node_title] = node_addr
    for line in lines:
        if line.strip().startswith("edge:"):
            src_node = line[line.find("sourcename")+11:line.find("targetname")].strip()
            dst_node = line[line.find("targetname")+11:line.find("}")].strip()
            # print ("src_node %s dst_node %s" %(src_node,dst_node)
            if src_node in cg_nodes and dst_node in cg_nodes:
                cg_edges.append(str(cg_nodes[src_node])+'->'+str(cg_nodes[dst_node]))
    result["cfg"]["edge"] = cfg_edges
    result["cfg"]["node"] = cfg_nodes
    result["cg"]["edge"] = cg_edges
    pickle.dump(result,open(bin_path+suffix,'w'))
    qexit(0) 

