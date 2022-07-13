import r2pipe
import json
import os
import time

from elftools.elf.elffile import ELFFile
from Monitor2 import Monitor
from utils import *

info_display = False

class RadareAdapter:
    # def __init__(self,bin_path,thumb):
    def __init__(self,bin_path):
        self.bin_path = bin_path
        self.thumb = 0

    def get_result(self):
        OKF("Radare get the result of %s"%self.bin_path)
        result = {}
        result["instruction"] = {}
        result["function"] = {}
        result["cfg"] = {}
        result["cg"] = {}
        all_insts = {}
        r = r2pipe.open(self.bin_path)
        sections = r.cmd('iSj')
        if self.thumb == 1:
            r.cmd('ahb 16')
            r.cmd('e asm.bits = 16')
        r.cmd('e anal.bb.maxsize = 1000000')
        monitor = Monitor("radare2", self.bin_path, 2*60*60, ".radare_aaaa2")
        # monitor = Monitor(2*60*60,  self.bin_path,  ".radare_aaa")
        monitor.start()
        r.cmd('aaaa')
        monitor.should_stop = True
        monitor.end_time = time.time() 
        monitor.join()
        OKF("finish the init analysis of %s" % self.bin_path)

        return 1
        
        for s in json.loads(sections):
            if 'x' in s['perm']:
                vaddr = s['vaddr']
                vsize = s['vsize']
                inst_result=r.cmd("pDj " +str(vsize)+" @" +str(vaddr))
                insts = json.loads(inst_result)
                for inst in insts:
                    inst_addr = inst["offset"]
                    all_insts[inst_addr] = {}
                    all_insts[inst_addr]["size"] = inst["size"]
                    if "disasm" not in inst.keys():
                        if inst["type"] == "invalid":
                            all_insts[inst_addr]["disasm"] = "invalid"
                    else:
                        all_insts[inst_addr]["disasm"] = inst["disasm"]
                    # print(f"instruction at {hex(inst_addr)}, size: {inst['size']}, disasm: {all_insts[inst_addr]['disasm']}")

        func_details = {}
        cfg_nodes = []
        cfg_edges = []
        func_result = r.cmd('afl')
        for i in func_result.split("\n"):
            addr =  i.split(" ")[0]
            if addr.startswith("0x"):
                addr = int(addr,16)
                result["function"][addr] = {}
                func_info = r.cmd('afi @'+str(addr))
                # print(func_info)
                result["function"][addr]["arg_num"] = get_arg_num(func_info,addr)
                size, bits = get_length_mode(func_info,addr)
                result["function"][addr]["size"] = size
                result["function"][addr]["bits"] = bits
                INFOF(f'function at {hex(addr)}, arg_num: {result["function"][addr]["arg_num"]}, size: {size}, bits: {bits}')
                func_cfg = r.cmd('agfj @'+str(addr))
                edges,nodes = get_cfg(func_cfg)
                cfg_edges = cfg_edges + edges
                cfg_nodes = cfg_nodes + nodes
        result["cfg"]["node"] = cfg_nodes
        result["cfg"]["edge"] = cfg_edges

        cg_result = r.cmd('agCd')
        cg = analysis_cg(cg_result)
        result["cg"]["edge"] = cg
        result["instruction"]["detail"] = all_insts

        r.quit()
        OKF("Radare finish the result of %s"%self.bin_path)
        return result

def analysis_inst(result):
    inst = []
    all = json.loads(result)
    for i in range(len(all)):
        inst.append(all[i]["offset"])
    return inst

def analysis_func(result):
    func = []
    return func

def get_arg_num(result,offset):
    current_offset = -1
    for l in result.split("\n"):
        if l.startswith("offset"):
            current_offset =int(l.split(":")[-1].strip(),16)
        if current_offset == offset:
            if  l.startswith("args"):
                return l.split(":")[1].strip()
    return -1

def get_length_mode(result,offset):
    current_offset = -1
    size = -1
    bits = -1
    for l in result.split("\n"):
        if l.startswith("offset"):
            current_offset =int(l.split(":")[-1].strip(),16)
        if current_offset == offset:
            if  l.startswith("size"):
                size = l.split(":")[1].strip()
            if l.startswith("bits"):
                bits = l.split(":")[1].strip()
    return size, bits

def get_cfg(result):
    edges= []
    nodes = []
    raw_json = json.loads(result)
    if len(raw_json) == 0:
        return edges,nodes
    cfg_json = raw_json[0]
    for b in cfg_json["blocks"]:
        nodes.append(b["offset"])
        if "jump" in b.keys():
            edges.append(str(b["offset"])+'->'+str(b["jump"]))
        if "fail" in b.keys():
            edges.append(str(b["offset"])+"->"+str(b["fail"]))
    return edges,nodes

def analysis_cg(result):
    cg= []
    for l in result.split("\n"):
        if "->" in l:
            caller = int(l.split("->")[0].strip()[1:-1],16)
            callee = int(l.split("->")[1].strip().split(" ")[0].strip()[1:-1],16)
            cg.append(str(caller)+"->"+str(callee))
    return cg


def get_va_size(section):
    result = []
    for attr in section.strip().split(" "):
        if attr != "":
            result.append(attr)
    return result[3],result[2]



if __name__ == "__main__":
    radareadapter = RadareAdapter("/path/to/binary")
    result = radareadapter.get_result()
    
    # print(result)

