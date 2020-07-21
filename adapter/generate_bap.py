import ConfigParser
import os
import sys

def trans(orig):
    results = open(orig,'r').readlines()
    target = orig[:-4]
    cf = ConfigParser.ConfigParser()
    cf.add_section('INSTRUCTION')
    cf.add_section('FUNCTION')
    insts = []
    func = []
    for r in results:
        if "inst" in r:
            inst = int(r.split(':')[1].strip())
            insts.append(inst)
        if "function" in r and "block" not in r and "Signature" not in r:
            func.append(int(r.split(':')[1].strip()))
    cf.set("INSTRUCTION","INST",insts)
    cf.set("FUNCTION","START",func)
    cf.write(open(target, "w"))

def trans_bap(orig):
    f = open(orig,'r')
    results = f.readlines()
    f.close()
    target = orig+'_truth'
    cf = ConfigParser.ConfigParser()
    cf.add_section('INSTRUCTION')
    cf.add_section('FUNCTION')
    cf.add_section('CFG')
    cf.add_section('CG')
    funcs = []
    func_info = {}
    insts = []
    cfg_nodes = []
    cfg_edges = []
    cg_edges = []
    #read the insts
    for r in results:
        if len(r) > 30 and len(r.split(" "))>20:
            tmp_split = r.split(":")[1].strip().split(" ")
            inst_str = tmp_split[0]+tmp_split[1]+tmp_split[2]+tmp_split[3]
            insts.append(str(int(r.split(" ")[0][:-1],16))+":"+str(len(inst_str.strip())/2))
    cf.set("INSTRUCTION","INST",insts)
    #read the funcs and cfgs

    f = open(orig+'_cfg')
    lines = f.readlines()
    f.close()
    for line in lines:
        if "label" in line:
            funcname = line[line.find("label")+7:-1].split('--')[0]
            func_start = int(line[line.find("label")+7:-1].split('--')[1][:-2],16)
            func_info[funcname] = func_start
            funcs.append(func_start)
        if "graph" not in line and "label" not in line and "->" not in line and ";" in line:
            node_addr = int(line.strip()[1:-2],16)
            cfg_nodes.append(node_addr)
        if "->" in line:
            parent = line.strip().split('->')[0].strip()[1:-1]
            child = line.strip().split('->')[1].strip()[1:-2]
            cfg_edges.append(str(int(parent,16))+'->'+str(int(child,16)))
    cf.set("FUNCTION","START",funcs)
    cf.set("CFG","NODE",cfg_nodes)
    cf.set("CFG","EDGE",cfg_edges)

    f = open(orig+"_cg")
    lines = f.readlines()
    f.close()
    for line in lines:
        if "->" in line:
            parent_func_name = line.split("->")[0].strip()[2:-1]
            child_func_name = line.split("->")[1].strip()[2:-1]
            if parent_func_name not in func_info.keys() or child_func_name not in func_info.keys():
                continue
            cg_edges.append(str(func_info[parent_func_name])+'->'+str(func_info[child_func_name]))
    cf.set("CG","EDGE",cg_edges)

    cf.write(open(target, "w"))

if __name__ == "__main__":
    targets = []
    type = ["C","C++","C_thumb","C++_thumb"]
    dir = "/home/linux/arm_study/bin/gcc/"
    for t in type:
        #files = os.listdir("/home/linux/arm_study/bin/gcc/C++_thumb/")
        for f in os.listdir(dir+t):
            if f.endswith(".stripped"):
                #if os.path.isfile(dir+t+"/"+f+"_bap_truth"):
                #    continue
                targets.append(dir+t+"/"+f)
    print targets
    for f in targets:
        cmd1 = "bap -dasm "+f+" > "+f+"_bap"
        print cmd1
        #os.system(cmd1)
        cmd2 = "bap -drcfg "+f+" > "+f+"_bap_cfg"
        print cmd2
        #os.system(cmd2)
        cmd3 = "bap -dcallgraph "+f +" > "+f+"_bap_cg"
        print cmd3
        #os.system(cmd3)
        trans_bap(f+"_bap")
    #trans_bap(dir+"C/401.bzip2.O2.stripped_bap")
