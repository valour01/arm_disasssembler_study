import angr
import sys
import time
from Monitor2 import Monitor
import json
from utils import ERRORF, INFOF, OKF

class __Autonomy__(object): 
    def __init__(self): 
        self._buff = "" 
    def write(self, out_stream): 
        self._buff += out_stream

class AngrAdapter():
    def __init__(self,bin_path):
        self.bin_path = bin_path


    def get_result(self):
        OKF("angr is to generate the result of %s." % self.bin_path)
        result = {}
        result["instruction"] = {}
        result["function"] = {}
        result["cfg"] = {}
        result["cg"] = {}
        p = angr.Project(self.bin_path, \
                main_opts={"backend": "elf"}, \
                load_options={"auto_load_libs": False})
        monitor = Monitor(2*60*60,self.bin_path,".angr")
        monitor.start()
        try:
            current = sys.stdout
            f = open("/dev/null", 'w')
            sys.stdout = f
            cfg = p.analyses.CFGFast(resolve_indirect_jumps = False)
            p.analyses.CompleteCallingConventions(recover_variables=True,cfg=cfg)
            sys.stdout = current
        except:
            ERRORF("angr analysis %s failed." % self.bin_path)
            result["crash"] = 1
            return result
        monitor.should_stop = True
        monitor.end_time = time.time()
        monitor.join()
        OKF("angr finish to generate the cfg of %s" % self.bin_path)
        INFOF(f"angr time consumed: {monitor.end_time-monitor.start_time}s")

        cg_edges = []
        cfg_nodes = []
        cfg_edges = []
        # get functions from cfg.kb
        for f in cfg.kb.functions:
            func = cfg.kb.functions[f]
            f_num = int(f)
            if f_num % 2 ==1:
                f_num = f_num -1
            # init a function dic
            if f_num not in result["function"].keys():
                result["function"][f_num] = {}
                arg_num = 0
                # extract the number of argument
                if func._cc:
                    # current = sys.stdout 
                    # tempout = __Autonomy__() 
                    # sys.stdout = tempout 
                    # print(func._cc)
                    # sys.stdout = current 
                    #print(tempout._buff)
                    args = repr(func._cc).split(": ")[1].split("->None")[0].split(",")
                    if "[]" in args:
                        arg_num = 0
                    else :
                        arg_num = len(args)
                    # print(args,arg_num)
                    # del tempout
                # record the funtion signature (argument, return)
                result["function"][f_num]["param"] = arg_num
                result["function"][f_num]["has_return"] = func.has_return 
                result["function"][f_num]["returning"] = func._returning
                INFOF(f"{self.bin_path}'s function at {hex(f_num)} param num: {arg_num}")
                INFOF(f"{self.bin_path}'s function at {hex(f_num)} has_return: {func.has_return }")
                INFOF(f"{self.bin_path}'s function at {hex(f_num)} returning: {func._returning}")
                
        # get call graph edges ?
        for e in cfg.kb.callgraph.edges:
            f_one = int(e[0])
            if f_one % 2 == 1:
                f_one = f_one - 1
            f_two = int(e[1])
            if f_two % 2 == 1:
                f_two = f_two - 1
            cg_edges.append(str(f_one)+'->'+str(f_two))
            # INFOF(f"{self.bin_path}'s call graph edges: {str(f_one)}->{str(f_two)}")
        result["cg"]["edge"] = cg_edges

        thumb_code = []
        arm_code = []
        all_insts = {}
        tmp_nodes = {}
        filters = []
        rm_nodes = []
        rm_edges = []
        add_edges = []

        for n in cfg.graph.nodes:
            if n.block!=None:
                n_num = int(n.block.addr)
                if n_num % 2 == 1:
                    n_num = n_num -1
                cfg_nodes.append(n_num)
                
                for succ in n.successors:
                    if succ.block != None:
                        n_succ = int(succ.block.addr)
                        if n_succ % 2 == 1:
                            n_succ = n_succ - 1
                        cfg_edges.append(str(n_num)+'->'+str(n_succ))
                        # INFOF(f"{self.bin_path}'s edges: {str(n_num)}->{str(n_succ)}")
                if n.block != None:  # dup of line-107 ?
                    c_block = n.block.capstone
                    if len(c_block.insns)>0:
                        last_inst = c_block.insns[-1]
                        if "bl" == last_inst.mnemonic or 'blx' == last_inst.mnemonic:
                            tmp_nodes[n.block.addr] = {}
                            tmp_nodes[n.block.addr]["node"] = n
                            tmp_nodes[n.block.addr]["next_addr"] = last_inst.address+last_inst.size
                            filters.append(last_inst.address+last_inst.size)
                    # get instructions
                    for i in c_block.insns:
                        all_insts[i.address] = {}
                        all_insts[i.address]["size"] = i.size
                        all_insts[i.address]["disasm"] = ("%s %s")%(i.mnemonic, i.op_str)
                    # thumb code or arm code ?
                    # for insn in n.block.instruction_addrs:
                    #     if insn % 2 == 1:
                    #         thumb_code.append(insn-1)
                    #     else:
                    #         arm_code.append(insn)
        index = len(tmp_nodes.keys())
        result["instruction"]["arm"] = arm_code
        result["instruction"]["thumb"] = thumb_code
        result["instruction"]["detail"] = all_insts
        OKF("angr finish to generate the result of %s" % self.bin_path)
        # print(result)

        return result  

if __name__ == "__main__":
    angradapter = AngrAdapter("/home/qinmdai/ARM_DIS_TOOLS/work/arm/470.lbm.O2.strip")
    
    result = angradapter.get_result()
