import angr
import sys
from Monitor2 import Monitor


class AngrAdapter():
    def __init__(self,bin_path):
        self.bin_path = bin_path


    def get_result(self):
        print ("angr is to generate the result of %s"%self.bin_path)
        result = {}
        result["instruction"] = {}
        result["function"] = {}
        p = angr.Project(self.bin_path)
        monitor = Monitor(2*60*60,self.bin_path,".angr")
        monitor.start()
        try:
            cfg = p.analyses.CFGFast(resolve_indirect_jumps = False)
        except:
            result["crash"] = 1
            return result
        monitor.should_stop = True
        monitor.end_time = time.time()
        monitor.join()
        for f in cfg.kb.functions:
            f_num = int(f)
            if f_num % 2 ==1:
                f_num = f_num -1
            if f_num not in result["function"].keys():
                result["function"][f_num] = {}


        thumb_code = []
        arm_code = []
        all_insts = {}
        for n in cfg.graph.nodes:
            if n.block!=None:
                c_block = n.block.capstone
                for i in c_block.insns:
                    all_insts[i.address] = {}
                    all_insts[i.address]["size"] = i.size
                    all_insts[i.address]["disasm"] = ("%s %s")%(i.mnemonic, i.op_str)
                for insn in n.block.instruction_addrs:
                    if insn % 2 == 1:
                        thumb_code.append(insn-1)
                    else:
                        arm_code.append(insn)
        index = len(tmp_nodes.keys())
 
                                      
        result["instruction"]["arm"] = arm_code
        result["instruction"]["thumb"] = thumb_code
        result["instruction"]["detail"] = all_insts
        print ("angr finish to generate the result of %s"%self.bin_path)
        return result

if __name__ == "__main__":
    angradapter = AngrAdapter("/path/to/binary")
    result = angradapter.get_result()
