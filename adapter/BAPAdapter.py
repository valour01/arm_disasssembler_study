import os
import pickle
from Monitor import Monitor
from utils import *

class BAPAdapter:
    def __init__(self,bin_path,disa_suffix, disa_cmd, suffix):
        self.bin_path = bin_path 
        self.disa_suffix = disa_suffix 
        self.disa_cmd = disa_cmd
        self.suffix = suffix

    def cg(self,cg_cmd):
        cmd = cg_cmd + "  " + self.bin_path +" >  "+self.bin_path+self.cg_suffix 
        print (cmd)
        os.system(cmd)

    def cfg(self,cfg_cmd):
        cmd = cfg_cmd + "  " + self.bin_path +" >  "+self.bin_path+self.cfg_suffix 
        print (cmd)
        os.system(cmd)

    def disa(self):
        cmd = self.disa_cmd + "  " + self.bin_path +" >  "+self.bin_path+self.disa_suffix 
        OKF(f"BAP CMD: {cmd}")
        os.system(cmd)

    def is_complete(self):
        r = pickle.load(open(self.bin_path+self.suffix+".monitor1_cpu","rb"))
        if "complete" in r.keys():
            if r["complete"] == 1:
                return True 
        return False        


    def get_result(self):
        result = {}
        if os.path.isfile(self.bin_path+".bap") and os.path.isfile(self.bin_path+".bap.monitor1_cpu"):
            pass
        else:
            monitor = Monitor("bap",self.bin_path,2*60*60,".bap")
            monitor.start()
            self.disa() 
            monitor.join()
            if not self.is_complete():
                result["imcomplete"] = 1
                ERRORF(f"BAP analysis failed.")
                return result            
        OKF("BAP get the result of %s" % self.bin_path)
        result["instruction"] = {}
        result["function"] = {}
        all_insts = {}
        inst_f = open(self.bin_path+self.disa_suffix,'r')
        inst_lines = inst_f.readlines()
        inst_f.close()
        for l in inst_lines:
            #print(l)
            if len(l) > 30 and len(l.split(" "))>20:
                addr = int(l.split(":")[0],16)
                all_insts[addr] = {}
                tmp_split = l.split(":")[1].strip().split(" ")
                if len(tmp_split) >= 4:
                    raw = tmp_split[0]+tmp_split[1]+tmp_split[2]+tmp_split[3]
                    size = len(raw.strip())/2
                    all_insts[addr]["size"] = size
                    all_insts[addr]["disasm"] = str(tmp_split[4:]).replace("'', ","")
                    INFOF(f"instruction size: {size}, disasm: {all_insts[addr]['disasm']}")
            if ": <" in l:
                func_start = int(l.split(":")[0],16)
                func_name = l.split(":")[1].strip()[1:-1]
                result["function"][func_start] = {} 
                INFOF(f"function start at: {hex(func_start)}")

        result["instruction"]["detail"] = all_insts
        pickle.dump(result,open(self.bin_path+".bap","wb"))
        #print(result["function"])
        return result

if __name__ == "__main__":
    bapadapter = BAPAdapter("/path/to/binary",".bap_disa","bap -dasm",".bap")
    result = bapadapter.get_result()
