import subprocess
import os
from Monitor import Monitor
from utils import *

class ObjdumpAdapter:
    def __init__(self,bin_path):
        self.bin_path = bin_path
        self.monitor_time = 2*60*60

    def get_result(self):
        result = {}
        all_insts = {}
        cmd = "arm-linux-gnueabi-objdump -d " + self.bin_path + " > " + self.bin_path + ".raw" 
        monitor = Monitor("arm-linux-gnueabi-objdump", self.bin_path, self.monitor_time, ".objdump")
        monitor.start()   
        OKF(f"Objdump CMD: {cmd}")     
        OKF("Objdump get the result of  %s" % self.bin_path)
        os.system(cmd)
        monitor.join()
        OKF("Objdump finish the result of %s" % self.bin_path)
        result["instruction"] = {}
        f = open(self.bin_path+".raw","r")
        lines = f.readlines()
        f.close()
        for l in lines:
            l_split = l.split("\t")
            if len(l_split) < 4:
                continue
            if l_split[0].endswith(":") and ".word" not in l:
                insn = int(l_split[0].strip()[:-1],16)
                size = len(l_split[1].strip())/2
                disasm  = " ".join(l_split[2:])
                all_insts[insn] = {}
                all_insts[insn]["size"] = size
                all_insts[insn]["disasm"] = disasm
                INFOF(f"instruction at {hex(insn)}, size: {size}, disasm: {disasm}")
        result["instruction"]["detail"] = all_insts
        return result


if __name__ == "__main__":
    objdump = ObjdumpAdapter("/path/to/binary")
    r = objdump.get_result()
