import r2pipe
import json
import os
import time

from elftools.elf.elffile import ELFFile
from Monitor2 import Monitor


class RadareAdapter:
    def __init__(self,bin_path):
        self.bin_path = bin_path
        self.thumb = 0

    def get_insts(self,vsize,vaddr):
        results = {}
        batch_size = 30000
        start_addr = vaddr
        while start_addr < vsize+vaddr:
            size = batch_size
            if vsize + vaddr - start_addr < batch_size:
                size = vsize +vaddr - start_addr
            disa_cmd = "pDj "+str(size)+" @"+str(start_addr)
            print disa_cmd
            inst_results = self.r.cmd(disa_cmd)
            insts = json.loads(inst_results)
            if size < batch_size:
                length = len(insts)
            else:
                length = len(insts) -1
            for i in range(length):
                inst = insts[i]
                inst_addr = inst["offset"]
                results[inst_addr] = {}
                results[inst_addr]["size"] = inst["size"]
                if "disasm" not in inst.keys():
                    if inst["type"] == "invalid":
                        results[inst_addr]["disasm"] = "invalid"
                else:
                    results[inst_addr]["disasm"] = inst["disasm"]
                start_addr = inst["offset"] + inst["size"]
        return results


    def get_result(self):
        print ("Radare get the result of %s"%self.bin_path)
        result = {}
        result["instruction"] = {}
        result["function"] = {}
        all_insts = {}
        self.r = r2pipe.open(self.bin_path)
        sections = self.r.cmd('iSj')
        with open(self.bin_path,"rb") as f:
            elf = ELFFile(f)
            entry = elf.header.e_entry
            if entry %2 == 1:
                self.thumb = 1

        if self.thumb == 1:
            print("IS thumb at entry")
            self.r.cmd('ahb 16')
            self.r.cmd('e asm.bits = 16')
        self.r.cmd('e anal.bb.maxsize = 1000000')
        monitor = Monitor(2*60*60,self.bin_path,".radare_aa")
        monitor.start()
        self.r.cmd('aaa')
        monitor.should_stop = True
        monitor.end_time = time.time() 
        monitor.join()
        print ("finish the init analysis of %s"%self.bin_path)
        
        try:
            for s in json.loads(sections):
                if 'x' in s['perm']:
                    vaddr = s['vaddr']
                    vsize = s['vsize']
                    results = self.get_insts(vsize,vaddr)
                    all_insts.update(results)
        except:
            os.system("echo 1>"+self.bin_path+".radare_aa.error")
            return None

   
        func_result = self.r.cmd('afl')
        for i in func_result.split("\n"):
            addr =  i.split(" ")[0]
            if addr.startswith("0x"):
                addr = int(addr,16)
                result["function"][addr] = {}
                

        result["instruction"]["detail"] = all_insts

        self.r.quit()
        print ("Radare finish the result of %s"%self.bin_path)
        return result


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


def get_va_size(section):
    result = []
    for attr in section.strip().split(" "):
        if attr != "":
            result.append(attr)
    return result[3],result[2]

if __name__ == "__main__":
    radareadapter = RadareAdapter("/path/to/binary")
    result = radareadapter.get_result()



