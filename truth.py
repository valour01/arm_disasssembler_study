import sys
import pickle
import gc
import os
import commands
import elftools
import getopt
import logging
import ConfigParser
from elftools.elf.elffile import ELFFile
from multiprocessing import Pool
from capstone import *
from capstone.arm import *

logging.basicConfig(filename='tmp.log', level=logging.INFO)


class Binary:
    def __init__(self,path,disassembler):
        self.disassembler = disassembler
        self.path = path
        self.code_indexes = []
        self.arm_code_bound = []
        self.arm_codes = []
        self.thumb_code_bound = []
        self.thumb_codes = []
        self.data = []
        self.sections = {}
        self.start_addr = None
        self.end_addr = None
        self.insts = None
        self.subprograms = []
        self.func_starts = []
        self.cs_insts = []
        self.generate_truth()


    def get_func_by_addr(self,addr):
        for f in self.subprograms:
            if f.low_pc == addr:
                return f
        return None


    def get_bb_by_addr(self,addr):
        for f in self.subprograms:
            for bb in f.bbs:
                if bb.insts[0] == addr:
                    return bb
        return None



    def edge_num(self):
        num = 0
        for subprogram in self.subprograms:
            for bb in subprogram.bbs:
                num+=len(bb.jump_targets)
                num+=len(bb.callee)
        return num


    def block_num(self):
        return sum([ len(subprogram.bbs) for subprogram in self.subprograms ])


    def generate_truth(self):
        """
        Analysis the binary and evaluate the tools
        """
        #print ("read the sections")
        self.read_sections()
        #print ("read the symbols")
        self.read_symbols()
        #print ("start core analysis")
        self.get_instructions()
        #print ("get subprograms")
        self.get_subprograms()
        self.get_other_subprograms()
        #self.dump()



    def get_truth(self):
        print "TruthGenerator is to get the ground truth of %s"%self.path
        result = {}
        result["instruction"] = {}
        result["function"] = {}
        all_insts = {}
        for i in self.cs_insts:
            all_insts[i.address] = {}
            all_insts[i.address]["size"] = i.size
            all_insts[i.address]["id"] = i.id
            all_insts[i.address]["mnemonic"] = i.mnemonic
            all_insts[i.address]["op_str"] = i.op_str
            
        result["instruction"]["arm"] = self.arm_codes
        result["instruction"]["thumb"] = self.thumb_codes
        result["instruction"]["data"] = self.data
        result["instruction"]["detail"] = all_insts
        for f in self.subprograms:
            result["function"][f.low_pc] = {}
            result["function"][f.low_pc]["high_pc"] = f.high_pc
        return result


    def read_symbols(self):
        """
        Get the ARM mapping symbols
        """
        cmd = "readelf -s "+self.path
        print cmd
        status, output = commands.getstatusoutput(cmd)
        for line in output.split('\n'):
            if "$a" in line:
                sec_index = int(line.strip().split(' ')[-2])
                if sec_index not in self.code_indexes:
                    continue
                self.arm_code_bound.append(int(line.strip().split(' ')[1],16))
            if "$d" in line:
                sec_index = int(line.strip().split(' ')[-2])
                if sec_index not in self.code_indexes:
                    continue
                self.data.append(int(line.strip().split(' ')[1],16))
            if "$t" in line:
                sec_index = int(line.strip().split(' ')[-2])
                if sec_index not in self.code_indexes:
                    continue
                self.thumb_code_bound.append(int(line.strip().split(' ')[1],16))
        self.mappings = sorted(self.arm_code_bound + self.thumb_code_bound + self.data)

    def get_mode(self,addr):
        """
        Check whether the code is thumb or arm
        """
        for i in range(len(self.mappings)-1):
            if self.mappings[i] <= addr and self.mappings[i+1] >addr:
                if self.mappings[i] in self.arm_code_bound:
                    return 0
                if self.mappings[i] in self.thumb_code_bound:
                    return 1
                if self.mappings[i] in self.data:
                    return 2


    def get_other_subprograms(self):
        cmd = "readelf -s "+self.path
        status, output = commands.getstatusoutput(cmd)
        for line in output.split('\n'):
            if "FUNC" in line:
                tmp_split = line.strip().split(' ')
                line_split = []
                for t in tmp_split:
                    if t != "":
                        line_split.append(t)
                lowpc = int(line_split[1],16)

                if line_split[2].startswith("0x"):
                    size = int(line_split[2],16)
                else:
                    size = int(line_split[2])
                
                highpc = lowpc + size
 
                subprogram = Function("",lowpc,highpc,"","","","",self)
                self.subprograms.append(subprogram)
                self.func_starts.append(subprogram.low_pc)




    def get_subprograms(self):
        """
        Generate the subprograms according to the dwarf info debugging information
        """
        f = open(self.path,'rb')
        elffile = ELFFile(f)
        dwarfinfo = elffile.get_dwarf_info()
        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag == "DW_TAG_subprogram":
                    if "DW_AT_low_pc" in DIE.attributes.keys()  and "DW_AT_high_pc" in DIE.attributes.keys() and ("DW_AT_name" in DIE.attributes.keys() or "DW_AT_specification" in DIE.attributes.keys()):
                        ret = 0
                        lowpc = DIE.attributes["DW_AT_low_pc"].value 
                        highpc = DIE.attributes["DW_AT_high_pc"].value 
                        if DIE.attributes["DW_AT_high_pc"].form == "DW_FORM_data4":
                            highpc = lowpc +highpc
                        name = ""
                        ret = 0
                        num_args = 0
                        subprogram = Function(name,lowpc,highpc,"","",ret,num_args,self)
                    
                        self.subprograms.append(subprogram)
                        self.func_starts.append(subprogram.low_pc)



    def get_instructions(self):
        """
        Get the binary instructions according to the mapping symbols information
        """
        for i in range(len(self.mappings)-1):
            for sec in self.sections.keys():
                if self.mappings[i] >= self.sections[sec]["start_addr"]:
                    end_bound = min(self.mappings[i+1],self.sections[sec]["end_addr"])
                    if self.mappings[i] in self.arm_code_bound:
                        #print "ARM: 0x%x to 0x%x" % (self.insts[i],self.insts[i+1])
                        target_text = self.sections[sec]["content"][self.mappings[i]-self.sections[sec]["start_addr"]:end_bound-self.sections[sec]["start_addr"]]
                        cs_insts = self.disassembler.disasm_arm_inst(target_text,self.mappings[i])
                        for cs_inst in cs_insts:
                            self.arm_codes.append(cs_inst.address)
                        self.cs_insts = self.cs_insts + cs_insts
                    if self.mappings[i] in self.thumb_code_bound:
                        target_text = self.sections[sec]["content"][self.mappings[i]-self.sections[sec]["start_addr"]:end_bound-self.sections[sec]["start_addr"]]
                        #target_text = self.text[self.mappings[i]-self.start_addr:self.mappings[i+1]-self.start_addr]
                        cs_insts = self.disassembler.disasm_thumb_inst(target_text,self.mappings[i])
                        for cs_inst in cs_insts:
                            self.thumb_codes.append(cs_inst.address)
                        self.cs_insts = self.cs_insts + cs_insts
                    if self.mappings[i] in self.data:
                        pass
                    #print "DATA: 0x%x to 0x%x" % (self.insts[i],self.insts[i+1])



    def read_sections(self):
        """
        Get the ARM binary's ELF information and where the text section is
        """
        cmd = "readelf -S "+self.path
        status, output = commands.getstatusoutput(cmd)

        for line in output.split('\n'):
            text_info = line.strip()[4:].split(' ')
            new_info = []
            for info in text_info:
                if info != '':
                    new_info.append(info)
            if len(new_info) <7:
                continue
            mode = new_info[6]
            if "X" in mode:
                addr = int(new_info[2],16)
                off = int(new_info[3],16)
                size = int(new_info[4],16)
                index = int(line.strip()[1:3])
                self.code_indexes.append(index)
                f = open(self.path,'r')
                f.read(off)
                sec_name = new_info[0]
                self.sections[sec_name] = {}
                self.sections[sec_name]["content"] = f.read(size)
                self.sections[sec_name]["start_addr"] = addr
                self.sections[sec_name]["end_addr"] = addr + size
                self.sections[sec_name]["index"] = index
                self.sections[sec_name]["size"] =  size

class Function:
    def __init__(self,name,low_pc,high_pc,file,line,rettype,param,binary):
        """
        Function represents a subprogram
        """
        self.name = name
        self.low_pc = low_pc
        self.high_pc = high_pc
        self.file = file
        self.line = line
        self.rettype = rettype
        self.param = param
        self.binary = binary
        self.insts = []
        self.bbs = []
        self.ir_bbs =[]
        self.edges = []
        self.ir_edges = []



class Disassembler:
    def __init__(self):
        """
        This is the disassembler that use capstone to help us to disassmble
        """
        self.md_arm = Cs(CS_ARCH_ARM,CS_MODE_ARM)
        self.md_arm.detail = True
        self.md_thumb = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
        self.md_thumb.detail = True


    def disasm_arm_inst(self,text,start_addr):
        cs_insts = []
        for insn in self.md_arm.disasm(text,start_addr):
            cs_insts.append(insn)
        return cs_insts

    def disasm_thumb_inst(self,text,start_addr):
        cs_insts = []
        for insn in self.md_thumb.disasm(text,start_addr):
            cs_insts.append(insn)
        return cs_insts

if __name__ == "__main__":
    truth = Binary("/path/to/binary",Disassembler())
