import os 
import shutil
import time
from Monitor3 import Monitor



class GhidraAdapter:
    def __init__(self,bin_path,ghidra_raw_suffix,ghidra_path,ghidra_project_path,ghidra_script_name):
        self.bin_path = bin_path
        self.ghidra_raw_suffix = ghidra_raw_suffix
        self.ghidra_path = ghidra_path 
        self.ghidra_project_path = ghidra_project_path
        self.ghidra_script_name = ghidra_script_name 

    def get_result(self):
        self.get_raw_result()
        if not os.path.isfile(self.bin_path+self.ghidra_raw_suffix):
            return None
        print "anaylsis the raw data of %s" % (self.bin_path+self.ghidra_raw_suffix)
        f = open(self.bin_path+self.ghidra_raw_suffix)
        result = {}
        result["instruction"] = {}
        result["function"] = {}
        all_insts = {}
        thumb_codes = []
        arm_codes = []
        lines = f.readlines()
        for l in lines:
            if "Function" in l:
                func_addr = int(l.strip().split("|")[0].split(":")[1],16)
                result["function"][func_addr] = {}
                continue
            if "Inst" in l:
                inst = int(l.split("|")[1].split(":")[1],16)
                thumb = l.split("|")[0].split(":")[1]
                if thumb =="1":
                    thumb_codes.append(inst)
                else:
                    arm_codes.append(inst)
                all_insts[inst] = {}
                all_insts[inst]["size"] = l.split("|")[2].split(":")[1]
                all_insts[inst]["disasm"] = l.split("|")[3][7:]
        result["instruction"]["arm"] = arm_codes
        result["instruction"]["thumb"] = thumb_codes
        result["instruction"]["detail"] = all_insts

        print "ghidra finish generates the result of %s"%self.bin_path
        return result


    def get_raw_result(self):
        if os.path.isfile(self.bin_path+self.ghidra_raw_suffix) and os.path.isfile(self.bin_path+self.ghidra_raw_suffix+".monitor3_cpu"):
            print "ghidra already analyzed %s"%self.bin_path
            return
        print "ghidra generate the raw result of %s"% self.bin_path
        self.ghidra_project_path = self.bin_path+".ghidra_project"
        if os.path.isdir(self.ghidra_project_path):
            os.system("rm -rf "+self.ghidra_project_path)
        os.mkdir(self.ghidra_project_path)
        
        #if os.path.isdir(os.path.join(self.ghidra_project_path, os.path.basename(self.bin_path)+".gpr")):
        #    shutil.rmtree(os.path.join(self.ghidra_project_path,os.path.basename(self.bin_path)+".gpr"))
        #if os.path.isfile(os.path.join(self.ghidra_project_path, os.path.basename(self.bin_path)+".rep")):
        #    os.remove(os.path.join(self.ghidra_project_path,os.path.basename(self.bin_path)+".rep"))
        cmd = self.ghidra_path + "  "+ self.ghidra_project_path +"  "+os.path.basename(self.bin_path) +" -import  "+self.bin_path + " -scriptPath "+os.path.dirname(self.ghidra_script_name) + " -postScript  "+os.path.basename(self.ghidra_script_name)+ "  "+self.ghidra_raw_suffix+" -deleteProject"
        print cmd
        if os.path.isfile(self.bin_path+self.ghidra_raw_suffix+".monitor3_ts"):
            os.system("rm "+self.bin_path+self.ghidra_raw_suffix+".monitor3_ts")
        monitor = Monitor("java",self.bin_path,2*60*60,".ghidra_raw")
        monitor.start()
        os.system(cmd)
        monitor.join()

if __name__ == "__main__":
    ghidraadapter = GhidraAdapter("/path/to/binary",".ghidra_raw","/path/to/ghidra_9.0.4/support/analyzeHeadless","/path/to/ghidra_project/","/path/to/adapter/AnalysisARMTool.java")
    result = ghidraadapter.get_raw_result()
