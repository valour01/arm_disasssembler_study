import sys   
import time
import os
from Monitor2 import Monitor


class NinjaAdapter():
    def __init__(self,bin_path,ninja_path):
        self.ninja_path = ninja_path
        self.bin_path = bin_path

    def get_result(self):
        print "MainL pid:",os.getpid()
        print "ninja path is %s" % self.ninja_path
        if self.ninja_path not in sys.path:
            sys.path.append(self.ninja_path)
        import binaryninja as binja
        print "Ninja get the result of %s"%self.bin_path
        monitor = Monitor(2*60*60,self.bin_path,".ninja")
        monitor.start()
        bv = binja.BinaryViewType.get_view_of_file(self.bin_path)    
        monitor.should_stop = True
        monitor.end_time = time.time()
        monitor.join()
        result = {}
        all_insts = {}
        
        result["instruction"] = {}
        result["function"] = {}
        index = 0

        for i in bv.instructions:
            index +=1
            if index % 1000 ==0:
                print "%s Dumped %d instructions"%(self.bin_path, index)
            all_insts[int(i[1])] = {}
            funcs = bv.get_functions_containing(i[1])
            if len(funcs) == 0:
                return 
            arch = funcs[0].arch
            all_insts[int(i[1])]["size"] = int(bv.get_instruction_length(i[1],arch))
            all_insts[int(i[1])]["disasm"] =  "  ".join('%s' % s for s in i[0])
        result["instruction"]["detail"] = all_insts

        for func in bv.functions:
            result["function"][int(func.start)] = {}

        print "Ninja finish the analysis of %s"%self.bin_path 
        return result

if __name__ =="__main__":
    ninjaadapter = NinjaAdapter("/path/to/binary","/path/to/binaryninja/python")
    result = ninjaadapter.get_result()
