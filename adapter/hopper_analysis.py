import os
import time
import pickle
result = {}
doc = Document.getCurrentDocument()
os.system("echo "+str(time.time())+" >"+doc.getExecutableFilePath()+".hopper.monitor3_ts")
seg_list = doc.getSegmentsList()

funcs = []
arm_codes = []
thumb_codes = []
all_insts = {}

result["instruction"] = {}
result["function"] = {}

for seg in seg_list:
    if True:
        start = seg.getStartingAddress()
        end = start + seg.getLength()
        addr = start 
        inst = None
        index = 0
        while addr < end:
            inst = None 
            index += 1
            if index %1000 ==0:
                print "addr: 0x%x %.2f finish %.4f"% (addr,time.time(),float(addr-start)/(end-start))
            type_address = seg.getTypeAtAddress(addr)
            if type_address == 66 or type_address == 65:
                all_insts[addr] = {}
                try:
                    inst = seg.getInstructionAtAddress(addr)
                except:
                    addr +=1
                    continue 
                inst_len = inst.getInstructionLength()
                all_insts[addr]["size"] = inst_len
                all_insts[addr]["disasm"] = inst.getInstructionString()
            if inst == None:
                addr += 1
            else:
                addr += inst_len
                    
    num_procedure = seg.getProcedureCount()
    for i in range(num_procedure):
        if i%100 == 0:
            print "function: finish %.3f"%(float(i)/num_procedure)
        procedure = seg.getProcedureAtIndex(i)
        result["function"][procedure.getEntryPoint()] = {}
        

result["instruction"]["arm"] = arm_codes
result["instruction"]["thumb"] = thumb_codes
result["instruction"]["detail"] = all_insts
pickle.dump(result,open(doc.getExecutableFilePath()+".hopper_test","w"))
exit(1)
