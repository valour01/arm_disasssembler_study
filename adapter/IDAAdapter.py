import os 


class IDAAdapter:
    def __init__(self, bin_path, ida_suffix,ida_path,ida_script_path):
        self.bin_path = bin_path
        self.ida_path = ida_path
        self.ida_suffix = ida_suffix
        self.ida_script_path = ida_script_path


    def get_result(self):
        print "IDA generate the result of %s"%self.bin_path
        cmd = self.ida_path + " -A -c -S\""+self.ida_script_path+"  "+self.ida_suffix+"  "+os.path.join(os.getcwd(),self.bin_path)+"\"  "+os.path.join(os.getcwd(),self.bin_path)
        os.system(cmd)
