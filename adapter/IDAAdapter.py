import os 


class IDAAdapter:
    def __init__(self, bin_path, ida_suffix,ida_path,ida_cg_suffix,ida_script_path):
        self.bin_path = bin_path
        self.ida_path = ida_path
        self.ida_cg_suffix = ida_cg_suffix
        self.ida_suffix = ida_suffix
        self.ida_script_path = ida_script_path


    def get_result(self):
        #/Applications/IDA\ Pro\ 7.0/ida.app/Contents/MacOS/ida -c -S"/Users/MuhuiJiang/Documents/Fredist/adapter/ida_analysis.py  .ida  .ida.gdl  /Users/MuhuiJiang/Documents/Fredist/result/C_thumb/458.sjeng.O2.strip"  result/C_thumb/458.sjeng.O2.strip
        print ("\n\nIDA generate the result of %s"%self.bin_path)
        cmd =   self.ida_path + " -c -S\""+\
                self.ida_script_path+"  "+\
                self.ida_suffix+"  "+\
                self.ida_cg_suffix+"  "+\
                os.path.join(os.getcwd(),self.bin_path)+"\"  "+\
                os.path.join(os.getcwd(),self.bin_path)
        print(cmd)
        os.system(cmd)


if __name__ == "__main__":
    idaadapter = IDAAdapter(\
            "/path/to/binary",\
            ".ida",\
            "/path/to/ida ",\
            ".ida.cg",\
            "/path/to/ida_analysis.py")
    result = idaadapter.get_result()

