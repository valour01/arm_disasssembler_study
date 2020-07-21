import os 
from Monitor3 import Monitor


class HopperAdapter:
    def __init__(self,bin_path,hopper_script_path,hopper_path):
        self.bin_path = bin_path
        self.hopper_script_path = hopper_script_path
        self.hopper_path = hopper_path


    def get_result(self):
        print "Hopper generates the result of %s"%self.bin_path
        if os.path.isfile(self.bin_path+".hopper.monitor3_ts"):
            print "ts file exists"
            os.system("rm "+self.bin_path+".hoppe.monitor3_ts")
        cmd = self.hopper_path+" -e "+self.bin_path+" -l ELF -Y  "+self.hopper_script_path
        monitor = Monitor(os.path.basename(self.hopper_path),self.bin_path,2*60*60,".hopper")
        monitor.start()
        os.system(cmd)
        monitor.join()


if __name__ == "__main__":
    hopperadapter = HopperAdapter("/path/to/binary","/path/to/adapter/hopper_analysis.py","/path/to/Hopper")
    hopperadapter.get_result()
