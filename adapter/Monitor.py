import thread
import pickle
import psutil
import time
import threading
import os

class Monitor(threading.Thread):
    def __init__(self,tool_name, bin_path, monitor_time, tool_suffix):
        threading.Thread.__init__(self)
        self.tool_name = tool_name
        self.bin_path = bin_path
        self.monitor_time = monitor_time
        self.tool_suffix = tool_suffix

    def get_process(self):
        for p in psutil.process_iter(attrs=["cmdline","name"]):
            if self.bin_path in str(p.info["cmdline"]):
                if self.tool_name == p.info["name"]:
                    return p.pid
        return None

    def get_all_cpu_time(self):
        return self.cpu_times[0]+self.cpu_times[1]+self.cpu_times[2]+self.cpu_times[3]

    def run(self):
        print "Monitor start to monitor the %s"% self.bin_path
        start_time = time.time()
        result = {}
        resource = {}
        while time.time() - start_time < 20:
            pid = self.get_process()
            if pid != None:
                break
            else:
                print "cannot find the process for %s"% self.bin_path
                time.sleep(1)
        if pid == None:
            print "cannot locate the pid in 120 seconds for %s"%self.bin_path
            result["error"] = 1
            pickle.dump(result,open(self.bin_path+self.tool_suffix+".monitor1_cpu","wb"))
            return         
        end_time = -1
        print "Locate the pid %d"%pid
        p = psutil.Process(pid)
        self.cpu_times = [0,0,0,0]
        while self.get_all_cpu_time() < self.monitor_time:
            try:
                mem = p.memory_percent()
                mem_info = p.memory_info()
                cpu = p.cpu_percent(interval = 1)
                timestamp = time.time() - 0.5
                self.cpu_times = p.cpu_times()
                print self.get_all_cpu_time()
                resource[timestamp] = {}
                resource[timestamp]["mem_percent"] = mem
                resource[timestamp]["cpu_percent"] = cpu
                resource[timestamp]["mem_info"] = mem_info
            except psutil.NoSuchProcess:
                end_time = time.time()
                break
        if psutil.pid_exists(pid):
            psutil.Process(pid).kill()
            complete = 0
        else:
            complete = 1
        result["resource"] = resource
        result["start"] = start_time
        result["end"] = end_time
        result["complete"] = complete
        result["cpu_times"] = self.cpu_times
        pickle.dump(result,open(self.bin_path+self.tool_suffix+".monitor1_cpu","wb"))
