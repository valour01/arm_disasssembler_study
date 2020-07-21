import thread
import pickle
import psutil
import time
import threading
import os

class Monitor(threading.Thread):
    def __init__(self,monitor_time, bin_path, tool_suffix):
        threading.Thread.__init__(self)
        self.monitor_time = monitor_time
        self.tool_suffix = tool_suffix
        self.bin_path = bin_path
        self.should_stop = False
        self.end_time = -1


    def get_process(self):
        return os.getpid()

    def get_all_cpu_time(self):
        return self.cpu_times[0]+self.cpu_times[1]+self.cpu_times[2]+self.cpu_times[3]


    def run(self):
        print "Thread get pid:%d"%os.getpid()
        print "Monitor start to monitor the %s"% self.bin_path
        start_time = time.time()
        result = {}
        resource = {}
        pid = self.get_process()
        p = psutil.Process(pid)
        self.cpu_times = p.cpu_times()
        init_cpu_time = self.get_all_cpu_time()
        while self.get_all_cpu_time() - init_cpu_time < self.monitor_time:
            try:
                mem = p.memory_percent()
                mem_info = p.memory_info()
                cpu = p.cpu_percent(interval = 1)
                self.cpu_times = p.cpu_times()
                print self.get_all_cpu_time() - init_cpu_time
                timestamp = time.time() - 0.5
                resource[timestamp] = {}
                resource[timestamp]["mem_percent"] = mem
                resource[timestamp]["cpu_percent"] = cpu
                resource[timestamp]["mem_info"] = mem_info
            except psutil.NoSuchProcess:
                break
            if self.should_stop == True:
                break
        if self.should_stop == True:
            complete = 1
        else:
            complete = 0
        result["resource"] = resource
        result["start"] = start_time
        result["end"] = self.end_time
        result["complete"] = complete
        result["cpu_times"] = self.get_all_cpu_time() - init_cpu_time
        pickle.dump(result,open(self.bin_path+self.tool_suffix+".monitor2_cpu","wb"))
        if complete == 0:
            p = psutil.Process(pid)
            for child in p.children():
                child.kill()
            p.kill()
