# color
red    = '\033[91m'
green  = '\033[92m'
yellow = '\033[93m'
blue   = '\033[94m'
reset  = '\033[0m'

global error_display 
global info_display
global ok_display

error_display = True
info_display = False
ok_display = True

def ERRORF(msg):
    if error_display:
        print("{}[-][ERROR]{} {}".format(red, reset, msg))

def INFOF(msg):
    if info_display:
        print("{}[+][INFO]{} {}".format(yellow, reset, msg))

def OKF(msg):
    if ok_display:
        print("{}[+][OK]{} {}".format(green, reset, msg))
