from scapy.all import *

import argparse

parser = argparse.ArgumentParser(description='To input ip and ether addresses')

parser.add_argument('--interface', action='store')
parser.add_argument('--victim-ip', action='store')
parser.add_argument('--victim-ethernet', action='store')
parser.add_argument('--reflector-ip', action='store')
parser.add_argument('--reflector-ethernet', action='store')
results=parser.parse_args()

victimIP=results.victim_ip
print victimIP
victimEth =results.victim_ethernet
print victimEth
reflectorIP=results.reflector_ip
print reflectorIP
reflectorEth=results.reflector_ethernet
print reflectorEth

def refl():
	
	while True:
		#Part 1
		#-----------------------#
		#read any incoming packets to the victim ip
		f="dst("+victimIP+" or "+reflectorIP+")"
		print f
		f = str(f)
		print "----------SNIFFING PACKET 1----------------------------------------"
		arppkt = sniff(count=1, filter=f) #change to destination ip
	
		#display incoming packet
		arppkt[0].show()
		arppkt[0].command()
	
		if ARP in arppkt[0]==true:
			#prepare packet for reply - ARP
			arpsrc=arppkt[0][ARP].psrc
			arpdst=arppkt[0][ARP].pdst
			ethsrc=arppkt[0][Ether].src
			ethdst=arppkt[0][Ether].dst
			#manipulate the packet
			new_arppkt = eval(arppkt[0].command())
			new_arppkt[ARP].psrc=arpdst
			new_arppkt[ARP].pdst = arpsrc
			new_arppkt[Ether].src = ethdst
			new_arppkt[Ether].dst = ethsrc
		else:
			#prepare packet for reply - TCP/UDP
			arpsrc=arppkt[0][IP].src
			arpdst=arppkt[0][IP].dst
			ethsrc=arppkt[0][Ether].src
			ethdst=arppkt[0][Ether].dst
			#manipulate the packet
			new_arppkt = eval(arppkt[0].command())
			new_arppkt[IP].src=arpdst
			new_arppkt[IP].dst = arpsrc
			new_arppkt[Ether].src = ethdst
			new_arppkt[Ether].dst = ethsrc

		print "----------SENDING RESPONSE - PACKET 1----------------------------------------"	
		#print new packet
		new_arppkt.show()

		#send back to attacker
		sendp(arppkt)


		#Part 2
		#-----------------------#
		iupp="ip and src "
		filter2=iupp+arpsrc+" and dst "+arpdst
		filter2=str(filter2)
		print filter2
		print "----------SNIFFING PACKET 2----------------------------------------"
		ippkt = sniff(count=1, filter=filter2)
		ippkt[0].show();
	
		new_ippkt = eval(ippkt[0].command())
		newSrcIP=reflectorIP
		newSrcEther=reflectorEth
		if victimIP==new_ippkt[IP].dst:
			newSrcIP=reflectorIP
			newSrcEther=reflectorEth
		elif new_ippkt[IP].dst==reflectorIP:
			newSrcIP=victimIP
			newSrcEther=victimEth
		#prepare new packet
		new_ippkt[IP].src=newSrcIP
		new_ippkt[IP].dst=arpsrc
		new_ippkt[Ether].src=newSrcEther
		new_ippkt[Ether].dst=ethsrc
		print "----------SENDING RESPONSE - PACKET 2----------------------------------------"	
		#send new packet
		new_ippkt.show()
		sendp(new_ippkt)

#call function
refl();
