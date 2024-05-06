#! /usr/bin/env python3
import subprocess
import tempfile
from netfilterqueue import NetfilterQueue
from scapy.all import IP
from scapy.all import *


### Config ###
#Editor to use (must be in path)
editor= "vim"

# Create a temporary file with the content and open the editor
def input_via_editor(editor, content=""):
	with tempfile.NamedTemporaryFile(mode='w') as temp_file:
		if content:
			temp_file.write(content)
			temp_file.flush()
		try:
			subprocess.check_call([editor, temp_file.name])
		except subprocess.CalledProcessError as e:
			raise IOError("{} exited with code {}.".format(editor, e.returncode))
		with open(temp_file.name) as temp_file_2:
			return temp_file_2.read()
		
def modify_icmp_response(packet):
    # Check if the packet is an ICMP Echo reply
    if ICMP in packet and packet[ICMP].src == "192.168.8.161":  # ICMP Echo Reply
        print("ICMP caught")
        # Modify the packet fields
        packet[IP].src = "192.168.8.122"
        packet[IP].dst = "192.168.8.122"  

        return packet
    return packet



# Proccess intercepted packets
def interrupt_and_edit(pkt):
    # global editor
	
    print("Packet Intercepted")

    packet = IP(pkt.get_payload())
    print(packet)
    #packet = IP(pkt.get_payload()) #if want to edit the payload only

    #compute the equivalent scapy command
    # scapy_command = packet.command()

    #let the user edit the scapy command
    # user_defined_command = input_via_editor(editor, scapy_command)
    #convert to packet
    # user_defined_packet = eval(user_defined_command)

    user_defined_packet = modify_icmp_response(packet)

        
    #force update of the checksum
    # del user_defined_packet[IP].chksum
    #update the payload
    pkt.set_payload( raw(user_defined_packet) )
	
    print("Packet forwarded")

    #forward the packet
    pkt.accept()


if __name__=="__main__":

    nfqueue = NetfilterQueue()

    # iptables -I OUTPUT -d 192.168.8.161 -j NFQUEUE --queue-num 2
    #Bind to the same queue number (here 2)
    nfqueue.bind(2, interrupt_and_edit)
    print("bound")
	
    #run (indefinetely)
    try:
        print("running")
        nfqueue.run()
        print("after running")
    except KeyboardInterrupt:
        print('Quiting...')
        nfqueue.unbind()