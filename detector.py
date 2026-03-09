from scapy.all import sniff, DNS, DNSRR
import time
dns_memory = {}
# the function that checks ever single packet that in the net
def process_packet(packet):
    if packet.haslayer(DNS): #check if the packet is DNS if not its not relevent if she is DNS we find the dns layer to see what is that
        dns_layer = packet.getlayer(DNS)
        if dns_layer.qr == 0: #qr= query/respond, if 0 thats a DNS query if 1 thats a DNS respond
            tx_id = dns_layer.id #the id of the question
            query_name = dns_layer.qd.qname.decode() #the domain name that have been searched
            dns_memory[tx_id] = {"name": query_name, "time": time.time()} # by the id am writing the name of the domain and the time
            print(f"[*]the dns req sent: {query_name} (ID: {tx_id})")
        elif dns_layer.qr == 1:
            tx_id=dns_layer.id
            if tx_id in dns_memory:
                latency= time.time() - dns_memory[tx_id].get("time")
                query_name = dns_memory[tx_id].get("name")
                if packet.haslayer(DNSRR):
                    ttl_value = packet.getlayer(DNSRR).ttl
                    if latency < 0.005 or ttl_value > 10000:
                        print(f"!!! [ALERT] Possible DNS Spoofing Detected !!!")
                        print(f"[*] Site: {query_name}")
                        print(f"[*] Latency: {latency:.4f}s (Too fast!)")
                        print(f"[*] TTL: {ttl_value} (Too high!)")
                    else:
                        print(f"[V] Safe response for {query_name} (Time: {latency:.4f}s)")
                    del dns_memory[tx_id]
print("--- DNS Spoofing Detector is Running ---")
sniff(filter="udp port 53", prn=process_packet, store=False)