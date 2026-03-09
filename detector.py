from scapy.all import sniff, DNS, DNSRR
import time

# --- Configuration & Memory ---

# Storage for active queries: {tx_id: {"name": domain, "time": sent_timestamp}}
dns_memory = {}

# Storage for already resolved IDs to detect Race Conditions (duplicates)
# Format: {tx_id: "last_resolved_ip"}
resolved_ids = {}

# Long-term history of domain resolutions to detect IP changes
# Format: {domain_name: "last_known_ip"}
domain_history = {}

# Security Thresholds
MAX_TTL = 10000  # TTL values higher than this are suspicious
MIN_LATENCY = 0.005  # Responses faster than 5ms are likely from a local attacker (MITM)


def process_packet(packet):
    """
    Analyzes every packet on the network to detect DNS Spoofing.
    """
    if packet.haslayer(DNS):
        dns_layer = packet.getlayer(DNS)
        tx_id = dns_layer.id  # The unique 16-bit Transaction ID

        # --- PHASE 1: Handling DNS Queries (Outgoing) ---
        if dns_layer.qr == 0:
            query_name = dns_layer.qd.qname.decode().strip('.')

            # Record the query in our temporary memory
            dns_memory[tx_id] = {
                "name": query_name,
                "time": time.time()
            }
            print(f"[*] Query Sent: {query_name} (ID: {tx_id})")

        # --- PHASE 2: Handling DNS Responses (Incoming) ---
        elif dns_layer.qr == 1:

            # A) RACE CONDITION CHECK:
            # If the ID is already in 'resolved_ids', it means we've already seen
            # a response for this ID. This is a classic sign of a "Race Condition" attack.
            if tx_id in resolved_ids:
                print(f"!!! [CRITICAL] Race Condition Detected! (ID: {tx_id}) !!!")
                print(f"    Second response received for an already resolved query.")
                return  # Stop processing this duplicate packet

            # B) NORMAL RESPONSE PROCESSING:
            if tx_id in dns_memory:
                sent_time = dns_memory[tx_id]["time"]
                domain_name = dns_memory[tx_id]["name"]

                # Calculate network latency: $Latency = Current\_Time - Sent\_Time$
                latency = time.time() - sent_time

                if packet.haslayer(DNSRR):
                    # Extract TTL and the resolved IP Address (rdata)
                    answer_layer = packet.getlayer(DNSRR)
                    ttl_value = answer_layer.ttl
                    resolved_ip = answer_layer.rdata

                    # Convert resolved_ip to string if it's not
                    resolved_ip = str(resolved_ip)

                    is_suspicious = False
                    alerts = []

                    # Check 1: Latency Threshold
                    if latency < MIN_LATENCY:
                        is_suspicious = True
                        alerts.append(f"Suspiciously fast latency ({latency:.4f}s)")

                    # Check 2: TTL Threshold
                    if ttl_value > MAX_TTL:
                        is_suspicious = True
                        alerts.append(f"Abnormally high TTL ({ttl_value})")

                    # Check 3: IP Address History Change
                    # If we've seen this domain before and the IP is different, it's a red flag.
                    if domain_name in domain_history:
                        previous_ip = domain_history[domain_name]
                        if resolved_ip != previous_ip:
                            is_suspicious = True
                            alerts.append(f"IP Mismatch! (Previous: {previous_ip}, Current: {resolved_ip})")

                    # Output Results
                    if is_suspicious:
                        print(f"\n[!!!] SPOOFING ALERT for {domain_name} [!!!]")
                        for alert in alerts:
                            print(f"    - {alert}")
                    else:
                        print(f"[V] Clean response for {domain_name} ({resolved_ip})")

                    # Update History
                    domain_history[domain_name] = resolved_ip
                    resolved_ids[tx_id] = resolved_ip  # Mark as resolved

                    # Clean up memory
                    del dns_memory[tx_id]


# Start sniffing on UDP port 53 (Standard DNS Port)
print("--- Advanced DNS Spoofing Detector is Active ---")
sniff(filter="udp port 53", prn=process_packet, store=False)