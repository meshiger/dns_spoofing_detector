# Advanced DNS Spoofing Detector

A professional Python-based network security tool designed to detect **DNS Spoofing** and **Man-in-the-Middle (MITM)** attacks in real-time using the Scapy library.

##  Detection Logic
The detector employs four main heuristic methods to identify malicious DNS activity:

1. **Transaction ID Tracking**: Maps outgoing queries to incoming responses to ensure every response was actually requested.
2. **Latency Analysis**: Calculates the time difference between query and response. Responses arriving significantly faster than the network average ($< 5ms$) are flagged as local injection attempts.
3. **TTL (Time To Live) Inspection**: Detects abnormally high TTL values often used by attackers to "poison" the local DNS cache for extended periods.
4. **Duplicate Detection (Race Condition)**: Identifies if multiple responses are received for a single query ID—a signature of an attacker attempting to "outrun" the legitimate DNS server.
5. **IP History Tracking**: Maintains a stateful history of resolved domains. If a domain suddenly points to a different IP address than previously recorded, an alert is triggered.

##  Getting Started

### Prerequisites
- Python 3.x
- `scapy` library
- Administrator/Root privileges (required for network sniffing)

### Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/meshiger/dns_spoofing_detector.git](https://github.com/meshiger/dns_spoofing_detector.git
