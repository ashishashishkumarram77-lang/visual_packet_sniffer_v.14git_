# NetPulse: Visual Network Packet Sniffer & Traffic Analyzer
**BCA Final Year Networking Project (Python + Scapy + Flask & Tkinter)**

## 1. Project Overview & Abstract
**NetPulse** is a real-time network traffic monitoring and packet analysis tool designed for computer networking education and local diagnostics. Built in Python using **Scapy**, **Flask**, and **Tkinter**, it captures network packets on a laptop's active interface, classifies traffic across core protocols (**TCP, UDP, HTTP, DNS, ICMP**), identifies top source and destination IP flows, inspects OSI Layer 2–7 packet headers with hexadecimal payload dumps, and plots real-time bandwidth usage graphs.

To guarantee smooth live demonstrations during university practical exams and viva voce sessions (even on lab machines without Administrator/root privileges), NetPulse includes an automatic **Safe Simulation Mode** alongside live Scapy raw-socket sniffing.

## 2. Project Directory Structure
```text
visual_packet_sniffer/
├── app.py                  # Flask + Scapy Web Dashboard Backend & REST API
├── tkinter_sniffer.py      # Standalone Python Tkinter Desktop GUI Version
├── templates/
│   └── index.html          # Interactive Web Dashboard UI (Tailwind + Chart.js)
├── requirements.txt        # Python dependencies (scapy, flask, psutil)
└── README.md               # Setup instructions, architecture & Viva Voce Q&A
```

## 3. How to Run on Your Laptop

### Step 1: Install Python Dependencies
```bash
pip install -r requirements.txt
```
*(Note for Windows users: Install [Npcap](https://npcap.com/) with "WinPcap API-compatible Mode" checked if you want live raw-socket capture. Even without Npcap, the project will automatically run in Simulation Mode!)*

### Step 2A: Run the Web Dashboard (Flask + Scapy)
```bash
# Standard run (auto-switches to simulation if not root/Admin):
python app.py

# Live hardware interface packet sniffing (Linux/macOS with sudo, or Windows Admin CMD):
sudo python3 app.py
```
Then open **`http://127.0.0.1:5000`** in your browser.

### Step 2B: Run the Desktop GUI Version (Tkinter + Scapy)
```bash
python tkinter_sniffer.py
```

## 4. Top Viva Voce Questions & Answers
1. **What is a Packet Sniffer?**
   A packet sniffer (or network analyzer) is a program that intercepts and logs network traffic passing over a digital network interface by reading frame headers at the Data Link (Layer 2), Network (Layer 3), and Transport (Layer 4) layers.
2. **Why does live packet sniffing require Administrator/root privileges?**
   Opening a raw socket or placing a network interface card (NIC) into promiscuous mode requires kernel-level permissions (`CAP_NET_RAW` on Linux or Npcap driver access on Windows) so unauthorized user programs cannot intercept system-wide network traffic.
3. **How does your project distinguish HTTP and DNS from regular TCP and UDP?**
   DNS operates over port 53 (primarily UDP) and contains a structured `DNSQR` query/response header. HTTP operates over TCP (typically ports 80/8080) and starts with ASCII request methods (`GET`, `POST`, `HEAD`) or `HTTP/1.1` status headers in the application payload.
4. **What is the difference between TCP and UDP?**
   TCP is connection-oriented, reliable, and uses a 3-way handshake (`SYN`, `SYN-ACK`, `ACK`) with sequence numbers and flow control. UDP is connectionless and low-overhead, making it ideal for DNS lookups, VoIP, and live video streaming.
5. **What is ICMP used for?**
   ICMP (Internet Control Message Protocol) is a Layer 3 diagnostic and control protocol used by utilities like `ping` (Echo Request Type 8 / Echo Reply Type 0) and `traceroute` (Time Exceeded Type 11).
