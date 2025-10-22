# Network Packet Analyzer

A Python-based tool for capturing, analyzing, and visualizing real-time network traffic.  
It provides insight into protocol distribution, source and destination IPs, and detects potentially suspicious activity such as high-frequency or large packet transmissions.

---

## 1. Overview

The Network Packet Analyzer is designed to simulate a simplified version of Wireshark for educational and research purposes.  
It captures live TCP/UDP packets from a system interface, logs relevant details, and visualizes them through an interactive Streamlit dashboard.

The project combines:
- Low-level network packet sniffing using **Scapy**
- Data analysis and anomaly detection in **Python**
- Real-time interactive visualization using **Streamlit**

---

## 2. Features

- **Live Packet Capture:** Capture TCP, UDP, and other packets in real-time.
- **Custom Filters:** Filter packets by protocol, IP, or port before capture.
- **Anomaly Detection:** Identify suspicious patterns such as DoS-like traffic or large packet sizes.
- **Dashboard Visualization:** Interactive charts for protocol and IP analysis.
- **Data Export:** Download captured packet logs in CSV format.
- **Modular Architecture:** Separate modules for capture, analysis, and visualization.

---

## 3. Project Structure

```
network-packet-analyzer/
│
├── main.py                 # Core packet capture logic
├── analyzer.py             # Suspicious traffic detection
├── utils.py                # Helper for filter construction
├── dashboard.py            # Streamlit dashboard for visualization
│
├── data/
│   ├── .gitkeep
│   ├── packet_log.csv      # Runtime-generated log (ignored by Git)
│   └── suspicious_log.csv  # Runtime-generated suspicious log (ignored by Git)
│
├── requirements.txt        # Dependencies
├── .gitignore              # Ignore runtime and environment files
└── README.md               # Project documentation
```

---

## 4. Installation

### Prerequisites
- Python 3.8 or above  
- pip package manager  
- Administrative / root privileges (for packet capture)

### Setup
```bash
# Clone the repository
git clone https://github.com/Krixna-Kant/network-packet-analyzer.git
cd network-packet-analyzer

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (macOS/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 5. Usage

### Step 1 — Capture Packets
Run the main script to start packet capture:

```bash
python main.py
```

- You can optionally filter packets by protocol, source IP, destination IP, or port.
- Captured data will be saved in `data/packet_log.csv`.

### Step 2 — View Dashboard
Launch the Streamlit dashboard for visualization:

```bash
streamlit run dashboard.py
```

The dashboard displays:
- Protocol distribution
- Top source IPs
- Suspicious packet activity
- Recent packet details

---

## 6. Example Output

| Timestamp           | Source IP     | Destination IP | Protocol | Length |
|---------------------|---------------|----------------|----------|--------|
| 2025-10-18 20:37:17 | 20.42.73.26   | 10.239.33.27   | TCP      | 66     |

Detected suspicious packets are logged in:
```
data/suspicious_log.csv
```

---

## 7. Limitations

- Must be run locally; network sniffing requires hardware interface access.
- Cloud deployment (e.g., Streamlit Cloud) supports dashboard visualization only with static data.
- Requires administrative privileges for packet capture.

---

## 8. Acknowledgments

- **Scapy** – for packet sniffing and network manipulation
- **Streamlit** – for interactive dashboard visualization
- **Pandas** – for data analysis and handling

---

## 9. Author

**Krishna Kant**  
B.Tech CSE | Maharaja Agrasen Institute of Technology (GGSIPU)  
GitHub: [https://github.com/Krixna-Kant](https://github.com/Krixna-Kant)