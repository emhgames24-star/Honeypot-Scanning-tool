import customtkinter as ctk
import subprocess
import threading
import os

app = ctk.CTk()
app.title("Honeypot Monitor")
app.geometry("900x650")
app.configure(fg_color="#080347")


def animate_progress(current, target):
    if current < target:
        current += 0.01
        progress.set(current)
        app.after(20, lambda: animate_progress(current, target))

def run_scan():
    status_label.configure(text="● PULLING PCAP", text_color="#ffd166")
    animate_progress(0, 0.2)
    right_box.configure(state="normal")
    right_box.insert("end", "Connecting to device...\n")
    right_box.configure(state="disabled")
    threading.Thread(target=pull_pcap, daemon=True).start()

def pull_pcap():
    # ---- CONFIGURATION ----
    SSH_PORT = "YOUR_SSH_PORT"               # e.g. "22"
    HONEYPOT_USER = "YOUR_HONEYPOT_USER"     # e.g. "pi"
    HONEYPOT_IP = "YOUR_HONEYPOT_IP"         # e.g. "192.168.1.100"
    REMOTE_PCAP = "YOUR_REMOTE_PCAP_PATH"    # e.g. "/home/pi/captures/honeypot.pcap"
    LOCAL_PCAP = "YOUR_LOCAL_PCAP_PATH"      # e.g. "/home/user/Desktop/honeypot.pcap"
    # -----------------------

    result = subprocess.run([
        "scp", "-P", SSH_PORT,
        f"{HONEYPOT_USER}@{HONEYPOT_IP}:{REMOTE_PCAP}",
        LOCAL_PCAP
    ], capture_output=True, text=True)

    if result.returncode !=0:
        right_box.configure(state="normal")
        right_box.insert("end", "Transfer Failed\n")
        right_box.configure(state="disabled")
        status_label.configure(text="● ERROR", text_color="#ff3c5a")
        return
    file_size = os.path.getsize(LOCAL_PCAP)
    file_size_kb = round(file_size / 1024, 2)
    right_box.configure(state="normal")
    right_box.insert("end", f"File transferred successfully — {file_size_kb} KB\n")
    right_box.configure(state="disabled")
    animate_progress(0.2, 0.5)
    status_label.configure(text="● ANALYZING", text_color="#4cc9f0")
    analyze_pcap()


def analyze_pcap():
    from scapy.all import rdpcap, ARP

    # ---- CONFIGURATION ----
    LOCAL_PCAP = "YOUR_LOCAL_PCAP_PATH"      # e.g. "/home/user/Desktop/honeypot.pcap"
    # Add your known device MAC addresses below
    known_devices = [
        'XX:XX:XX:XX:XX:XX',  # Device 1 - e.g. Desktop
        'XX:XX:XX:XX:XX:XX',  # Device 2 - e.g. Router
        'XX:XX:XX:XX:XX:XX',  # Device 3 - e.g. Honeypot Pi
        'XX:XX:XX:XX:XX:XX',  # Device 4 - e.g. PiHole
        'XX:XX:XX:XX:XX:XX',  # Device 5 - e.g. NAS
        'XX:XX:XX:XX:XX:XX',  # Device 6 - e.g. Other
    ]
    # -----------------------

    packets = rdpcap(LOCAL_PCAP)
    unknown = []
    seen = set()
        

    for packet in packets:
        if packet.haslayer(ARP):
            src_mac = packet[ARP].hwsrc.upper()
            src_ip = packet[ARP].psrc
            if src_mac not in known_devices and src_mac not in seen:
                seen.add(src_mac)
                unknown.append((src_mac, src_ip))

    if unknown:
        for mac, ip in unknown:
            right_box.configure(state="normal")
            right_box.insert("end", f"⚠ TANGO SPOTTED\n  MAC: {mac}\n  IP:  {ip}\n")
            right_box.configure(state="disabled")
        status_label.configure(text=f"● ALERT {len(unknown)} UNKNOWN", text_color="#ff3c5a")
    else:
        right_box.configure(state="normal")
        right_box.insert("end", "All clear — tangos spotted\n")
        right_box.configure(state="disabled")
        status_label.configure(text="● CLEAR", text_color="#00ff88")
    
    animate_progress(0.5, 1.0)
    
header = ctk.CTkFrame(app, fg_color="#0f1623",corner_radius=0, height=50)
header.pack(fill="x")
header_label = ctk.CTkLabel(header, text="⬡ HONEYPOT MONITOR",
                            font=ctk.CTkFont(family="Courier New", size=18, weight="bold"),
                            text_color="#e6e92f")
header_label.pack(side="left", padx=20, pady=14)

#main area frame
main = ctk.CTkFrame(app, fg_color="transparent")
main.pack(fill="both", expand=True, padx=12, pady=8)
#Left Panel
left_panel = ctk.CTkFrame(main, fg_color="#0f1623",corner_radius=8)
left_panel.pack(side="left", fill="both", expand=True, padx =(0,6))

left_title = ctk.CTkLabel(left_panel, text="WHITELIST",
                          font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
                          text_color = "#5a7a8a")
left_title.pack(anchor='w', padx=14, pady=(12,4))
#left text box
left_box = ctk.CTkTextbox(left_panel, fg_color="#080c14",
                          text_color="#c8d8e8",
                          font=ctk.CTkFont(family="Courier New",size=11),
                          corner_radius=6)
left_box.pack(fill="both", expand=True, padx=10, pady=(0,10))
for mac, name in {
    'XX:XX:XX:XX:XX:XX': 'Device 1',
    'XX:XX:XX:XX:XX:XX': 'Device 2',
    'XX:XX:XX:XX:XX:XX': 'Device 3',
    'XX:XX:XX:XX:XX:XX': 'Device 4',
    'XX:XX:XX:XX:XX:XX': 'Device 5',
    'XX:XX:XX:XX:XX:XX': 'Device 6',
}.items():
    left_box.insert("end", f"  {mac}    {name}\n")
left_box.configure(state="disabled")
#right panel
right_panel = ctk.CTkFrame(main, fg_color="#0f1623",corner_radius=8)
right_panel.pack(side="left", fill="both", expand=True, padx =(6,0))

right_title = ctk.CTkLabel(right_panel, text="EVENT LOG",
                          font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
                          text_color = "#5a7a8a")
right_title.pack(anchor='w', padx=14, pady=(12,4))
#right textbox
right_box = ctk.CTkTextbox(right_panel, fg_color="#080c14",
                           text_color="#c8d8e8",
                           font=ctk.CTkFont(family="Courier New", size=11),
                           corner_radius=6)
right_box.pack(fill="both", expand=True, padx=10, pady=(0,10))
footer = ctk.CTkFrame(app, fg_color="#0f1623", corner_radius=0, height=50)
footer.pack(fill="x", side="bottom")

scan_bttn = ctk.CTkButton(footer, text="▶ RUN SCAN",
                          font=ctk.CTkFont(family="Courier New", size=13, weight="bold"),
                          fg_color="#d65f10", text_color="#000000",
                          hover_color="#9C5A14", corner_radius=6,
                          width=160, height=36,
                          command=run_scan )
scan_bttn.pack(side="left", padx=16, pady=12)

status_label = ctk.CTkLabel(footer, text="● IDLE",
                            font=ctk.CTkFont(family="Courier New", size=12),
                            text_color="#3a4a5c")
status_label.pack(side="left", padx=12)

progress= ctk.CTkProgressBar(footer, fg_color="#1e2d40",
                             progress_color="#00ff88",
                             height=16,
                             corner_radius=8 )
progress.pack(side="left", fill="x", expand=True, padx=(0,16), pady=12)
progress.set(0)

                          
                          
app.mainloop()
