import sys
import socket
import platform
import subprocess
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QHBoxLayout, QPushButton, QWidget, QLineEdit, QLabel
)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QIcon
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP


def is_network_active():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False


def ping_ip(ip):
    system = platform.system().lower()
    command = ["ping", "-n", "1", ip] if system == "windows" else ["ping", "-c", "1", ip]
    try:
        subprocess.check_output(command, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


class SnifferThread(QThread):
    packet_captured = pyqtSignal(dict)

    def __init__(self, ip_filter=None):
        super().__init__()
        self.ip_filter = ip_filter.strip() if ip_filter else None
        self.running = True

    def run(self):
        def process_wrapper(pkt):
            if not self.running:
                return True
            process_wrapper.counter += 1
            if process_wrapper.counter % 5 == 0:
                self.process_packet(pkt)

        process_wrapper.counter = 0
        sniff(prn=process_wrapper, store=False, stop_filter=lambda x: not self.running)

    def stop(self):
        self.running = False

    def process_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if self.ip_filter and self.ip_filter != src_ip and self.ip_filter != dst_ip:
                return

            pkt_info = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "src": src_ip,
                "dst": dst_ip,
                "proto": packet[IP].proto,
                "len": len(packet),
                "desc": self.ai_analyze(packet)
            }
            self.packet_captured.emit(pkt_info)

    def ai_analyze(self, packet):
        suspicious_ports = [6667, 12345, 31337, 4444]
        length = len(packet)
        desc = "Normal packet"

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            return desc

        if sport in suspicious_ports or dport in suspicious_ports:
            desc = "⚠ Suspicious port"
        elif length > 1500:
            desc = "⚠ Large packet"
        elif length < 50:
            desc = "⚠ Small packet"

        if TCP in packet and packet[TCP].flags == 0x02:
            desc += " | SYN scan?"

        return desc


class PacketSnifferGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔍 Wireshark-like Packet Sniffer with AI-based Packet Analysis")
        self.setGeometry(100, 100, 1000, 600)
        self.setWindowIcon(QIcon("icon.ico"))

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol", "Length", "AI Analysis"
        ])

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter target IP address (required)")

        self.network_status = QLabel("🌐 Network status: Unknown")
        self.network_status.setStyleSheet("color: gray; font-weight: bold;")

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: blue; font-weight: bold;")

        self.timer_label = QLabel("Elapsed time: 0s")
        self.timer_label.setStyleSheet("color: darkblue; font-weight: bold;")

        self.start_button = QPushButton("▶ Start")
        self.start_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        self.start_button.clicked.connect(self.start_sniffing)

        self.stop_button = QPushButton("⏹ Stop")
        self.stop_button.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setDisabled(True)

        self.clear_button = QPushButton("🧹 Clear")
        self.clear_button.setStyleSheet("background-color: #607D8B; color: white; font-weight: bold;")
        self.clear_button.clicked.connect(self.clear_table)

        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("Target IP:"))
        top_layout.addWidget(self.ip_input)
        top_layout.addWidget(self.start_button)
        top_layout.addWidget(self.stop_button)
        top_layout.addWidget(self.clear_button)

        main_layout = QVBoxLayout()
        main_layout.addLayout(top_layout)
        main_layout.addWidget(self.network_status)
        main_layout.addWidget(self.status_label)
        main_layout.addWidget(self.timer_label)
        main_layout.addWidget(self.table)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.sniffer = None
        self.elapsed_seconds = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_timer)

        self.update_network_status_initial()

    def update_network_status_initial(self):
        self.network_status.setText("🌐 Network status: Unknown")
        self.network_status.setStyleSheet("color: gray; font-weight: bold;")

    def update_timer(self):
        self.elapsed_seconds += 1
        self.timer_label.setText(f"Elapsed time: {self.elapsed_seconds}s")

    def start_sniffing(self):
        if self.sniffer and self.sniffer.isRunning():
            self.status_label.setText("⚠ Sniffer already running.")
            return

        ip = self.ip_input.text().strip()

        if not ip:
            self.status_label.setText("❌ IP address is required!")
            return

        if not is_network_active():
            self.network_status.setText("❌ Network is INACTIVE")
            self.network_status.setStyleSheet("color: red; font-weight: bold;")
            self.status_label.setText("Cannot start sniffing: Network is inactive.")
            return
        else:
            self.network_status.setText("🌐 Network is ACTIVE")
            self.network_status.setStyleSheet("color: green; font-weight: bold;")
            self.clear_table()
            self.status_label.setText("")

        self.status_label.setText(f"🏓 Pinging {ip}...")
        QApplication.processEvents()
        if not ping_ip(ip):
            self.status_label.setText(f"❌ IP {ip} is not reachable.")
            return

        self.status_label.setText(f"✅ Sniffing started for IP: {ip}")

        self.elapsed_seconds = 0
        self.timer_label.setText("Elapsed time: 0s")
        self.timer.start(1000)

        self.sniffer = SnifferThread(ip_filter=ip)
        self.sniffer.packet_captured.connect(self.add_packet)
        self.sniffer.start()
        self.start_button.setDisabled(True)
        self.stop_button.setDisabled(False)

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer.wait()
            self.status_label.setText("🛑 Sniffer stopped.")
        else:
            self.status_label.setText("⚠ Sniffer is not running.")
        self.timer.stop()
        self.timer_label.setText(f"Elapsed time stopped at: {self.elapsed_seconds}s")
        self.start_button.setDisabled(False)
        self.stop_button.setDisabled(True)

    def clear_table(self):
        self.table.setRowCount(0)
        self.status_label.setText("🧹 Table cleared.")

    def add_packet(self, pkt_info):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(pkt_info["time"]))
        self.table.setItem(row, 1, QTableWidgetItem(pkt_info["src"]))
        self.table.setItem(row, 2, QTableWidgetItem(pkt_info["dst"]))
        self.table.setItem(row, 3, QTableWidgetItem(str(pkt_info["proto"])))
        self.table.setItem(row, 4, QTableWidgetItem(str(pkt_info["len"])))
        ai_item = QTableWidgetItem(pkt_info["desc"])
        if "⚠" in pkt_info["desc"]:
            ai_item.setForeground(QColor("red"))
        self.table.setItem(row, 5, ai_item)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferGUI()
    window.show()
    sys.exit(app.exec())
