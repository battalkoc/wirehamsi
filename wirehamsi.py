import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget, QLineEdit, QLabel, QHBoxLayout, QSplitter, QTextEdit,
    QListWidgetItem, QFileDialog, QComboBox, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont, QColor, QIcon, QPixmap
from scapy.all import sniff, IFACES
import psutil
import socket
import os
from datetime import datetime

class PacketSniffer(QThread):
    packet_captured = pyqtSignal(str,str)
    def __init__(self,filter_rule="",interface=""):
        super().__init__()
        self.filter_rule = filter_rule
        self.interface = interface
    def procces_packet(self,packet):
        packet_summary = packet.summary()
        packet_details = packet.show(dump=True)
        self.packet_captured.emit(packet_summary,packet_details)
    def run(self):
        sniff(prn=self.procces_packet,filter=self.filter_rule,iface=self.interface,count=0)
    def set_filter(self,filter_rule):
        self.filter_rule = filter_rule
    def set_interface(self,interface):
        self.interface = interface


class PacketSnifferApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WireHamsi")
        self.setWindowIcon(QIcon("icon.ico"))
        self.sniffer_thread = PacketSniffer()
        self.sniffer_thread.packet_captured.connect(self.display_packet)
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.packet_data = []
        self.initUI()
    def initUI(self):
        layout = QVBoxLayout()
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Paket Yakalamayı Başlat")
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button = QPushButton("Paket Yakalamayı Durdur")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.log_button = QPushButton("Kayıt Yap")
        self.log_button.setCheckable(True)
        self.log_button.clicked.connect(self.toggle_logging)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.log_button)

        filter_layout = QHBoxLayout()
        self.filter_label = QLabel("Filtre:")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filtre girin (örn. ip or tcp)")
        self.filter_button = QPushButton("Filtre Uygula")
        self.filter_button.clicked.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_label)
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(self.filter_button)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Paketler arasında arama yapın...")
        self.search_bar.textChanged.connect(self.search_packets)

        iface_layout = QHBoxLayout()
        self.interface_label = QLabel("Ağ Arayüzü:")
        self.interface_dropdown = QComboBox()
        connected_interfaces = self.get_connected_interfaces()
        for iface in IFACES.values():
            iface_name = iface.description
            if iface.name in connected_interfaces:
                iface_name += " ✅"
            else:
                iface_name += " ❌"
            self.interface_dropdown.addItem(iface_name,iface.name)
        iface_layout.addWidget(self.interface_label)
        iface_layout.addWidget(self.interface_dropdown)

        packet_layout = QHBoxLayout()
        self.packet_count_label = QLabel("Toplam Yakalanan Paket: 0")
        self.tcp_label = QLabel("TCP Paketleri: 0")
        self.udp_label = QLabel("UDP Paketleri: 0")
        self.icmp_label = QLabel("ICMP Paketleri: 0")
        packet_layout.addWidget(self.packet_count_label)
        packet_layout.addWidget(self.tcp_label)
        packet_layout.addWidget(self.udp_label)
        packet_layout.addWidget(self.icmp_label)

        self.packet_save = QPushButton("Paketleri Kaydet")
        self.packet_save.clicked.connect(self.save_packets)

        splitter = QSplitter(Qt.Horizontal)
        self.packet_list = QListWidget()
        self.packet_list.itemClicked.connect(self.display_packet_details)
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        splitter.addWidget(self.packet_list)
        splitter.addWidget(self.packet_details)

        layout.addLayout(button_layout)
        layout.addLayout(filter_layout)
        layout.addWidget(self.search_bar)
        layout.addLayout(iface_layout)
        layout.addLayout(packet_layout)
        layout.addWidget(self.packet_save)
        layout.addWidget(splitter)
        self.setLayout(layout)
        self.setStyleSheet("""
        QWidget {
            background-color: #1e1e2f;
            color: #e5e5e5;
            font-size: 14px;
            font-family: 'Segoe UI', sans-serif;
        }

        QPushButton {
            background-color: #3b3b52;
            color: #ffffff;
            border: 1px solid #4d4d63;
            padding: 8px;
            border-radius: 6px;
            transition: background-color 0.3s ease; /* Geçiş efekti */
        }

        QPushButton:hover {
            background-color: #5a5a7a;
        }

        QPushButton:pressed {
            background-color: #7e57c2;
            color: #ffffff;
        }

        QPushButton:checked {
            background-color: #7e57c2;
            color: #ffffff;
        }

        QLineEdit, QComboBox, QTextEdit {
            background-color: #2b2b3b;
            color: #e5e5e5;
            border: 1px solid #4d4d63;
            padding: 6px;
            border-radius: 4px;
        }

        QLineEdit:focus, QComboBox:focus, QTextEdit:focus {
            border: 1px solid #7e57c2; /* Odaklandığında mor kenarlık */
        }

        QLabel {
            color: #cfcfdf;
            font-weight: bold;
        }

        QListWidget {
            background-color: #2b2b3b;
            color: #e5e5e5;
            border: 1px solid #4d4d63;
            padding: 4px;
            border-radius: 6px;
        }

        QListWidget::item:selected {
            background-color: #7e57c2;
            color: #ffffff;
            border-radius: 4px;
            margin: 2px;
        }

        QListWidget::item:hover {
            background-color: #5a5a7a;
        }

        QComboBox QAbstractItemView {
            background-color: #2b2b3b;
            color: #ffffff;
            selection-background-color: #7e57c2;
            border: 1px solid #4d4d63;
            padding: 4px;
            border-radius: 4px;
        }

        QSplitter::handle {
            background-color: #7e57c2;
            height: 4px;
            border-radius: 2px;
        }

        QCheckBox {
            color: #d1d1d1;
        }

        QCheckBox::indicator {
            width: 16px;
            height: 16px;
            border-radius: 3px;
            background-color: #3b3b52;
            border: 1px solid #4d4d63;
        }

        QCheckBox::indicator:checked {
            background-color: #7e57c2;
            border: 1px solid #7e57c2;
        }
        """)
    def get_connected_interfaces(self):
        connected_interfaces = set()
        for iface, info in psutil.net_if_addrs().items():
            for snic in info:
                if snic.family == socket.AF_INET:
                    if iface in psutil.net_if_stats() and psutil.net_if_stats()[iface].isup:
                        connected_interfaces.add(iface)
        return connected_interfaces
    def start_sniffing(self):
        if not self.sniffer_thread.isRunning():
            selected_interface = self.interface_dropdown.currentData()
            iface = IFACES.dev_from_name(selected_interface)
            if iface:
                try:
                    self.sniffer_thread.set_interface(iface.name)
                    self.sniffer_thread.set_filter(self.filter_input.text())
                    self.format_display()
                    self.sniffer_thread.start()
                    self.start_button.setEnabled(False)
                    self.stop_button.setEnabled(True)
                except OSError as e:
                    self.show_error_message(str(e))
                    self.start_sniffing()
            else:
                self.show_error_message("Geçersiz ağ arayüzü seçildi!")
    def stop_sniffing(self):
        if self.sniffer_thread.isRunning():
            self.sniffer_thread.terminate()
            self.sniffer_thread.wait()
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
    def show_error_message(self,message):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText("Bir Hata Oluştu!")
        msg.setInformativeText(message)
        msg.setWindowTitle("Hata")
        msg.exec_()
    def format_display(self):
        self.packet_list.clear()
        self.packet_details.clear()
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.update_packet_stats()
    def update_packet_stats(self):
        self.packet_count_label.setText(f"Toplam Yakalanan Paket: {self.packet_count}")
        self.tcp_label.setText(f"TCP Paketleri: {self.tcp_count}")
        self.udp_label.setText(f"UDP Paketleri: {self.udp_count}")
        self.icmp_label.setText(f"ICMP Paketleri: {self.icmp_count}")
    def display_packet(self,packet_summary, packet_details, add_to_data=True):
        item = QListWidgetItem()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        item.setText(f"[{timestamp}] {packet_summary}")
        item.setData(Qt.UserRole,packet_details)
        if add_to_data:
            self.packet_data.append((packet_summary,packet_details))
        font = QFont()
        font.setWeight(QFont.Black)
        item.setFont(font)
        try:
            if hasattr(self,"log_file") and self.log_file:
                self.log_file.write(f"[{timestamp}] {packet_summary}\n")
                self.log_file.write("Detaylar:\n"+packet_details+"\n")
                self.log_file.write("-"*40+"\n")
                self.log_file.flush()
        except:
            print("Yazılamadı!")
        if "TCP" in packet_summary:
            item.setBackground(Qt.lightGray)
            item.setForeground(QColor(0,0,0))
            self.tcp_count += 1
        elif "UDP" in packet_summary:
            item.setBackground(Qt.yellow)
            item.setForeground(QColor(0,0,0))
            self.udp_count += 1
        elif "ICMP" in packet_summary:
            item.setBackground(Qt.green)
            self.icmp_count += 1

        self.packet_list.addItem(item)
        self.packet_count += 1
        self.update_packet_stats()
    def display_packet_details(self,item):
        details = item.data(Qt.UserRole)
        self.packet_details.setText(details)
    def apply_filter(self):
        filter_text = self.filter_input.text().lower()
        self.format_display()
        for packet_summary, packet_details in self.packet_data:
            if not filter_text or filter_text in packet_summary.lower():
                self.display_packet(packet_summary,packet_details,add_to_data=False)
    def search_packets(self):
        search_text = self.search_bar.text().lower()
        for index in range(self.packet_list.count()):
            item = self.packet_list.item(index)
            item.setHidden(search_text not in item.text().lower())
    def toggle_logging(self):
        if self.log_button.isChecked():
            try:
                self.log_file = open("packet_log.txt","a",encoding="utf-8")
                self.log_button.setText("Kaydı Durdur")
            except Exception as e:
                self.show_error_message(f"Kayıt dosyası açılamadı: {str(e)}")
                self.log_button.setChecked(False)
        else:
            if hasattr(self,"log_file") and self.log_file:
                try:
                    if not self.log_file.closed:
                        self.log_file.close()
                except Exception as e:
                    self.show_error_message(f"Kayıt dosyası kapatılamadı: {str(e)}")
                finally:
                    self.log_file = None
            self.log_button.setText("Kayıt Yap")
    def save_packets(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self,"Paketleri Kaydet","","Text Files (*.txt);;All Files (*)", options=options)
        if file_path:
            with open(file_path, "w") as file:
                for index in range(self.packet_list.count()):
                    item = self.packet_list.item(index)
                    file.write(item.text() + "\n")
                    file.write("Detaylar: \n"+item.data(Qt.UserRole)+"\n")
                    file.write("-"*40+"\n")
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec_())
