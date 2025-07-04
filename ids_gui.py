import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import socket
import psutil
from ids_module import IntrusionDetectionSystem
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt


def get_default_interface():
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return iface
    return "eth0"


class IDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")
        self.root.geometry("600x500")
        self.root.configure(bg='green')  

        self.ids = None
        self.running = False

        self.interface = get_default_interface()

        
        tk.Label(root, text=f"Using Interface: {self.interface}", fg="white", bg="green").pack(pady=5)
        tk.Label(root, text="Traffic Threshold (default: 100):", fg="white", bg="green").pack()

        self.threshold_entry = tk.Entry(root)
        self.threshold_entry.insert(0, "100")
        self.threshold_entry.pack(pady=5)

        self.start_button = tk.Button(root, text="Start IDS", bg="darkgreen", fg="white", command=self.start_ids)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop IDS", bg="darkred", fg="white", command=self.stop_ids)
        self.stop_button.pack(pady=5)

        self.plot_button = tk.Button(root, text="Plot Traffic", bg="darkgreen", fg="white", command=self.plot_traffic)
        self.plot_button.pack(pady=5)

        self.view_log_button = tk.Button(root, text="View Logs", bg="darkgreen", fg="white", command=self.view_logs)
        self.view_log_button.pack(pady=5)

        
        self.log_display = scrolledtext.ScrolledText(root, height=15, width=70)
        self.log_display.pack(pady=10)
        self.log_display.configure(bg="#ccffcc")  # light green background for readability

    def start_ids(self):
        if self.running:
            messagebox.showinfo("Info", "IDS is already running.")
            return

        try:
            threshold = int(self.threshold_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid threshold value.")
            return

        self.ids = IntrusionDetectionSystem(self.interface, email=None, threshold=threshold)
        self.running = True

        def run_ids():
            self.ids.start()
            self.log_display.insert(tk.END, "[INFO] IDS sniffing started...\n")

        threading.Thread(target=run_ids, daemon=True).start()
        self.log_display.insert(tk.END, f"[INFO] Started IDS on interface '{self.interface}' with threshold {threshold}\n")

    def stop_ids(self):
        if self.ids and self.running:
            self.ids.stop()
            self.running = False
            self.log_display.insert(tk.END, "[INFO] IDS stopped.\n")
        else:
            messagebox.showinfo("Info", "IDS is not running.")

    def plot_traffic(self):
        if not self.ids or not self.ids.packet_count:
            messagebox.showwarning("Warning", "Start the IDS and ensure packets are being captured.")
            return

        sorted_traffic = sorted(self.ids.packet_count.items(), key=lambda x: x[1], reverse=True)
        ips = [ip for ip, count in sorted_traffic]
        counts = [count for ip, count in sorted_traffic]

        fig, ax = plt.subplots(figsize=(10, 5))  # Wider for better layout
        bars = ax.bar(ips, counts, color='seagreen', edgecolor='black')

        ax.set_title("Packet Traffic per IP", fontsize=14)
        ax.set_xlabel("IP Address", fontsize=12)
        ax.set_ylabel("Packet Count", fontsize=12)
        ax.grid(axis='y', linestyle='--', alpha=0.7)

        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", fontsize=9)

        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height}', xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=8)

        fig.tight_layout()
        plot_window = tk.Toplevel(self.root)
        plot_window.title("Traffic Plot")
        plot_window.geometry("800x500")  # Ensures full display

        canvas = FigureCanvasTkAgg(fig, master=plot_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def view_logs(self):
        try:
            with open("ids_log.txt", "r") as f:
                logs = f.read()
            self.log_display.delete(1.0, tk.END)
            self.log_display.insert(tk.END, logs)
        except FileNotFoundError:
            messagebox.showerror("Error", "Log file not found.")


if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
