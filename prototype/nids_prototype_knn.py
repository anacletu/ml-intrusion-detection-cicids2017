import pandas as pd
import numpy as np
import tkinter as tk

import joblib
import time
import threading
import datetime
import json
import os
import csv
import netifaces

from collections import defaultdict, deque
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP

# Get the default gateway
gateways = netifaces.gateways()  
default_gateway = gateways.get('default', {})

# Constants
try:
    INTERFACE = default_gateway[netifaces.AF_INET][1]
except:
    raise Exception("Could not determine the default interface. Please specify the interface manually.")

TIME_WINDOW = 5
ACTIVITY_TIMEOUT = 2.0
CLEANUP_INTERVAL = 60
MODEL_PATH = '../ml_models/supervised/knn_model.joblib'
SCALER_PATH = '../ml_models/scalars/robust_scalar_supervised'

# Flow keys to whitelist (e.g., DHCP)
WHITELISTED_FLOWS = {
    "0.0.0.0:68-255.255.255.255:67-UDP",  # DHCP client to server
    "192.168.0.1:67-255.255.255.255:68-UDP",  # DHCP server to client
    # more as needed
}

class NetworkAnomalyDetector:
    def __init__(self, model_path, threshold=0.7):
        # Load the pre-trained XGBoost model
        with open(model_path, 'rb') as f:
            self.model = joblib.load(f)
        self.capture_running = False
        
        # Detection threshold
        self.threshold = threshold
        
        # Traffic statistics for feature extraction
        self.flow_stats = defaultdict(lambda: {
            'start_time': None,
            'end_time': None,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'fwd_packet_sizes': deque(maxlen=100),
            'bwd_packet_sizes': deque(maxlen=100),
            'packet_sizes': deque(maxlen=100),
            'fwd_iat': deque(maxlen=100),
            'bwd_iat': deque(maxlen=100),
            'flow_iat': deque(maxlen=100),
            'fwd_psh_flags': 0,
            'fwd_urg_flags': 0,
            'fin_flags': 0,
            'syn_flags': 0,
            'rst_flags': 0,
            'psh_flags': 0,
            'ack_flags': 0,
            'urg_flags': 0,
            'ece_flags': 0,
            'fwd_header_bytes': 0,
            'bwd_header_bytes': 0,
            'fwd_win_bytes': None,
            'bwd_win_bytes': None,
            'active_times': deque(maxlen=100),
            'idle_times': deque(maxlen=100),
            'last_active_time': None,
            'last_idle_time': None,
            'active_start': None,
            'idle_start': None,
            'last_packet_time': None,
            'last_fwd_packet_time': None,
            'last_bwd_packet_time': None,
            'min_seg_size_forward': float('inf'),
            'active': False,
            'fwd_data_packets': 0,
        })
        
        # Time window for flow aggregation (in seconds)
        self.time_window = TIME_WINDOW
        
        # Activity timeout (in seconds)
        self.activity_timeout = ACTIVITY_TIMEOUT
        
        # Alert system
        self.alerts = []
        self.alert_callback = None
        
        # Flow cache cleanup timer
        self.last_cleanup = time.time()
        self.cleanup_interval = CLEANUP_INTERVAL
        
        # Total packet count
        self.total_packets_processed = 0
    
    def set_alert_callback(self, callback):
        """Set callback function for alerts"""
        self.alert_callback = callback
    
    def process_packet(self, packet):
        """Process a single packet and update flow statistics"""
        if IP not in packet:
            return
        
        self.total_packets_processed += 1
        
        # Extract IP addresses
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Determine protocol and ports
        if TCP in packet:
            protocol = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            header_length = len(packet[TCP])
            
            # Extract window size
            if hasattr(packet[TCP], 'window'):
                window_size = packet[TCP].window
            else:
                window_size = 0
                
        elif UDP in packet:
            protocol = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            header_length = len(packet[UDP])
            window_size = 0
        else:
            # Skip non-TCP/UDP packets
            return
        
        # Create directional flow keys (src->dst and dst->src)
        forward_key = f"{ip_src}:{src_port}-{ip_dst}:{dst_port}-{protocol}"
        backward_key = f"{ip_dst}:{dst_port}-{ip_src}:{src_port}-{protocol}"
        
        # Determine flow direction
        packet_size = len(packet)
        current_time = time.time()
        is_forward = True
        
        # Check if this is part of an existing flow
        if forward_key in self.flow_stats:
            flow_key = forward_key
        elif backward_key in self.flow_stats:
            flow_key = backward_key
            is_forward = False
        else:
            # New flow, use forward key
            flow_key = forward_key
        
        # Get flow statistics
        flow = self.flow_stats[flow_key]
        
        # Initialize flow if this is the first packet
        if flow['start_time'] is None:
            flow['start_time'] = current_time
            flow['active_start'] = current_time
            flow['active'] = True
        
        # Update flow end time
        flow['end_time'] = current_time
        
        # Calculate and store inter-arrival time
        if flow['last_packet_time'] is not None:
            iat = current_time - flow['last_packet_time']
            flow['flow_iat'].append(iat)
            
            # Check if it is needed to update active/idle times
            if iat > self.activity_timeout:
                if flow['active_start'] is not None:
                    active_time = flow['last_packet_time'] - flow['active_start']
                    flow['active_times'].append(active_time)
                    flow['active_start'] = None
                    flow['idle_start'] = flow['last_packet_time']
                
                if flow['idle_start'] is not None:
                    idle_time = current_time - flow['idle_start']
                    flow['idle_times'].append(idle_time)
                    flow['idle_start'] = None
                
                flow['active_start'] = current_time
                flow['active'] = True
            
        flow['last_packet_time'] = current_time
        
        # Update direction-specific statistics
        if is_forward:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_size
            flow['packet_sizes'].append(packet_size)
            flow['fwd_packet_sizes'].append(packet_size)
            
            if protocol == 'TCP':
                if packet[TCP].flags & 0x08:  # PSH flag
                    flow['fwd_psh_flags'] += 1
                    flow['psh_flags'] += 1
                
                if packet[TCP].flags & 0x20:  # URG flag
                    flow['fwd_urg_flags'] += 1
                    flow['urg_flags'] += 1
                
                if hasattr(packet[TCP], 'flags'):
                    if packet[TCP].flags & 0x01:  # FIN flag
                        flow['fin_flags'] += 1
                    if packet[TCP].flags & 0x02:  # SYN flag
                        flow['syn_flags'] += 1
                    if packet[TCP].flags & 0x04:  # RST flag
                        flow['rst_flags'] += 1
                    if packet[TCP].flags & 0x10:  # ACK flag
                        flow['ack_flags'] += 1
                    if packet[TCP].flags & 0x40:  # ECE flag
                        flow['ece_flags'] += 1
                
                # Update min_seg_size_forward
                if hasattr(packet[TCP], 'options'):
                    mss = next((x[1] for x in packet[TCP].options if x[0] == 'MSS'), None)
                    if mss is not None and mss < flow['min_seg_size_forward']:
                        flow['min_seg_size_forward'] = mss
            
            flow['fwd_header_bytes'] += header_length
            
            # Store initial window size
            if flow['fwd_win_bytes'] is None and window_size > 0:
                flow['fwd_win_bytes'] = window_size
            
            # Check if this is a data packet
            if TCP in packet and len(packet[TCP].payload) > 0:
                flow['fwd_data_packets'] += 1
            
            # Update IAT for forward packets
            if flow['last_fwd_packet_time'] is not None:
                flow['fwd_iat'].append(current_time - flow['last_fwd_packet_time'])
            flow['last_fwd_packet_time'] = current_time
            
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_size
            flow['packet_sizes'].append(packet_size)
            flow['bwd_packet_sizes'].append(packet_size)
            flow['bwd_header_bytes'] += header_length
            
            # Store initial window size
            if flow['bwd_win_bytes'] is None and window_size > 0:
                flow['bwd_win_bytes'] = window_size
            
            # Update IAT for backward packets
            if flow['last_bwd_packet_time'] is not None:
                flow['bwd_iat'].append(current_time - flow['last_bwd_packet_time'])
            flow['last_bwd_packet_time'] = current_time
        
        # Check if it's time to perform detection
        if current_time - flow['start_time'] >= self.time_window:
            self.detect_anomalies(flow_key)
        
        # Periodically clean up old flows
        if current_time - self.last_cleanup > self.cleanup_interval:
            self.cleanup_old_flows()
            self.last_cleanup = current_time
    
    def extract_features(self, flow_key):
        """Extract features from flow statistics that match CICIDS2017 features"""
        flow = self.flow_stats[flow_key]
        
        # Skip flows with too few packets
        if flow['fwd_packets'] + flow['bwd_packets'] < 2:
            return None
        
        # Calculate flow duration
        duration = flow['end_time'] - flow['start_time']
        if duration <= 0:  # Avoid division by zero
            duration = 0.001
        
        # Initialize features dictionary
        features = {}
        
        # Get destination port from flow key
        parts = flow_key.split('-')
        if len(parts) >= 2:
            try:
                dst_part = parts[0].split(':')[1] if ':' in parts[0] else parts[1].split(':')[1]
                features['Destination Port'] = int(dst_part)
            except:
                features['Destination Port'] = 0
        else:
            features['Destination Port'] = 0
            
        # Basic flow features
        features['Flow Duration'] = duration * 1000  # Convert to milliseconds
        features['Flow Bytes/s'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / duration
        features['Flow Packets/s'] = (flow['fwd_packets'] + flow['bwd_packets']) / duration
        
        # Forward packet features
        features['Total Fwd Packets'] = flow['fwd_packets']
        features['Total Length of Fwd Packets'] = flow['fwd_bytes']
        features['Fwd Packet Length Min'] = min(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
        features['Fwd Packet Length Max'] = max(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
        features['Fwd Packet Length Mean'] = np.mean(flow['fwd_packet_sizes']) if flow['fwd_packet_sizes'] else 0
        features['Fwd Packet Length Std'] = np.std(flow['fwd_packet_sizes']) if len(flow['fwd_packet_sizes']) > 1 else 0
        features['Fwd Packets/s'] = flow['fwd_packets'] / duration
        features['Fwd Header Length'] = flow['fwd_header_bytes']
        
        # Backward packet features
        features['Bwd Packets/s'] = flow['bwd_packets'] / duration
        features['Bwd Packet Length Min'] = min(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
        features['Bwd Packet Length Max'] = max(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
        features['Bwd Packet Length Mean'] = np.mean(flow['bwd_packet_sizes']) if flow['bwd_packet_sizes'] else 0
        features['Bwd Packet Length Std'] = np.std(flow['bwd_packet_sizes']) if len(flow['bwd_packet_sizes']) > 1 else 0
        features['Bwd Header Length'] = flow['bwd_header_bytes']
        
        # Packet length features
        features['Min Packet Length'] = min(flow['packet_sizes']) if flow['packet_sizes'] else 0
        features['Max Packet Length'] = max(flow['packet_sizes']) if flow['packet_sizes'] else 0
        features['Packet Length Mean'] = np.mean(flow['packet_sizes']) if flow['packet_sizes'] else 0
        features['Packet Length Std'] = np.std(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
        features['Packet Length Variance'] = np.var(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
        
        # Average packet size
        total_packets = flow['fwd_packets'] + flow['bwd_packets']
        if total_packets > 0:
            features['Average Packet Size'] = (flow['fwd_bytes'] + flow['bwd_bytes']) / total_packets
        else:
            features['Average Packet Size'] = 0
        
        # IAT (Inter Arrival Time) features
        if flow['flow_iat']:
            features['Flow IAT Mean'] = np.mean(flow['flow_iat'])
            features['Flow IAT Std'] = np.std(flow['flow_iat']) if len(flow['flow_iat']) > 1 else 0
            features['Flow IAT Max'] = max(flow['flow_iat'])
            features['Flow IAT Min'] = min(flow['flow_iat'])
        else:
            features['Flow IAT Mean'] = 0
            features['Flow IAT Std'] = 0
            features['Flow IAT Max'] = 0
            features['Flow IAT Min'] = 0
        
        # Forward IAT
        if flow['fwd_iat']:
            features['Fwd IAT Total'] = sum(flow['fwd_iat'])
            features['Fwd IAT Mean'] = np.mean(flow['fwd_iat'])
            features['Fwd IAT Std'] = np.std(flow['fwd_iat']) if len(flow['fwd_iat']) > 1 else 0
            features['Fwd IAT Max'] = max(flow['fwd_iat'])
            features['Fwd IAT Min'] = min(flow['fwd_iat'])
        else:
            features['Fwd IAT Total'] = 0
            features['Fwd IAT Mean'] = 0
            features['Fwd IAT Std'] = 0
            features['Fwd IAT Max'] = 0
            features['Fwd IAT Min'] = 0
        
        # Backward IAT
        if flow['bwd_iat']:
            features['Bwd IAT Total'] = sum(flow['bwd_iat'])
            features['Bwd IAT Mean'] = np.mean(flow['bwd_iat'])
            features['Bwd IAT Std'] = np.std(flow['bwd_iat']) if len(flow['bwd_iat']) > 1 else 0
            features['Bwd IAT Max'] = max(flow['bwd_iat'])
            features['Bwd IAT Min'] = min(flow['bwd_iat'])
        else:
            features['Bwd IAT Total'] = 0
            features['Bwd IAT Mean'] = 0
            features['Bwd IAT Std'] = 0
            features['Bwd IAT Max'] = 0
            features['Bwd IAT Min'] = 0
        
        # Flag counts
        features['PSH Flag Count'] = flow['psh_flags']
        features['FIN Flag Count'] = flow['fin_flags']
        features['ACK Flag Count'] = flow['ack_flags']
        
        # Window features
        features['Init_Win_bytes_forward'] = flow['fwd_win_bytes'] if flow['fwd_win_bytes'] is not None else 0
        features['Init_Win_bytes_backward'] = flow['bwd_win_bytes'] if flow['bwd_win_bytes'] is not None else 0
        
        # Active and idle time statistics
        if flow['active_times']:
            features['Active Mean'] = np.mean(flow['active_times'])
            features['Active Max'] = max(flow['active_times'])
            features['Active Min'] = min(flow['active_times'])
        else:
            features['Active Mean'] = 0
            features['Active Max'] = 0
            features['Active Min'] = 0
        
        if flow['idle_times']:
            features['Idle Mean'] = np.mean(flow['idle_times'])
            features['Idle Max'] = max(flow['idle_times'])
            features['Idle Min'] = min(flow['idle_times'])
        else:
            features['Idle Mean'] = 0
            features['Idle Max'] = 0
            features['Idle Min'] = 0
        
        # Additional features
        features['min_seg_size_forward'] = flow['min_seg_size_forward'] if flow['min_seg_size_forward'] != float('inf') else 0
        features['act_data_pkt_fwd'] = flow['fwd_data_packets']
        
        # Calculate Subflow statistics
        features['Subflow Fwd Bytes'] = flow['fwd_bytes']
            
        return features
    
    def detect_anomalies(self, flow_key):
        """Detect anomalies in a flow using the XGBoost model"""
        if flow_key in WHITELISTED_FLOWS:
            return  # Skip whitelist flows

        features = self.extract_features(flow_key)
        if features is None:
            return
        
        # Create a DataFrame with the extracted features
        df = pd.DataFrame([features])
        
        # Make sure all required features are present
        required_features = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'Average Packet Size', 'Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Max', 'Idle Min'
        ]
        
        # Add missing features with default values
        for feature in required_features:
            if feature not in df.columns:
                df[feature] = 0
        
        # Select only the features needed by the model in the right order
        df = df[required_features]

        # Applying Robust Scaler to the features as they were scaled during training
        rb_scalar = joblib.load(SCALER_PATH)
        df = rb_scalar.transform(df)

        # Define class names for readability (according to the what was defined during training)
        class_names = ['Normal Traffic', 'DoS', 'DDoS', 'Port Scanning', 'Brute Force', 'Web Attacks', 'Bots']
        
        # Make prediction
        try:
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(df)
                # Get the predicted class index (highest probability)
                predicted_class_idx = np.argmax(probabilities[0])
                predicted_class = class_names[predicted_class_idx]
                confidence_score = probabilities[0][predicted_class_idx]
            
            # Option 2: If the KNN model doesn't return probabilities
            else:
                # Get the predicted class
                predicted_class_idx = self.model.predict(df)[0]
                predicted_class = class_names[predicted_class_idx]
                
                # For KNN without probabilities, we can estimate confidence based on neighbors
                if hasattr(self.model, 'kneighbors'):
                    # Get distances and indices of nearest neighbors
                    distances, indices = self.model.kneighbors(df)
                    
                    # Get the classes of the nearest neighbors
                    nearest_neighbor_classes = [self.model.classes_[i] for i in indices[0]]
                    
                    # Count how many neighbors agree with the prediction
                    matching_neighbors = sum(1 for c in nearest_neighbor_classes if c == predicted_class_idx)
                    
                    # Calculate confidence as the fraction of agreeing neighbors
                    confidence_score = matching_neighbors / len(nearest_neighbor_classes)
                else:
                    # Fallback if kneighbors method is not available
                    confidence_score = 1.0 if predicted_class != 'Normal Traffic' else 0.0
            
            # Check if the prediction is anything other than Normal Traffic and above the threshold
            if predicted_class != 'Normal Traffic' and confidence_score >= self.threshold:
                ip_src, port_src = flow_key.split('-')[0].split(':')
                ip_dst, port_dst = flow_key.split('-')[1].split(':')
                protocol = flow_key.split('-')[2] if len(flow_key.split('-')) > 2 else "Unknown"
                
                alert = {
                    'flow': flow_key,
                    'attack_type': predicted_class,
                    'confidence': float(confidence_score),
                    'timestamp': datetime.datetime.now().isoformat(),
                    'src': f"{ip_src}:{port_src}",
                    'dst': f"{ip_dst}:{port_dst}",
                    'protocol': protocol,
                    'details': f"{predicted_class} detected in flow {ip_src}:{port_src} -> {ip_dst}:{port_dst} [{protocol}] with confidence {confidence_score:.4f}"
                }
                self.alerts.append(alert)
                
                # Call the alert callback if set
                if self.alert_callback:
                    self.alert_callback(alert)
        
        except Exception as e:
            print(f"Error in anomaly detection: {e}")

        
        # Reset flow statistics after detection
        self.flow_stats[flow_key] = {
            'start_time': time.time(),
            'end_time': None,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'fwd_packet_sizes': deque(maxlen=100),
            'bwd_packet_sizes': deque(maxlen=100),
            'packet_sizes': deque(maxlen=100),
            'fwd_iat': deque(maxlen=100),
            'bwd_iat': deque(maxlen=100),
            'flow_iat': deque(maxlen=100),
            'fwd_psh_flags': 0,
            'fwd_urg_flags': 0,
            'fin_flags': 0,
            'syn_flags': 0,
            'rst_flags': 0,
            'psh_flags': 0,
            'ack_flags': 0,
            'urg_flags': 0,
            'ece_flags': 0,
            'fwd_header_bytes': 0,
            'bwd_header_bytes': 0,
            'fwd_win_bytes': None,
            'bwd_win_bytes': None,
            'active_times': deque(maxlen=100),
            'idle_times': deque(maxlen=100),
            'last_active_time': None,
            'last_idle_time': None,
            'active_start': None,
            'idle_start': None,
            'last_packet_time': None,
            'last_fwd_packet_time': None,
            'last_bwd_packet_time': None,
            'min_seg_size_forward': float('inf'),
            'active': False,
            'fwd_data_packets': 0,
        }
    
    def cleanup_old_flows(self):
        """Remove flows that have been inactive for too long"""
        current_time = time.time()
        to_remove = []
        
        for flow_key, flow in self.flow_stats.items():
            if flow['last_packet_time'] is not None and current_time - flow['last_packet_time'] > self.cleanup_interval:
                self.detect_anomalies(flow_key)
                to_remove.append(flow_key)
        
        for flow_key in to_remove:
            del self.flow_stats[flow_key]
    
    def start_capture(self, interface=None, filter=None):
        """Start packet capture in a separate thread"""
        self.capture_running = True
        def capture_thread():
            try:
                while self.capture_running:
                    sniff(
                        iface=interface,
                        filter=filter,
                        prn=self.process_packet,
                        store=0,
                        timeout=1,  # Sniff in short increments
                        stop_filter=lambda x: not self.capture_running
                    )
            except Exception as e:
                print(f"Capture error: {e}")
            finally:
                self.capture_running = False # Reset
        
        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()
        return thread

    def get_total_packets(self):
        """Get the total number of packets processed"""
        return self.total_packets_processed

class NetworkAnomalyGUI:
    def __init__(self, detector):
        self.detector = detector
        self.root = tk.Tk()
        self.root.title("Network Anomaly Detection")
        self.root.geometry("800x600")
        
        self.setup_ui()
        
        # Set the alert callback
        self.detector.set_alert_callback(self.add_alert)
    
    def setup_ui(self):
        # Control frame
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Interface selection
        tk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_var = tk.StringVar(value=INTERFACE)
        interface_entry = tk.Entry(control_frame, textvariable=self.interface_var, width=10)
        interface_entry.pack(side=tk.LEFT, padx=5)
        
        # Filter
        tk.Label(control_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        filter_entry = tk.Entry(control_frame, textvariable=self.filter_var, width=20)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        # Threshold
        tk.Label(control_frame, text="Threshold:").pack(side=tk.LEFT, padx=5)
        self.threshold_var = tk.DoubleVar(value=0.7)
        threshold_entry = tk.Entry(control_frame, textvariable=self.threshold_var, width=5)
        threshold_entry.pack(side=tk.LEFT, padx=5)
        
        # Start/Stop button
        self.running = False
        self.start_stop_btn = tk.Button(control_frame, text="Start", command=self.toggle_capture)
        self.start_stop_btn.pack(side=tk.LEFT, padx=20)
        
        # Clear button
        tk.Button(control_frame, text="Clear Alerts", command=self.clear_alerts).pack(side=tk.LEFT, padx=5)
        
        # Alert log
        tk.Label(self.root, text="Anomaly Detection Alerts:").pack(anchor=tk.W, padx=10, pady=5)
        self.alert_log = scrolledtext.ScrolledText(self.root, height=20)
        self.alert_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Statistics frame
        stats_frame = tk.Frame(self.root)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(stats_frame, text="Packets Processed:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.packets_var = tk.StringVar(value="0")
        tk.Label(stats_frame, textvariable=self.packets_var).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        tk.Label(stats_frame, text="Alerts Generated:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.alerts_var = tk.StringVar(value="0")
        tk.Label(stats_frame, textvariable=self.alerts_var).grid(row=0, column=3, sticky=tk.W, padx=5)
        
        # Start statistics update
        self.update_statistics()
    
    def toggle_capture(self):
        if not self.running:
            # Update threshold
            self.detector.threshold = self.threshold_var.get()
            
            # Start capture
            interface = self.interface_var.get() if self.interface_var.get() else None
            filter_str = self.filter_var.get() if self.filter_var.get() else None
            
            try:
                self.capture_thread = self.detector.start_capture(interface=interface, filter=filter_str)
                self.running = True
                self.start_stop_btn.config(text="Stop")
                self.status_var.set(f"Capturing on {interface or 'default interface'}")
                self.add_log_message(f"Started capture on {interface or 'default interface'}")
            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")
        else:
            self.detector.capture_running = False # Set flag to stop.
            self.running = False
            self.start_stop_btn.config(text="Start")
            self.status_var.set("Capture stopped")
            self.add_log_message("Stopped capture")
    
    def add_alert(self, alert):
        """Add an alert to the log and write to a JSON file."""
        # Format timestamp for display
        timestamp = alert.get('timestamp', datetime.datetime.now().isoformat())
        
        # Get the Atomic Red Team test ID if available
        test_id = os.environ.get("ATOMIC_RED_TEAM_TEST", "unknown")
        
        # Add additional context to the alert
        alert["test_id"] = test_id
        alert["detection_time"] = datetime.datetime.now().isoformat()
        
        # Calculate detection latency if we have attack start time in env var
        attack_start_time = os.environ.get("ATTACK_START_TIME")
        if attack_start_time:
            try:
                start = datetime.datetime.fromisoformat(attack_start_time)
                now = datetime.datetime.now()
                alert["detection_latency_seconds"] = (now - start).total_seconds()
            except (ValueError, TypeError):
                alert["detection_latency_seconds"] = None
        
        # Format alert for display
        alert_text = f"[{timestamp}] {alert['details']}\n"
        self.alert_log.insert(tk.END, alert_text)
        self.alert_log.see(tk.END)
        
        # Update alert count
        self.alerts_var.set(str(len(self.detector.alerts)))

        # Ensure the alerts directory exists
        os.makedirs("nids_alerts", exist_ok=True)
        
        # Use a daily log file for better organization
        log_date = datetime.datetime.now().strftime("%Y-%m-%d")
        log_file = os.path.join("nids_alerts", f"nids_alerts_{log_date}.jsonl")
        
        try:
            with open(log_file, "a") as f:  # "a" for append mode
                json.dump(alert, f)
                f.write("\n")  # Add newline for JSONL format
        except Exception as e:
            print(f"Error writing alert to JSON file: {e}")
            
        # Also log to a consolidated CSV for easier analysis
        try:
            csv_file = os.path.join("nids_alerts", "nids_alerts.csv")
            csv_exists = os.path.exists(csv_file)
            
            with open(csv_file, "a", newline='') as csvfile:
                fieldnames = ["timestamp", "attack_type", "confidence", "src", "dst", 
                            "protocol", "test_id", "detection_latency_seconds"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                
                if not csv_exists:
                    writer.writeheader()
                
                writer.writerow({k: alert.get(k) for k in fieldnames})
        except Exception as e:
            print(f"Error writing to CSV file: {e}")
    
    def add_log_message(self, message):
        """Add a regular log message to the alert log"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_text = f"[{timestamp}] {message}\n"
        self.alert_log.insert(tk.END, log_text)
        self.alert_log.see(tk.END)
    
    def clear_alerts(self):
        """Clear the alert log"""
        self.alert_log.delete(1.0, tk.END)
        self.detector.alerts = []
        self.alerts_var.set("0")
    
    def update_statistics(self):
        """Update statistics periodically"""
        if self.running:
            # Count total packets processed
            total_packets = self.detector.get_total_packets()
            self.packets_var.set(str(total_packets))
        
        # Schedule next update
        self.root.after(1000, self.update_statistics)
    
    def run(self):
        """Run the GUI main loop"""
        self.root.mainloop()

def main():
    # Path to the pre-trained XGBoost model
    model_path = MODEL_PATH
    
    # Create detector and GUI
    detector = NetworkAnomalyDetector(model_path)
    gui = NetworkAnomalyGUI(detector)
    
    # Run the application
    gui.run()

if __name__ == "__main__":
    main()
