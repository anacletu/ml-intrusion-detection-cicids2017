import time
import os
import psutil
import threading
import logging
import subprocess
import pandas as pd
import netifaces

# Setup logging
# Ensure the logs directory exists
logs_directory = "logs"
if not os.path.exists(logs_directory):
    os.makedirs(logs_directory)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(logs_directory, "pcap_test_results.txt")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NIDS-Resource-Monitor")

# NIDS Script Configurations
NIDS_CONFIGS = {
    "knn": {
        "script_path": "../nids_prototype_knn.py",
    },
    "xgboost": {
        "script_path": "../nids_prototype_xgboost.py",
    }
}

# List of PCAP files
# Monday is excluded as it only contains benign traffic
PCAP_FILES = [
    "../../pcaps/cicids2017/Friday-WorkingHours.pcap",
    "../../pcaps/cicids2017/Thursday-WorkingHours.pcap",
    "../../pcaps/cicids2017/Wednesday-workingHours.pcap",
    "../../pcaps/cicids2017/Tuesday-WorkingHours.pcap",
]

# Automatically get the default network interface
INTERFACE = netifaces.gateways()['default'][netifaces.AF_INET][1]
logger.info(f"Using default network interface: {INTERFACE}")

class ResourceMonitor:
    def __init__(self, nids_type, process):
        self.nids_type = nids_type
        self.process = process
        self.cpu_usage = []
        self.memory_usage = []
        self.monitor_thread = None
        self.stop_monitoring = False

    def _monitor_resources(self):
        """Continuously monitor CPU and memory resources for the specific process"""
        while not self.stop_monitoring:
            try:
                # Check if process is still running
                if not self.process.is_running():
                    break

                # CPU usage for the specific process
                cpu_percent = self.process.cpu_percent(interval=1)
                self.cpu_usage.append(cpu_percent)

                # Memory usage 
                memory_info = self.process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)  # Convert to MB
                self.memory_usage.append(memory_mb)

                time.sleep(1)
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
                break

    def start(self):
        """Start resource monitoring"""
        self.stop_monitoring = False
        self.monitor_thread = threading.Thread(target=self._monitor_resources)
        self.monitor_thread.start()

    def stop(self):
        """Stop resource monitoring and log results"""
        self.stop_monitoring = True
        if self.monitor_thread:
            self.monitor_thread.join()

        # Calculate and log resource statistics
        if self.cpu_usage and self.memory_usage:
            logger.info(f"Resource Usage for {self.nids_type} NIDS:")
            logger.info(f"  Average CPU Usage: {sum(self.cpu_usage)/len(self.cpu_usage):.2f}%")
            logger.info(f"  Peak CPU Usage: {max(self.cpu_usage):.2f}%")
            logger.info(f"  Average Memory Usage: {sum(self.memory_usage)/len(self.memory_usage):.2f} MB")
            logger.info(f"  Peak Memory Usage: {max(self.memory_usage):.2f} MB")

            # Write detailed results to a CSV
            results_df = pd.DataFrame({
            'CPU_Usage': self.cpu_usage,
            'Memory_Usage_MB': self.memory_usage
            })
            results_df.to_csv(os.path.join(logs_directory, f"{self.nids_type}_resource_log.csv"), index=False)

def run_nids_with_resource_monitoring(nids_type, config, pcap_path, interface, speed=1):
    """
    Run a specific NIDS script with comprehensive resource monitoring
    
    Args:
        nids_type (str): Type of NIDS (knn, xgboost)
        config (dict): NIDS configuration
        pcap_path (str): Path to pcap file to replay
        interface (str): Network interface to use
        speed (float, optional): Replay speed. Defaults to 1.
    """
    try:
        # Prepare NIDS script command
        nids_cmd = [
            "sudo",
            "python3", 
            config["script_path"]
        ]
        
        logger.info(f"Running {nids_type} NIDS: {' '.join(nids_cmd)}")
        
        # Start NIDS script
        nids_process = subprocess.Popen(nids_cmd)
        
        # Create psutil process object for monitoring
        psutil_process = psutil.Process(nids_process.pid)
        
        # Start resource monitoring
        resource_monitor = ResourceMonitor(nids_type, psutil_process)
        resource_monitor.start()
        
        # Wait for NIDS process to complete
        nids_process.wait()
        
        # Stop resource monitoring
        resource_monitor.stop()
        
        logger.info(f"{nids_type} NIDS execution completed")
        
    except Exception as e:
        logger.error(f"Error in {nids_type} NIDS execution: {e}")

def run_tcpreplay(pcap_path, interface, speed=1):
    """
    Run tcpreplay to replay the PCAP file
    
    Args:
        pcap_path (str): Path to PCAP file
        interface (str): Network interface to use
        speed (float, optional): Replay speed multiplier
    """
    try:
        logger.info(f"Running tcpreplay for {pcap_path}")
        cmd = ["sudo", "tcpreplay", "-i", interface, f"--multiplier={speed}", pcap_path]
        
        subprocess.run(cmd, check=True, timeout=60)  # 60-second timeout
        logger.info("Tcpreplay completed successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Tcpreplay error: {e}")
    except subprocess.TimeoutExpired:
        logger.warning("Tcpreplay timed out")

def main():
    # Start NIDS processes first
    nids_processes = []
    
    # Start NIDS processes once (monitoring the network interface)
    for nids_type in NIDS_CONFIGS.keys():
        logger.info(f"Starting {nids_type} NIDS to monitor the interface.")
        
        # Start the NIDS script in a subprocess (run once, monitor en0)
        nids_process = subprocess.Popen([
            "sudo", "python3", NIDS_CONFIGS[nids_type]["script_path"]
        ])
        nids_processes.append(nids_process)
    
    # Run tests for each PCAP file sequentially
    for pcap_path in PCAP_FILES:
        logger.info(f"Replaying PCAP: {pcap_path}")
        
        time.sleep(5)  # Allow some time for NIDS to start (click the interface for starting)

        # Run tcpreplay for this PCAP file on the network interface
        run_tcpreplay(pcap_path, INTERFACE)

    # Wait for all NIDS processes to complete (if needed)
    for nids_process in nids_processes:
        nids_process.wait()

    logger.info("Testing completed")


if __name__ == "__main__":
    main()
