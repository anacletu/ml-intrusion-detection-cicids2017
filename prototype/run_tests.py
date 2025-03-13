import subprocess
import time
import datetime
import json
import os
import argparse
import random
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("nids_test.log"),
        logging.StreamHandler()
    ]
)

# Define attack categories and their associated technique IDs
ATTACK_TECHNIQUES = {
    "bots": [
        "T1059.003",  # Windows Command Shell
        "T1059.001",  # PowerShell
        "T1071.001",  # Web Protocols
        "T1105",      # Ingress Tool Transfer
    ],
    "port_scanning": [
        "T1046",      # Network Service Scanning
        "T1595.001",  # Active Scanning: Scanning IP Blocks
        "T1595.002",  # Active Scanning: Vulnerability Scanning
    ],
    "web_attacks": [
        "T1190",      # Exploit Public-Facing Application
        "T1210",      # Exploitation of Remote Services
        "T1203",      # Exploitation for Client Execution
        "T1059.007",  # JavaScript
    ],
    "brute_force": [
        "T1110.001",  # Brute Force: Password Guessing
        "T1110.002",  # Brute Force: Password Cracking
        "T1110.003",  # Brute Force: Password Spraying
        "T1110.004",  # Brute Force: Credential Stuffing
    ],
    "dos": [
        "T1498.001",  # Network Denial of Service: Direct Network Flood
        "T1499.001",  # Endpoint Denial of Service: OS Exhaustion Flood
        "T1499.002",  # Endpoint Denial of Service: Service Exhaustion Flood
    ],
    "ddos": [
        "T1498.002",  # Network Denial of Service: Reflection Amplification
        "T1498.001",  # Network Denial of Service: Direct Network Flood (with multiple sources)
    ]
}

class AtomicRedTeamTester:
    def __init__(self, output_dir="nids_test_results", delay_between_tests=60, randomize=False):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.delay_between_tests = delay_between_tests
        self.randomize = randomize
        self.results = {}
        
    def run_test(self, technique_id, test_number=None):
        """Run a specific Atomic Red Team test"""
        start_time = datetime.datetime.now()
        start_time_iso = start_time.isoformat()
        os.environ["ATTACK_START_TIME"] = start_time_iso
        
        test_command = ["invoke-atomic", "test", technique_id]
        if test_number is not None:
            test_command.extend(["-TestNumbers", str(test_number)])
            
        technique_name = self._get_technique_name(technique_id)
        logging.info(f"Running test: {technique_id} ({technique_name})")
        
        os.environ["ATOMIC_RED_TEAM_TEST"] = technique_id
        
        try:
            start_time = datetime.datetime.now()
            start_time_iso = start_time.isoformat()
            
            proc = subprocess.run(
                test_command,
                capture_output=True,
                text=True,
                timeout=300  # 5-minute timeout
            )
            
            end_time = datetime.datetime.now()
            end_time_iso = end_time.isoformat()
            duration_seconds = (end_time - start_time).total_seconds()
            
            result = {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "test_number": test_number,
                "start_time": start_time_iso,
                "end_time": end_time_iso,
                "duration_seconds": duration_seconds,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "returncode": proc.returncode,
                "success": proc.returncode == 0
            }
            
            logging.info(f"Test completed: {technique_id} (Success: {result['success']})")
            return result
            
        except subprocess.TimeoutExpired:
            end_time = datetime.datetime.now()
            logging.warning(f"Test timed out: {technique_id}")
            return {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "test_number": test_number,
                "start_time": start_time_iso,
                "end_time": end_time.isoformat(),
                "duration_seconds": 300,  # timeout value
                "error": "Test timed out after 5 minutes",
                "success": False
            }
        except Exception as e:
            end_time = datetime.datetime.now()
            logging.error(f"Test error for {technique_id}: {str(e)}")
            return {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "test_number": test_number,
                "start_time": start_time_iso,
                "end_time": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds(),
                "error": str(e),
                "success": False
            }
        finally:
            if "ATOMIC_RED_TEAM_TEST" in os.environ:
                del os.environ["ATOMIC_RED_TEAM_TEST"]
    
    def _get_technique_name(self, technique_id):
        """Get a more readable name for the technique ID"""
        # This is a simplified mapping - in a real implementation you might 
        # want to fetch this from the MITRE ATT&CK database or Atomic Red Team repo
        technique_names = {
            "T1059.001": "PowerShell",
            "T1059.003": "Windows Command Shell",
            "T1046": "Network Service Scanning",
            "T1110.001": "Password Guessing",
            "T1110.002": "Password Cracking",
            "T1498.001": "Direct Network Flood",
            # Add more mappings as needed
        }
        return technique_names.get(technique_id, "Unknown Technique")
    
    def run_attack_category(self, category):
        """Run all tests in a specific attack category"""
        if category not in ATTACK_TECHNIQUES:
            logging.error(f"Unknown attack category: {category}")
            return []
            
        techniques = ATTACK_TECHNIQUES[category]
        if self.randomize:
            random.shuffle(techniques)
            
        category_results = []
        logging.info(f"Starting tests for category: {category}")
        
        for technique_id in techniques:
            result = self.run_test(technique_id)
            category_results.append(result)
            
            # Save intermediate results
            self._save_results(category, category_results)
            
            # Wait between tests
            if self.delay_between_tests > 0 and techniques.index(technique_id) < len(techniques) - 1:
                logging.info(f"Waiting {self.delay_between_tests} seconds before next test...")
                time.sleep(self.delay_between_tests)
                
        return category_results
    
    def run_all_attacks(self):
        """Run all attack categories"""
        categories = list(ATTACK_TECHNIQUES.keys())
        if self.randomize:
            random.shuffle(categories)
            
        for category in categories:
            logging.info(f"Starting attack category: {category}")
            results = self.run_attack_category(category)
            self.results[category] = results
            
            # Wait between categories
            if categories.index(category) < len(categories) - 1:
                wait_time = self.delay_between_tests * 2  # longer wait between categories
                logging.info(f"Waiting {wait_time} seconds before next category...")
                time.sleep(wait_time)
                
        self._save_final_report()
        return self.results
    
    def _save_results(self, category, results):
        """Save intermediate results for a category"""
        output_file = self.output_dir / f"{category}_results.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
            
    def _save_final_report(self):
        """Save the final comprehensive report"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"nids_test_report_{timestamp}.json"
        
        report = {
            "timestamp": timestamp,
            "total_tests": sum(len(results) for results in self.results.values()),
            "successful_tests": sum(
                sum(1 for test in category if test.get("success", False))
                for category, category_tests in self.results.items()
            ),
            "results_by_category": self.results
        }
        
        with open(report_file, "w") as f:
            json.dump(report, f, indent=4)
            
        logging.info(f"Final report saved to {report_file}")

def parse_args():
    parser = argparse.ArgumentParser(description="NIDS Testing Framework using Atomic Red Team")
    parser.add_argument("--category", "-c", choices=list(ATTACK_TECHNIQUES.keys()) + ["all"], 
                        default="all", help="Attack category to test")
    parser.add_argument("--delay", "-d", type=int, default=60,
                        help="Delay in seconds between tests")
    parser.add_argument("--output", "-o", default="nids_test_results",
                        help="Output directory for test results")
    parser.add_argument("--randomize", "-r", action="store_true",
                        help="Randomize the order of tests")
    return parser.parse_args()

def main():
    args = parse_args()
    
    logging.info("Starting NIDS Testing Framework")
    logging.info(f"Configuration: category={args.category}, delay={args.delay}s, "
                 f"output={args.output}, randomize={args.randomize}")
    
    tester = AtomicRedTeamTester(
        output_dir=args.output,
        delay_between_tests=args.delay,
        randomize=args.randomize
    )
    
    if args.category == "all":
        tester.run_all_attacks()
    else:
        tester.run_attack_category(args.category)
    
    logging.info("NIDS Testing Framework completed")

if __name__ == "__main__":
    main()