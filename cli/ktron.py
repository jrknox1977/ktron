#!/usr/bin/env python3

# AUTHOR: KNOX (Joshua Knox)
# DATE: 2024-08

import argparse
import json
import os
import shutil
import colorama
import requests
from colorama import Fore, Style
from tinydb import TinyDB, Query
from datetime import datetime
from dotenv import load_dotenv

class KTRON:
    def __init__(self):
        colorama.init()  # Initialize colorama
        load_dotenv()
        self.api_url = "http://localhost:5000"
        self.working_dir = self.load_working_dir_from_env()
        self.info_dict = None
        self.target_ip = None
        self.hostname = None
        self.force = False
        self.args = None
        self.db = None
        self.run()

# -----( INIT FUNCTIONS )--------------------------------------------

    def run(self):
        self.display_banner()
        self.ktron_init()
        self.print_feedback()
        self.basic_recon()

    def ktron_init(self):
        self.parse_arguments()
        self.set_target_info()
        self.create_working_dir()
        self.init_database()
        self.check_required_tools()
        self.init_info_dict()
        self.save_info_dict()

    @staticmethod
    def display_banner():
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        banner = f"""{Fore.GREEN}
     _     _ _______ ______ _______ _______ 
    (_)   | (_______|_____ (_______|_______)
     _____| |   _    _____) )     _ _     _ 
    |  _   _)  | |  |  __  / |   | | |   | |
    | |  \ \   | |  | |  \ \ |___| | |   | |
    |_|   \_)  |_|  |_|   |_\_____/|_|   |_|

            Recon Tool - By Joshua Knox
    {Style.RESET_ALL}"""
        
        print(banner, flush=True)
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description="CTF Recon Tool")
        parser.add_argument("-i", "--ip", required=True, help="Target IP address")
        parser.add_argument("-n", "--hostname", required=True, help="Target hostname")
        parser.add_argument("-f", "--force", action="store_true", help="Force rerun of all tools")
        self.args = parser.parse_args()

    def set_target_info(self):
        self.target_ip = self.args.ip
        self.hostname = self.args.hostname
        self.force = self.args.force

    def init_database(self):
        db_dir = os.path.join(self.working_dir, self.hostname)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        db_path = os.path.join(db_dir, f"{self.hostname}_tinydb.json")
        self.db = TinyDB(db_path)
        print(f"{Fore.GREEN}TinyDB initialized at {Fore.CYAN}{db_path}{Style.RESET_ALL}")

    @staticmethod
    def check_tool_installed(tool_name, install_instructions):
        if shutil.which(tool_name) is None:
            print(f"{tool_name} is not installed. {tool_name} scan will run in the background instead.")
            print(f"To install {tool_name}, you can use one of the following commands:")
            for instruction in install_instructions:
                print(f"  {instruction}")
            return False
        else:
            print(f"{Fore.GREEN}{tool_name} is installed.{Style.RESET_ALL}")
        return True

    def check_required_tools(self):
        self.check_tool_installed("terminator", [
            "For Ubuntu/Debian: sudo apt-get install terminator",
            "For Fedora: sudo dnf install terminator",
            "For Arch Linux: sudo pacman -S terminator"
        ])
        self.check_tool_installed("gobuster", [
            "For Ubuntu/Debian/Kali: sudo apt-get install gobuster",
            "For Fedora: sudo dnf install gobuster",
            "For Arch Linux: sudo pacman -S gobuster"
        ])

    def init_info_dict(self):
        self.info_dict = {
            "working_dir": self.working_dir,
            "hostname": self.hostname,
            "ip": self.target_ip,
            "force": self.force,
            "recon_date": datetime.now().isoformat(),
            "tools": {}
        }
        self.db.insert(self.info_dict)

    def print_feedback(self):
        print("\n" + "="*50)
        print(f"{Fore.YELLOW}Working directory:{Style.RESET_ALL} {self.working_dir}")
        print(f"{Fore.YELLOW}Hostname:{Style.RESET_ALL} {self.hostname}")
        print(f"{Fore.YELLOW}IP:{Style.RESET_ALL} {self.target_ip}")
        print(f"{Fore.YELLOW}Force:{Style.RESET_ALL} {self.force}")
        print(f"{Fore.YELLOW}Database:{Style.RESET_ALL} {self.hostname}_tinydb.json")
        print("="*50 + "\n")


# -----( UTILITY FUNCTIONS )--------------------------------------------

    def save_info_dict(self):
        Target = Query()
        self.db.update(self.info_dict, Target.hostname == self.hostname)
        print(f"{Fore.GREEN}Reconnaissance information updated in TinyDB{Style.RESET_ALL}")
        
    def load_working_dir_from_env(self):
        return os.getenv("WORKING_DIR")

    def create_working_dir(self):
        target_dir = os.path.join(self.working_dir, self.hostname)
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        print(f"{Fore.GREEN}Working directory created: {Fore.CYAN}{target_dir}{Style.RESET_ALL}")

    def api_request(self, endpoint, params):
        url = f"{self.api_url}/{endpoint}"
        try:
            response = requests.post(url, json=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while making the request: {e}")
        except json.JSONDecodeError:
            print("Error: Received invalid JSON response")
        return None

# -----( RECON FUNCTIONS )--------------------------------------------
    def basic_recon(self):
        print(f"{Fore.YELLOW}Starting basic reconnaissance...{Style.RESET_ALL}")
        self.perform_nmap_quick_scan()
        # Add more recon steps here in the future

    def perform_nmap_quick_scan(self):
        print(f"{Fore.YELLOW}Kicking off NMAP quick scan...{Style.RESET_ALL}")
        scan_params = {
            "info_dict": self.info_dict,
            "scan_type": "quick_scan"
        }
        self.quick_scan_info = self.api_request("perform_nmap_scan", scan_params)
        if self.quick_scan_info is None:
            print("Failed to perform Nmap scan. Exiting.")
            return
        self.display_nmap_results()

    def display_nmap_results(self):
        print(f"{Fore.GREEN}Nmap scan completed successfully{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Nmap scan results:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}+------------+-----------+---------+-----------+")
        print(f"| {'Port':^10} | {'Protocol':^9} | {'Service':^7} | {'Version':^9} |")
        print(f"+------------+-----------+---------+-----------+")
        for port_info in self.quick_scan_info:
            print(f"| {port_info['port_number']:^10} | {port_info['protocol']:^9} | {port_info['service']:^7} | {port_info['version']:^9} |")
        print(f"+------------+-----------+---------+-----------+{Style.RESET_ALL}")


if __name__ == "__main__":
    ktron = KTRON()