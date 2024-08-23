import subprocess
import re
import os
import json
import xmltodict
from tinydb import TinyDB, Query
from datetime import datetime



global NMAP_SCANS

NMAP_SCANS = {
    "quick_scan": {
        "description": "Quick scan of top 1000 ports",
        "args": ["--top-ports", "1000"]
    },
    "detailed_scan": {
        "description": "Detailed scan with version detection and default scripts",
        "args": ["-sC", "-sV", "--top-ports", "1000"]
    }
}


# -----( NMAP SCAN FUNCTIONS )--------------------------------------------

def run_nmap_scan(info_dict, scan_type):
    if not validate_scan_type(scan_type):
        return None, f"Unknown scan type: {scan_type}"
    
    output_prefix = prepare_output_directory(info_dict, scan_type)
    
    if should_use_existing_results(info_dict, output_prefix):
        print(f"Nmap {scan_type} results already exist for {output_prefix}. Processing existing results.")
        return process_nmap_output(output_prefix)

    nmap_command = prepare_nmap_command(info_dict, scan_type, output_prefix)
    
    try:
        execute_nmap_scan(nmap_command)
        return process_nmap_output(output_prefix)
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap {scan_type}: {e}")
        print(f"Nmap error output: {e.stderr}")
        return None, str(e)

def validate_scan_type(scan_type):
    if scan_type not in NMAP_SCANS:
        print(f"Error: Unknown scan type '{scan_type}'")
        return False
    return True

def prepare_output_directory(info_dict, scan_type):
    working_dir = info_dict["working_dir"]
    hostname = info_dict["hostname"]
    ip = info_dict["ip"]
    
    output_dir = os.path.join(working_dir, hostname)
    os.makedirs(output_dir, exist_ok=True)
    return os.path.join(output_dir, f"nmap_{scan_type}_{ip.replace('.', '_')}")

def should_use_existing_results(info_dict, output_prefix):
    force = info_dict.get("force", False)
    return not force and all(os.path.exists(f"{output_prefix}.{ext}") for ext in ["nmap", "gnmap", "xml"])

def prepare_nmap_command(info_dict, scan_type, output_prefix):
    ip = info_dict["ip"]
    return ["nmap", "-oA", output_prefix] + NMAP_SCANS[scan_type]["args"] + [ip]

def execute_nmap_scan(nmap_command):
    result = subprocess.run(nmap_command, check=True, capture_output=True, text=True)
    print(f"Nmap command executed: {' '.join(nmap_command)}")
    print(f"Nmap output: {result.stdout}")

def process_nmap_output(output_prefix):
    xml_file = f"{output_prefix}.xml"
    if not os.path.exists(xml_file):
        return None, "XML output file not found"

    json_data = nmap_xml_to_json(xml_file)
    nmap_dict = json.loads(json_data)

    # Extract relevant information from nmap_dict
    # This is a simplified example; adjust according to your needs
    scan_result = nmap_dict.get('nmaprun', {}).get('host', {}).get('ports', {}).get('port', [])
    
    open_ports = []
    if isinstance(scan_result, list):
        for port in scan_result:
            if port.get('state', {}).get('@state') == 'open':
                open_ports.append({
                    'port_number': int(port.get('@portid')),
                    'protocol': port.get('@protocol'),
                    'service': port.get('service', {}).get('@name'),
                    'version': port.get('service', {}).get('@version', 'Unknown')
                })
    elif isinstance(scan_result, dict):
        if scan_result.get('state', {}).get('@state') == 'open':
            open_ports.append({
                'port_number': int(scan_result.get('@portid')),
                'protocol': scan_result.get('@protocol'),
                'service': scan_result.get('service', {}).get('@name'),
                'version': scan_result.get('service', {}).get('@version', 'Unknown')
            })

    return open_ports, None

# -----( UTILITY FUNCTIONS )--------------------------------------------

def nmap_xml_to_json(xml_file_path):
    # Read the XML file
    with open(xml_file_path, 'r') as xml_file:
        xml_content = xml_file.read()
    
    # Parse XML to dictionary
    nmap_dict = xmltodict.parse(xml_content)
    
    # Convert dictionary to JSON
    json_data = json.dumps(nmap_dict, indent=4)
    
    # Save JSON to file
    json_file_path = os.path.splitext(xml_file_path)[0] + '.json'
    with open(json_file_path, 'w') as json_file:
        json_file.write(json_data)
    
    return json_data

def update_db_with_nmap_results(db, hostname, scan_type, open_ports):
    Target = Query()
    existing_record = db.get(Target.hostname == hostname)
    
    if existing_record:
        if 'nmap_scans' not in existing_record:
            existing_record['nmap_scans'] = {}
        
        existing_record['nmap_scans'][scan_type] = {
            'timestamp': datetime.now().isoformat(),
            'open_ports': open_ports
        }
        
        # Update the top-level open_ports list
        if 'open_ports' not in existing_record:
            existing_record['open_ports'] = []
        
        # Merge new open ports with existing ones, avoiding duplicates
        existing_ports = {(port['port_number'], port['protocol']): port for port in existing_record['open_ports']}
        for new_port in open_ports:
            key = (new_port['port_number'], new_port['protocol'])
            if key not in existing_ports or existing_ports[key]['state'] != 'open':
                existing_ports[key] = new_port
        
        existing_record['open_ports'] = list(existing_ports.values())
        
        db.update(existing_record, Target.hostname == hostname)
    else:
        print(f"Error: No record found for hostname {hostname}")



