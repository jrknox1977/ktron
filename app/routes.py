from flask import Blueprint, render_template, jsonify
from app.tools import run_nmap_scan
import json
from flask import request

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/perform_nmap_scan', methods=['POST'])
def perform_nmap_scan():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        info_dict = data.get('info_dict')
        scan_type = data.get('scan_type')
        
        if not info_dict or not scan_type:
            return jsonify({"error": "Missing required parameters"}), 400
        
        results, error = run_nmap_scan(info_dict, scan_type)
        
        if error:
            return jsonify({"error": error}), 500
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
