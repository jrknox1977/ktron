# KTRON - CTF Recon Tool

KTRON is a comprehensive CTF (Capture The Flag) reconnaissance tool designed to automate and streamline the initial information gathering process. It combines various recon techniques and tools to provide a thorough overview of the target system.

## Features

- Automated Nmap scanning with customizable scan types
- TinyDB integration for persistent data storage
- Flask-based API for running scans and retrieving results
- Command-line interface for easy interaction
- Extensible architecture for adding new recon tools

## Prerequisites

- Python 3.6+
- Flask
- TinyDB
- Colorama
- Requests
- python-dotenv
- Nmap (installed on the system)

## Required tools:
- Terminator
- Gobuster

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ktron.git
   cd ktron
   ```

2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

3. Set up your environment variables:
   Create a `.env` file in the root directory and add the following:
   ```
   WORKING_DIR=/path/to/your/working/directory
   ```

## Usage

1. Start the Flask API server:
   ```
   python run.py
   ```

2. Run the KTRON CLI tool:
   ```
   python cli/ktron.py -i <target_ip> -n <target_hostname> [-f]
   ```
   Use the `-f` flag to force a rerun of all tools.

## Project Structure

```
.
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── routes.py
│   ├── tools.py
│   ├── templates/
│   └── static/
├── cli/
│   └── ktron.py
├── tests/
├── .env
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── run.py
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

- Joshua Knox - Author and maintainer

## Disclaimer

This tool is for educational purposes only. Always ensure you have explicit permission to scan or test any systems or networks you do not own.
