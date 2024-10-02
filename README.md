# 🛡️ UC01 - Network Security Scanner 🛡️

Welcome to **UC01**, your ultimate Python-based tool for comprehensive network security scanning and auditing! Whether you're a system administrator or a cybersecurity enthusiast, UC01 helps you gather critical information about domains, IP addresses, and network services.

## 🌟 Features

UC01 offers a wide range of network security analysis tools:

- 📝 **Domain Information Extraction**: Retrieve WHOIS and DNS records for any domain.
- 🔄 **Reverse DNS Lookup**: Identify the domain name associated with an IP address.
- 🌐 **Subdomain Enumeration**: Automatically discover subdomains or manually input them for analysis.
- 🗺️ **IP Geolocation**: Find out where an IP address is geographically located.
- 🔍 **Port Scanning**: Scan open ports on a target IP and analyze potential vulnerabilities.
- 🚀 **Full Network Scan**: Perform all available analyses (WHOIS, DNS, IP, Port scanning, etc.) in a single command.

## ⚙️ Installation

Make sure you have Python installed on your system. Follow these steps to set up and run UC01.

### Prerequisites

- Python 3.x
- Pip (Python package installer)

### Download

Run the following command to download :

```bash
git clone https://github.com/bdottech/uc01.py.git
```

```bash
cd uc01.py
```

### Install Required Libraries

Run the following command to install the necessary dependencies:

```bash
pip install -r requirements.txt
```

### Running UC01

Once the installation is complete, you can start UC01 by running the script:

```bash
python uc01.py
```

## 📋 Usage

UC01 is designed to be easy to use with a straightforward command-line interface.

1. **Domain Information Extraction**: Extract WHOIS and DNS data for a domain.
2. **Reverse DNS Lookup**: Perform reverse DNS on an IP address.
3. **Subdomain Enumeration**: Automatically or manually search for subdomains.
4. **IP Geolocation**: Locate the geographical position of an IP address.
5. **Port Scanning**: Check for open ports on a target IP.
6. **Full Scan**: Execute all analyses on a domain or IP address.

Simply follow the on-screen menu to choose the desired functionality.

## 🚧 Example

```bash
python uc01.py
```

You'll be prompted to choose from options like domain info, reverse DNS, subdomain enumeration, etc. Just follow the instructions to get detailed results.

## 💾 Saving Results

After completing a scan, UC01 gives you the option to save the results to a file for future reference. Just follow the prompts to specify a filename and location.

## 🔧 Contributing

We welcome contributions! If you'd like to improve UC01, feel free to submit a pull request. Please make sure to follow the code of conduct outlined in our contribution guide.

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
