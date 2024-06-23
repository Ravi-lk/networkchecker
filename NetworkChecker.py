import subprocess
from termcolor import colored
from colorama import init

# Initialize coloramaWW
init()

def run_bash_script(script_path):
    result = subprocess.run(script_path, capture_output=True, text=True, shell=True)
    return result.stdout

def parse_interfaces(output):
    interfaces = []
    for line in output.split('\n'):
        if 'inet ' in line:
            parts = line.split()
            ip_addr = parts[1]
            interface = parts[-1]
            interfaces.append((interface, ip_addr))
    return interfaces

def parse_routes(output):
    routes = []
    for line in output.split('\n'):
        if line.startswith('default') or 'via' in line:
            routes.append(line)
    return routes

def parse_dns(output):
    dns_servers = []
    for line in output.split('\n'):
        if line.startswith('nameserver'):
            dns_servers.append(line.split()[1])
    return dns_servers

def parse_open_ports(output):
    ports = []
    for line in output.split('\n'):
        if line.startswith('tcp') or line.startswith('udp'):
            parts = line.split()
            proto = parts[0]
            port = parts[3].split(':')[-1]
            ports.append((proto, port))
    return ports

def parse_firewall_rules(output):
    rules = []
    for line in output.split('\n'):
        if line and not line.startswith('Chain') and not line.startswith('target'):
            rules.append(line)
    return rules

def print_section_header(header):
    print(colored(f"\n{header}", 'cyan', attrs=['bold']))

def print_key_value(key, value, key_color='yellow', value_color='green'):
    print(f"{colored(key, key_color)}: {colored(value, value_color)}")

def display_ascii_art():
    art = """
   
.______   ____    ____    .______          ___   ____    ____  __  .__   __.  _______   __    __  
|   _  \  \   \  /   /    |   _  \        /   \  \   \  /   / |  | |  \ |  | |       \ |  |  |  | 
|  |_)  |  \   \/   /     |  |_)  |      /  ^  \  \   \/   /  |  | |   \|  | |  .--.  ||  |  |  | 
|   _  <    \_    _/      |      /      /  /_\  \  \      /   |  | |  . `  | |  |  |  ||  |  |  | 
|  |_)  |     |  |        |  |\  \----./  _____  \  \    /    |  | |  |\   | |  '--'  ||  `--'  | 
|______/      |__|        | _| `._____/__/     \__\  \__/     |__| |__| \__| |_______/  \______/  
                                                                                                  
  
    """
    print(colored(art, 'red'))

def display_welcome_message():
    display_ascii_art()
    print(colored("Network Configuration Checker", 'cyan', attrs=['bold']))
   
    print(colored("This script checks and validates network settings and configurations.\n", 'green'))

def validate_network_config():
    script_path = './network_info.sh'
    output = run_bash_script(script_path)

    print_section_header("Validating Network Interfaces and IP addresses")
    interfaces = parse_interfaces(output)
    for interface, ip in interfaces:
        print_key_value("Interface", interface)
        print_key_value("IP Address", ip)

    print_section_header("Validating Routing Table")
    routes = parse_routes(output)
    for route in routes:
        print(colored(f"Route: {route}", 'green'))

    print_section_header("Validating DNS Settings")
    dns_servers = parse_dns(output)
    for server in dns_servers:
        print_key_value("DNS Server", server)

    print_section_header("Validating Open Ports")
    ports = parse_open_ports(output)
    for proto, port in ports:
        print_key_value("Protocol", proto)
        print_key_value("Port", port)

    print_section_header("Validating Firewall Rules")
    rules = parse_firewall_rules(output)
    for rule in rules:
        print(colored(f"Rule: {rule}", 'green'))

if __name__ == "__main__":
    display_welcome_message()
    validate_network_config()
