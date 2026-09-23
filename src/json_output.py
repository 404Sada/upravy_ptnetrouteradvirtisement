import ast
import csv
from collections import defaultdict
from ptlibs.ptjsonlib import PtJsonLib


class JsonOutput:
    def __init__(self):
        self.ptjson = PtJsonLib(status="finished")

    def output_vulnerabilities(self, role_node_path, vulnerabilities, ra_csv_path):
        try:
            mac_to_info = defaultdict(lambda: {'IPs': [], 'Device_number': None, 'Role': None})
            ip_to_mac = defaultdict(list)

            with open(role_node_path, 'r', newline='') as role_file:
                role_reader = csv.reader(role_file)
                header = next(role_reader)
                mac_index = header.index('MAC')
                ip_index = header.index('IP')
                device_number_index = header.index('Device_number')
                role_index = header.index('Role')

                for row in role_reader:
                    mac = row[mac_index]
                    ip = row[ip_index]
                    device_number = int(row[device_number_index])
                    role = row[role_index]
                    mac_to_info[mac]['IPs'].append(ip)
                    mac_to_info[mac]['Device_number'] = device_number
                    mac_to_info[mac]['Role'] = role
                    ip_to_mac[ip].append(mac)

            sorted_devices = sorted(mac_to_info.items(), key=lambda item: item[1]['Device_number'])

            if "All" in vulnerabilities:
                code = 1
                for vuln in vulnerabilities["All"]:
                    self.ptjson.add_vulnerability(vuln_code=code, description=f"{vuln}")
                    code += 1

            ipv6_prefix = self.get_ipv6_prefix(ra_csv_path)
            if ipv6_prefix:
                self.ptjson.add_property("IPv6 prefix", ipv6_prefix)

            pref64_prefix = self.get_pref64_prefix(ra_csv_path)
            if pref64_prefix:
                self.ptjson.add_property("PREF64 prefix", pref64_prefix)

            for mac, info in sorted_devices:
                device_number = info['Device_number']
                role = info['Role']
                device_name = f"Device {device_number}"
                node_properties = {
                    "name": device_name,
                    "type": role,
                    "MAC": mac,
                    "vulnerabilities": vulnerabilities.get(device_name, [])
                }

                device_node = self.ptjson.create_node_object(device_name, "Site", None, node_properties)
                self.ptjson.add_node(device_node)


                for ip in info['IPs']:
                    protocol = "IPv6" if ":" in ip else "IPv4"
                    duplicated_text = "duplicated address" if len(ip_to_mac[ip]) > 1 else "normal address"
                    address_properties = {
                        "IP": ip,
                        "protocol": protocol,
                        "description": duplicated_text
                    }

                    address_node = self.ptjson.create_node_object("Address", device_name, device_node["key"], address_properties)
                    self.ptjson.add_node(address_node)

        except Exception as e:
            self.ptjson.end_error(f"Error in output_vulnerabilities: {e}", False)

    def get_ipv6_prefix(self, ra_csv_path):
        try:
            with open(ra_csv_path, 'r') as csvfile:
                csvreader = csv.DictReader(csvfile)
                prefixes = [
                    f"{row['Prefix']}/{row['Prefix_length']}" for row in csvreader 
                    if 'Prefix' in row and row['Prefix'] and 'Prefix_length' in row and row['Prefix_length']
                ]
                return prefixes[0] if prefixes else None
        except FileNotFoundError:
            self.ptjson.end_error("RA.csv file not found", False)
            return None

    def get_pref64_prefix(self, ra_csv_path):
        try:
            with open(ra_csv_path, 'r') as csvfile:
                csvreader = csv.DictReader(csvfile)
                for row in csvreader:
                    if 'Pref64' in row and row['Pref64']:
                        try:
                            pref64_data = ast.literal_eval(row['Pref64']) if isinstance(row['Pref64'], str) else row['Pref64']
                            if isinstance(pref64_data, dict) and 'prefix' in pref64_data and pref64_data['prefix']:
                                return pref64_data['prefix']
                        except Exception:
                            return row['Pref64']
                return None
        except FileNotFoundError:
            return None

    def get_json_output(self):
        return self.ptjson.get_result_json()
