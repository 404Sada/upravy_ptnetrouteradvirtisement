import csv
import ipaddress
import netifaces
import os
from scapy.all import *
from ptlibs import ptprinthelper

class NodeRoleAnalyzer:
    def __init__(self, src_MAC, time_all_path, ra_path, role_node_path):
        self.src_MAC = src_MAC
        self.time_all_path = time_all_path
        self.ra_path = ra_path
        self.role_node_path = role_node_path

    def analyze_node_role(self):
        try:
            if not self.has_data_csv(self.time_all_path):
                return

            self.extract_mac_addresses()
            self.remove_duplicates_and_empty_ips()
            self.reorder_and_assign_device_numbers()

            if self.has_data_csv(self.ra_path):
                self.process_ra_csv()
            else:
                self.assign_host_role()
        except Exception as e:
            ptprinthelper.ptprint(f"Error in analyze_node_role: {e}", "ERROR")

    def has_data_csv(self, file_path):
        try:
            return os.path.exists(file_path) and os.path.getsize(file_path) > 0
        except Exception as e:
            ptprinthelper.ptprint(f"Error checking data in {file_path}: {e}", "ERROR")
            return False

    def extract_mac_addresses(self):
        def is_valid_ip(ip):
            try:
                ip_obj = ipaddress.ip_address(ip)
                return True, ip_obj
            except ValueError:
                return False, None
            
        try:
            with open(self.time_all_path, 'r', newline='') as infile, \
                 open(self.role_node_path, 'w', newline='') as outfile:
                reader = csv.reader(infile)
                writer = csv.writer(outfile)
                header = next(reader)
                mac_index = header.index('src_MAC')
                ip_index = header.index('src_IP')
                writer.writerow(['MAC', 'IP', 'Device_number', 'Role'])
                for row in reader:
                    if row[mac_index] != self.src_MAC:
                        ip_value = row[ip_index]
                        if ip_value == "":
                            writer.writerow([row[mac_index], ip_value, '', ''])
                        else:
                            valid, ip_obj = is_valid_ip(ip_value)
                            if valid:
                                if isinstance(ip_obj, ipaddress.IPv6Address):
                                    if any(func(ip_value) for func in (in6_islladdr, in6_issladdr, in6_isuladdr, in6_isgladdr)):
                                        writer.writerow([row[mac_index], ip_value, '', ''])
                                elif isinstance(ip_obj, ipaddress.IPv4Address):
                                    writer.writerow([row[mac_index], ip_value, '', ''])
        except Exception as e:
            ptprinthelper.ptprint(f"Error in extract_mac_addresses: {e}", "ERROR")

    def remove_duplicates_and_empty_ips(self):
        try:
            seen_mac_ip = set()
            unique_rows = []
            mac_without_ip = set()

            with open(self.role_node_path, 'r', newline='') as infile:
                reader = csv.reader(infile)
                header = next(reader)
                for row in reader:
                    mac_ip_tuple = (row[0], row[1])
                    if row[1] == "":
                        mac_without_ip.add(row[0])
                    if mac_ip_tuple not in seen_mac_ip:
                        seen_mac_ip.add(mac_ip_tuple)
                        unique_rows.append(row)
            
            # Remove rows with empty IP if there is another row with the same MAC that has an IP
            filtered_rows = [row for row in unique_rows if row[0] not in mac_without_ip or row[1] != ""]

            with open(self.role_node_path, 'w', newline='') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(header)
                writer.writerows(filtered_rows)
        except Exception as e:
            ptprinthelper.ptprint(f"Error in remove_duplicates_and_empty_ips: {e}", "ERROR")

    def reorder_and_assign_device_numbers(self):
        try:
            with open(self.role_node_path, 'r', newline='') as infile:
                reader = csv.reader(infile)
                header = next(reader)
                rows = sorted(reader, key=lambda row: (row[0], row[1] if row[1] else ''))

            with open(self.role_node_path, 'w', newline='') as outfile:
                writer = csv.writer(outfile)
                writer.writerow(header)

                current_mac = None
                device_number = 0

                for row in rows:
                    if row[0] != current_mac:
                        current_mac = row[0]
                        device_number += 1
                    row[2] = device_number
                    writer.writerow(row)
        except Exception as e:
            ptprinthelper.ptprint(f"Error in reorder_and_assign_device_numbers: {e}", "ERROR")

    def process_ra_csv(self):
        try:
            with open(self.ra_path, 'r', newline='') as ra_file:
                ra_reader = csv.reader(ra_file)
                ra_header = next(ra_reader)
                ra_rows = [row for row in ra_reader if row[ra_header.index('src_MAC')] != '']
                
            if not ra_rows:
                self.assign_host_role()
                return

            ra_mac_set = {row[ra_header.index('src_MAC')] for row in ra_rows}
            ra_rows.sort(key=lambda row: {'High': 3, 'Medium': 2, 'Low': 1}[row[ra_header.index('Prf_flag')]], reverse=True)
            highest_preference_mac = ra_rows[0][ra_header.index('src_MAC')]
            unique_preferences = len(set(row[ra_header.index('Prf_flag')] for row in ra_rows))
            preferred_role = 'Preferred router' if unique_preferences == 1 else 'Router'
            
            self.update_roles(ra_mac_set, highest_preference_mac, preferred_role)
        except Exception as e:
            ptprinthelper.ptprint(f"Error in process_ra_csv: {e}", "ERROR")

    def assign_host_role(self):
        if not self.has_data_csv(self.time_all_path):
            return
        
        try:
            with open(self.role_node_path, 'r', newline='') as infile:
                reader = csv.reader(infile)
                header = next(reader)
                rows = [header]  # Start with the header

                for row in reader:
                    row[3] = 'Host'  # Modify the desired field
                    rows.append(row)  # Append the modified row to the list

            # Now write all rows back to the same file
            with open(self.role_node_path, 'w', newline='') as outfile:
                writer = csv.writer(outfile)
                writer.writerows(rows)  # Write all rows, including header

        except Exception as e:
            ptprinthelper.ptprint(f"Error in assign_host_role: {e}", "ERROR")

    def update_roles(self, ra_mac_set, highest_preference_mac, preferred_role):
        try:
            with open(self.role_node_path, 'r', newline='') as role_file:
                role_reader = csv.reader(role_file)
                role_header = next(role_reader)
                role_rows = list(role_reader)

            updated_role_rows = []
            for role_row in role_rows:
                mac = role_row[0]
                if mac not in ra_mac_set:
                    role = 'Host'
                elif mac == highest_preference_mac:
                    role = 'Preferred router'
                else:
                    role = preferred_role
                updated_role_rows.append([mac, role_row[1], role_row[2], role])

            with open(self.role_node_path, 'w', newline='') as role_file:
                writer = csv.writer(role_file)
                writer.writerow(role_header)
                writer.writerows(updated_role_rows)
        except Exception as e:
            ptprinthelper.ptprint(f"Error in update_roles: {e}", "ERROR")

class VulnerabilityAnalyzer:
    def __init__(self, time_all_path, role_node_path, ra_path, i, smac, sip, prefix, DNS_search_list, DNS_server, Route_info, pref64=None):
        self.time_all_path = time_all_path
        self.role_node_path = role_node_path
        self.ra_path = ra_path
        self.interface = i
        self.smac = smac
        self.sip = sip
        self.prefix = prefix
        self.DNS_search_list = DNS_search_list
        self.DNS_server = DNS_server
        self.Route_info = Route_info
        self.pref64 = pref64

    def analyze_vulnerabilities(self):
        vulnerabilities = {"All": []}

        try:
            self.check_ra_guard_missing(vulnerabilities)
            self.check_pvlan_or_similar(vulnerabilities)
            self.check_slaac(vulnerabilities)
            self.check_preference_flag(vulnerabilities)
            self.check_predictable_address(vulnerabilities)
            self.check_protocol_vulnerabilities(vulnerabilities)
        except Exception as e:
            ptprinthelper.ptprint(f"Error in analyze_vulnerabilities: {e}", "ERROR")
        
        # Arrange the dictionary keys in ascending order
        sorted_vulnerabilities = dict(sorted(vulnerabilities.items(), key=lambda item: (item[0] != "All", item[0])))

        return sorted_vulnerabilities

    def check_ra_guard_missing(self, vulnerabilities):
        try:
            def is_global_unicast_ipv6(ipv6_address):
                try:
                    # Split the address by colons to separate the components, but need to expand for checking
                    addr = ipaddress.ip_address(ipv6_address)
                    ipv6_address = addr.exploded

                    components = ipv6_address.split(':')

                    # Check if it has the required number of components for a valid IPv6 address
                    if len(components) != 8:
                        return False

                    # Check for global unicast prefix and discard addresses starting with reserved prefixes
                    global_unicast_prefixes = ['2001', '2002', '2003', '2004', '2005', '2006', '2007', '2008', '2009']
                    return components[0][:4] in global_unicast_prefixes

                except:
                    return False

            def get_ipv6_addresses(interface: str) -> list:
                try:
                    # Get the addresses for the specified interface
                    addresses = netifaces.ifaddresses(interface)
                    # Extract the IPv6 addresses
                    ipv6_info = addresses.get(netifaces.AF_INET6, [])
                    ipv6_addresses = [addr['addr'] for addr in ipv6_info]
                    return ipv6_addresses
                except (ValueError, KeyError, OSError):
                    # Return an empty list if there's an error
                    return []
            
            def check_ipv6_addresses_generated_from_prefix(ip: str, prefix: str) -> bool:
                """
                Checks if the given IPv6 address is generated from the specified prefix.

                Args:
                    ip (str): The IPv6 address to check.
                    prefix (str): The IPv6 network prefix in the form 'network/prefix_length'.

                Returns:
                    bool: True if the IP address is in the specified network prefix, False otherwise.
                """
                try:
                    # Create an IPv6 network object
                    ipv6_network = ipaddress.IPv6Network(prefix, strict=False)
                    
                    # Create an IPv6 address object
                    ipv6_address = ipaddress.IPv6Address(ip)
                    
                    # Check if the address is in the network
                    return ipv6_address in ipv6_network
                
                except ValueError as e:
                    return False
                except Exception as e:
                    return False

            sender_ipv6_addresses = get_ipv6_addresses(self.interface)
            # Open the file and read the header
            with open(self.time_all_path, 'r', newline='') as time_file:
                time_reader = csv.reader(time_file)
                time_header = next(time_reader)

                # Indexes of relevant columns
                dst_mac_index = time_header.index('dst_MAC')
                dst_ip_index = time_header.index('dst_IP')
                src_ip_index = time_header.index('src_IP')
                packet_index = time_header.index('packet')
                # Check for the legitimate default router being stolen
                for row in time_reader:
                    if row[dst_mac_index] == self.smac:
                        dst_ip = row[dst_ip_index]
                        if is_global_unicast_ipv6(dst_ip) and dst_ip != self.sip and dst_ip not in sender_ipv6_addresses:
                            if "The role of the legitimate default router has been stolen" not in vulnerabilities["All"]:
                                vulnerabilities["All"].append("The role of the legitimate default router has been stolen")
                            break

            # Check for illegitimate prefix accepted by hosts
            if self.prefix:
                with open(self.time_all_path, 'r', newline='') as time_file:
                    time_reader = csv.reader(time_file)
                    time_header = next(time_reader)

                    for row in time_reader:
                        src_ip = row[src_ip_index]
                        if check_ipv6_addresses_generated_from_prefix(src_ip, self.prefix):
                            if "Illegitimate prefix accepted by hosts" not in vulnerabilities["All"]:
                                vulnerabilities["All"].append("Illegitimate prefix accepted by hosts")
                            break

            # Check for illegitimate DNS server queried by hosts
            with open(self.time_all_path, 'r', newline='') as time_file:
                time_reader = csv.reader(time_file)
                time_header = next(time_reader)
                
                for row in time_reader:
                    dst_ip = row[dst_ip_index]
                    if self.DNS_server is not None:
                        if dst_ip in self.DNS_server:   
                            if "Illegitimate DNS server queried by hosts" not in vulnerabilities["All"]:
                                vulnerabilities["All"].append("Illegitimate DNS server queried by hosts")
                            break

            # Check for illegitimate DNS domain queried by hosts
            with open(self.time_all_path, 'r', newline='') as time_file:
                time_reader = csv.reader(time_file)
                time_header = next(time_reader)

                for row in time_reader:
                    packet = row[packet_index]
                    
                    if self.DNS_search_list is not None:
                        if any(element in packet for element in self.DNS_search_list):
                            if "Illegitimate DNS domain queried by hosts" not in vulnerabilities["All"]:
                                vulnerabilities["All"].append("Illegitimate DNS domain queried by hosts")
                            break

            # Check for illegitimate PREF64 prefix accepted by hosts
            if self.pref64:
                pref64_net = self.pref64 if '/' in self.pref64 else f"{self.pref64}/96"
                with open(self.time_all_path, 'r', newline='') as time_file:
                    time_reader = csv.reader(time_file)
                    time_header = next(time_reader)

                    for row in time_reader:
                        src_ip = row[src_ip_index]
                        dst_ip = row[dst_ip_index]
                        if check_ipv6_addresses_generated_from_prefix(src_ip, pref64_net) or check_ipv6_addresses_generated_from_prefix(dst_ip, pref64_net):
                            if "Illegitimate PREF64 prefix accepted by hosts" not in vulnerabilities["All"]:
                                vulnerabilities["All"].append("Illegitimate PREF64 prefix accepted by hosts")
                            break
            
        except Exception as e:
            ptprinthelper.ptprint(f"Error in check_ra_guard_missing: {e}", "ERROR")

    def check_pvlan_or_similar(self, vulnerabilities):
        try:
            with open(self.role_node_path, 'r', newline='') as role_file:
                role_reader = csv.reader(role_file)
                header = next(role_reader)
                ip_index = header.index('IP')
                role_index = header.index('Role')

                for row in role_reader:
                    if row[role_index] == 'Host' and row[ip_index].startswith('fe80:'):
                        if "PVLAN or similar configuration missing" not in vulnerabilities["All"]:
                            vulnerabilities["All"].append("PVLAN or similar configuration missing")
        except Exception as e:
            ptprinthelper.ptprint(f"Error in check_pvlan_or_similar: {e}", "ERROR")

    def check_slaac(self, vulnerabilities):
        try:
            with open(self.ra_path, 'r', newline='') as ra_file:
                ra_reader = csv.reader(ra_file)
                ra_header = next(ra_reader)
                a_flag_index = ra_header.index('A_flag')
                prefix_index = ra_header.index('Prefix')

                for row in ra_reader:
                    if row[a_flag_index] == 'On' and row[prefix_index]:
                        if "SLAAC discovered. DHCP should be preferred" not in vulnerabilities["All"]:
                            vulnerabilities["All"].append("SLAAC discovered. DHCP should be preferred")
        except Exception as e:
            ptprinthelper.ptprint(f"Error in check_slaac: {e}", "ERROR")

    def check_preference_flag(self, vulnerabilities):
        try:
            with open(self.ra_path, 'r', newline='') as ra_file:
                ra_reader = csv.reader(ra_file)
                ra_header = next(ra_reader)
                prf_flag_index = ra_header.index('Prf_flag')
                src_mac_index = ra_header.index('src_MAC')

                with open(self.role_node_path, 'r', newline='') as role_file:
                    role_reader = csv.reader(role_file)
                    role_header = next(role_reader)
                    mac_index = role_header.index('MAC')
                    device_number_index = role_header.index('Device_number')
                    role_index = role_header.index('Role')

                    mac_to_device = {row[mac_index]: row[device_number_index] for row in role_reader}

                for row in ra_reader:
                    mac = row[src_mac_index]
                    device_number = mac_to_device.get(mac)
                    if device_number:
                        if row[prf_flag_index] in ['Low', 'Medium']:
                            key = f"Device {device_number}"
                            if key not in vulnerabilities:
                                vulnerabilities[key] = []
                            if "Low/Medium preference of flag" not in vulnerabilities[key]:
                                vulnerabilities[key].append("Low/Medium preference of flag")
        except Exception as e:
            ptprinthelper.ptprint(f"Error in check_preference_flag: {e}", "ERROR")

    def check_predictable_address(self, vulnerabilities):
        try:
            with open(self.role_node_path, 'r', newline='') as role_file:
                role_reader = csv.reader(role_file)
                header = next(role_reader)
                mac_index = header.index('MAC')
                ip_index = header.index('IP')
                device_number_index = header.index('Device_number')

                for row in role_reader:
                    ip = row[ip_index]
                    mac = row[mac_index].replace(':', '').lower()
                    device_number = row[device_number_index]

                    if ip and (self.is_predictable(ip, mac)):
                        key = f"Device {device_number}"
                        if key not in vulnerabilities:
                            vulnerabilities[key] = []
                        if "Predictable address (no randomness or little randomness)" not in vulnerabilities[key]:
                            vulnerabilities[key].append("Predictable address (no randomness or little randomness)")
        except Exception as e:
            ptprinthelper.ptprint(f"Error in check_predictable_address: {e}", "ERROR")
    
    def check_protocol_vulnerabilities(self, vulnerabilities):
        try:
            # Read the role_node.csv to map MAC addresses to device numbers
            mac_to_device = {}
            with open(self.role_node_path, 'r', newline='') as role_file:
                role_reader = csv.reader(role_file)
                role_header = next(role_reader)
                mac_index = role_header.index('MAC')
                device_number_index = role_header.index('Device_number')

                for row in role_reader:
                    mac_to_device[row[mac_index]] = f"Device {row[device_number_index]}"

            # Read the time_all.csv to check for protocol-specific packets
            with open(self.time_all_path, 'r', newline='') as time_file:
                time_reader = csv.reader(time_file)
                time_header = next(time_reader)
                mac_index = time_header.index('src_MAC')
                packet_index = time_header.index('packet')

                for row in time_reader:
                    mac = row[mac_index]
                    packet = row[packet_index]
                    if mac in mac_to_device:
                        device_key = mac_to_device[mac]

                        if "ICMPv6MLReport" in packet or "ICMPv6MLDone" in packet:
                            if device_key not in vulnerabilities:
                                vulnerabilities[device_key] = []
                            if "MLDv1 active" not in vulnerabilities[device_key]:
                                vulnerabilities[device_key].append("MLDv1 active")

                        if "LLMNRQuery" in packet or "LLMNRResponse" in packet:
                            if device_key not in vulnerabilities:
                                vulnerabilities[device_key] = []
                            if "LLMNR active" not in vulnerabilities[device_key]:
                                vulnerabilities[device_key].append("LLMNR active")

                        if "DNS Ans" in packet:
                            if device_key not in vulnerabilities:
                                vulnerabilities[device_key] = []
                            if "mDNS active" not in vulnerabilities[device_key]:
                                vulnerabilities[device_key].append("mDNS active")
        except Exception as e:
            ptprinthelper.ptprint(f"Error in check_protocol_vulnerabilities: {e}", "ERROR")


    def is_predictable(self, ip, mac):
        # Check if the IPv6 address is derived from the MAC address (EUI-64 format)
        def check_eui64(ipv6: str, mac: str) -> bool:
            # Validate and expand the IPv6 address to its full form
            try:
                ipv6_full = ipaddress.ip_address(ipv6).exploded
            except ValueError:
                return False
            
            # Extract the last 4 segments (last 64 bits) and join them
            last_64_bits = "".join(ipv6_full.split(":")[4:])
            
            # Check if the last 64 bits conform to EUI-64 format (contain 'fffe' in the middle)
            if last_64_bits[6:10] != 'fffe':
                return False
            
            # Remove 'fffe' and reconstruct the MAC address
            eui64_mac = last_64_bits[:6] + last_64_bits[10:]
            
            # Flip the 7th bit of the first byte back
            first_byte = int(eui64_mac[:2], 16) ^ 0x02
            mac_address = "{:02x}{}".format(first_byte, eui64_mac[2:])
            
            # Format the MAC address properly
            mac_address = ":".join(mac_address[i:i+2] for i in range(0, 12, 2))
            
            return mac_address.lower() == mac.lower()
        
        if check_eui64(ip, mac):
            return True

        # Check for a high number of zeros (compact or explicitly written)
        zero_sequences = ip.split(':')
        zero_count = sum(1 for part in zero_sequences if part == '' or part == '0000')
        if zero_count >= 4:
            return True

        # Check for compressed zeros (:: covering at least 4 octets)
        if "::" in ip:
            double_colon_count = ip.count("::")
            if double_colon_count == 1:
                expanded_zero_count = 8 - len([part for part in zero_sequences if part])
                if expanded_zero_count >= 4:
                    return True

        # Check for repeated octets (at least 4 times)
        octet_count = {}
        for part in zero_sequences:
            if part and part != '0000':
                if part not in octet_count:
                    octet_count[part] = 0
                octet_count[part] += 1
                if octet_count[part] >= 4:
                    return True

        # Check for common predictable patterns
        predictable_patterns_last_octet = [
            "::1", "::2", "::3", "::4", "::5", "::6", "::7", "::8", "::9", "::a", "::b", "::c", "::d", "::e", "::f"
        ]
        predictable_patterns_anywhere = [
            "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
            "aaaa", "bbbb", "cccc", "dddd", "eeee", "ffff"
        ]

        # Check if last octet matches predictable patterns like ::1 to ::f
        if any(ip.lower().endswith(pattern) for pattern in predictable_patterns_last_octet):
            return True

        # Check if any pattern like 1111 to ffff appears at least 3 times
        for pattern in predictable_patterns_anywhere:
            if ip.lower().count(pattern) >= 3:
                return True

        return False



