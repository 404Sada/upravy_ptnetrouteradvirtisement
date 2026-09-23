import csv
from ptlibs import ptprinthelper
from collections import defaultdict

class NonJsonOutput:
    def print_box(string):
        box_char = '='
        print(box_char*(len(string)+4))
        print(box_char, string, box_char)
        print(box_char*(len(string)+4))
    
    def output_time_information(start_end_mode_path, time_all_path):
        # Reading start and end times from start_end_mode.csv
        try:
            with open(start_end_mode_path, 'r') as csvfile:
                csvreader = csv.reader(csvfile)
                times = [row[0] for row in csvreader if row]  # Read non-empty rows
                if len(times) >= 3:
                    start_time = times[1]
                    end_time = times[-1]
                    ptprinthelper.ptprint(f"Time starting the tool:    {start_time}", "INFO")
                    ptprinthelper.ptprint(f"Time ending the tool:      {end_time}", "INFO")
                else:
                    ptprinthelper.ptprint("Insufficient data in start_end_mode.csv", "ERROR")
        except FileNotFoundError:
            ptprinthelper.ptprint("start_end_mode.csv file not found", "ERROR")
        
        # Reading packet capture times from time_all.csv
        try:
            with open(time_all_path, 'r') as csvfile:
                csvreader = csv.DictReader(csvfile)
                times = [row['time'] for row in csvreader if 'time' in row and row['time']]  # Extract 'time' field if it exists and is not empty
                
                if times:
                    # Print the first time as start time for capturing packets
                    start_capture_time = times[0]
                    ptprinthelper.ptprint(f"First packet captured at:  {start_capture_time}", "INFO")
                    
                    # Print the last time as end time for capturing packets
                    end_capture_time = times[-1]
                    ptprinthelper.ptprint(f"Last packet captured at:   {end_capture_time}", "INFO")
                else:
                    ptprinthelper.ptprint("No time data found in time_all.csv", "ERROR")
        except FileNotFoundError:
            ptprinthelper.ptprint("time_all.csv file not found", "ERROR")

    def output_vulnerabilities(role_node_path, vulnerabilities, less_option=False):
        try:
            mac_to_info = defaultdict(lambda: {'IPs': [], 'Device_number': None, 'Role': None})
            ip_to_mac = defaultdict(list)

            # Read role_node.csv and collect device information
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
                    device_number = int(row[device_number_index])  # Convert to integer for sorting
                    role = row[role_index]
                    mac_to_info[mac]['IPs'].append(ip)
                    mac_to_info[mac]['Device_number'] = device_number
                    mac_to_info[mac]['Role'] = role
                    ip_to_mac[ip].append(mac)

            # Sort devices by device number in ascending order
            sorted_devices = sorted(mac_to_info.items(), key=lambda item: item[1]['Device_number'])

            # Print the number of devices found
            ptprinthelper.ptprint(f"Number of devices found:   {len(sorted_devices)}", "OK")

            # Print vulnerabilities for the key "All"
            if "All" in vulnerabilities:
                for vuln in vulnerabilities["All"]:
                    ptprinthelper.ptprint(f"Vulnerable on the network: {vuln}", "VULN", colortext=True)

            # Print information about each device
            for mac, info in sorted_devices:
                device_number = info['Device_number']
                role = info['Role']
                print("----------------------------------------------------------------")
                ptprinthelper.ptprint(f"Device number: {device_number} ({role})", "INFO")
  
                ips = info['IPs']

                # Print vulnerabilities for the device
                device_key = f"Device {device_number}"
                if device_key in vulnerabilities:
                    for vuln in vulnerabilities[device_key]:
                        ptprinthelper.ptprint(f"Vulnerable: {vuln}", "VULN", colortext=True)


                if not less_option:
                    ptprinthelper.ptprint(f"    MAC   {mac}")
                    for ip in ips:
                        # Check for duplicated IP
                        duplicated_text = " (duplicated address)" if len(ip_to_mac[ip]) > 1 else ""

                        # Print IP address
                        if ":" in ip:  # IPv6 address
                            ptprinthelper.ptprint(f"    IPv6  {ip}{duplicated_text}")
                        else:  # IPv4 address
                            ptprinthelper.ptprint(f"    IPv4  {ip}{duplicated_text}")

                
        except Exception as e:
            ptprinthelper.ptprint(f"Error in output_vulnerabilities: {e}", "ERROR")
        