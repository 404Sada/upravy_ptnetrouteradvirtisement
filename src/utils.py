import argparse
import ipaddress
import os
import re
import socket
import subprocess
import time
import psutil
import sys
from functools import partial
from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib
from src.non_json_output import NonJsonOutput
import netifaces
__version__ = "0.0.12"
SCRIPTNAME = "ptnetrouteradvertisement"

class ValidationUtils:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.information = []

    def validate_ipv6_address_string(self, value, arg_name):
        try:
            ipaddress.IPv6Address(value)
        except ipaddress.AddressValueError:
            self.errors.append(f"Invalid {arg_name}: {value}")
            return "Invalid parameter"
        return value

    def validate_ipv6_address_list(self, values, arg_name):
        valid_addresses = []
        for value in values:
            try:
                ipaddress.IPv6Address(value)
                valid_addresses.append(value)
            except ipaddress.AddressValueError:
                self.errors.append(f"Invalid {arg_name}: {value}. It must be a valid IPv6 address.")
        return valid_addresses if valid_addresses else "Invalid parameter"

    def validate_mac_address(self, value, arg_name):
        pattern = re.compile(r'^[0-9A-Fa-f]{2}([-:])[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$')
        if not pattern.match(value):
            self.errors.append(f"Invalid {arg_name}: {value}")
            return "Invalid parameter"
        return value

    def validate_interface(self, value):
        if value not in psutil.net_if_addrs():
            self.errors.append(f"Invalid interface: {value}")
            return "Invalid parameter"

        stats = psutil.net_if_stats()
        if not stats[value].isup:
            self.errors.append(f"Interface exists but is down or traffic is blocked: {value}")
            return "Invalid parameter"
        
        # Check if the interface has any IPv6 addresses
        has_ipv6 = False
        for addr in psutil.net_if_addrs()[value]:
            if addr.family == socket.AF_INET6:
                has_ipv6 = True
                break

        if not has_ipv6:
            self.errors.append(f"No IPv6 addresses found on interface: {value}")
            return "Invalid parameter"
        
        return value

    def validate_prf(self, value):
        allowed_values = ['High', 'Medium', 'Low', 'Reserved']
        if value not in allowed_values:
            self.errors.append(f"Invalid value for -prf: {value}. Allowed values are {', '.join(allowed_values)}")
            return "Invalid parameter"
        return value

    def validate_non_negative_integer(self, value, arg_name):
        try:
            ivalue = int(value)
            if ivalue < 0 or ivalue > 63113852:
                self.errors.append(f"Invalid value for {arg_name}: {value}. It must be a non-negative integer, less than 63113852")
                return "Invalid parameter"
        except ValueError:
            self.errors.append(f"Invalid value for {arg_name}: {value}")
            return "Invalid parameter"
        return ivalue

    def validate_non_negative_float(self, value, arg_name):
        try:
            ivalue = float(value)
            if ivalue < 0 or ivalue > 63113852:
                self.errors.append(f"Invalid value for {arg_name}: {value}. It must be a non-negative float, less than 63113852")
                return "Invalid parameter"
        except ValueError:
            self.errors.append(f"Invalid value for {arg_name}: {value}")
            return "Invalid parameter"
        return ivalue

    def validate_integer_in_range(self, value, arg_name, min_value=0, max_value=255):
        try:
            ivalue = int(value)
            if ivalue < min_value or ivalue > max_value:
                self.errors.append(f"Invalid value for {arg_name}: {value}. It must be an integer between {min_value} and {max_value}")
                return "Invalid parameter"
        except ValueError:
            self.errors.append(f"Invalid value for {arg_name}: {value}")
            return "Invalid parameter"
        return ivalue

    def validate_ipv6_prefix(self, value):
        try:
            network = ipaddress.IPv6Network(value, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            self.errors.append(f"Invalid IPv6 prefix: {value}")
            return "Invalid parameter"
        return value

    def validate_pref64_prefix(self, value):
        try:
            if '/' in value:
                network = ipaddress.IPv6Network(value, strict=False)
                prefix_to_plc = {96: 0, 64: 1, 56: 2, 48: 3, 40: 4, 32: 5}
                if network.prefixlen not in prefix_to_plc:
                    self.errors.append(f"Invalid PREF64 prefix length: /{network.prefixlen}. Allowed prefix lengths according are /96, /64, /56, /48, /40, /32")
                    return "Invalid parameter"
                self.derived_plc = prefix_to_plc[network.prefixlen]
                return str(network.network_address)
            else:
                ip = ipaddress.IPv6Address(value)
                return str(ip)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            self.errors.append(f"Invalid PREF64 prefix: {value}")
            return "Invalid parameter"

    def validate_dns_suffixes(self, values):
        dns_suffix_pattern = re.compile(
            r'^[a-zA-Z\d-]{1,63}(\.[a-zA-Z\d-]{1,63})*$'
        )
        valid_suffixes = []
        for value in values:
            if not dns_suffix_pattern.match(value):
                self.errors.append(f"Invalid DNS suffix: {value}. It must be a valid DNS suffix.")
            else:
                valid_suffixes.append(value)
        return valid_suffixes if valid_suffixes else "Invalid parameter"

    def validate_flood(self, value):
        allowed_values = ['random', 'constant']
        if value not in allowed_values:
            self.errors.append(f"Invalid value for -f: {value}. Allowed values are {', '.join(allowed_values)}")
            return "Invalid parameter"
        return value

    def validate_flood_interval(self, value):
        try:
            fvalue = float(value)
            if fvalue <= 0:
                self.errors.append(f"Invalid value for -fi: {value}. It must be a positive number greater than 0 (in milliseconds)")
                return "Invalid parameter"
            if fvalue > 63113852000:
                self.errors.append(f"Invalid value for -fi: {value}. It must be less than 63113852000 ms")
                return "Invalid parameter"
        except ValueError:
            self.errors.append(f"Invalid value for -fi: {value}. It must be a valid positive number in milliseconds")
            return "Invalid parameter"
        return fvalue

    def validate_prefix_res1(self, value):
        try:
            int_value = int(value, 0)
            if 0 <= int_value <= 15:
                return int_value
            else:
                self.errors.append(f"Invalid value for Prefix flags reserved bits: {value}. Allowed range is 0 to 15 (4 bits)")
                return "Invalid parameter"
        except ValueError:
            self.errors.append(f"Invalid value for Prefix flags reserved bits: {value}. It must be an integer between 0 and 15")
            return "Invalid parameter"

    def validate_prefix_res2(self, value):
        try:
            int_value = int(value, 0)
            if 0 <= int_value <= 4294967295:
                return int_value
            else:
                self.errors.append(f"Invalid value for Prefix 32-bit reserved field: {value}. Allowed range is 0 to 4294967295 (32 bits / 4 bytes)")
                return "Invalid parameter"
        except ValueError:
            self.errors.append(f"Invalid value for Prefix 32-bit reserved field: {value}. It must be an integer between 0 and 4294967295")
            return "Invalid parameter"

    def validate_ra_flags(self, value):
        try:
            int_value = int(value, 0)
            if 0 <= int_value <= 281474976710655:  # 48 bits (0xFFFFFFFFFFFF)
                return int_value
            else:
                self.errors.append(f"Invalid value for RA Flags: {value}. Allowed range is 0 to 281474976710655 (48 bits / 0x0 to 0xFFFFFFFFFFFF)")
                return "Invalid parameter"
        except ValueError:
            self.errors.append(f"Invalid value for RA Flags: {value}. It must be an integer between 0 and 281474976710655 (or hex 0x0 to 0xFFFFFFFFFFFF)")
            return "Invalid parameter"

    def validate_ha_res(self, value):
        try:
            int_value = int(value, 0)
            if 0 <= int_value <= 65535:
                return int_value
            else:
                self.errors.append(f"Invalid value for Home Agent Reserved field: {value}. Allowed range is 0 to 65535 (16 bits / 0x0 to 0xFFFF)")
                return "Invalid parameter"
        except ValueError:
            self.errors.append(f"Invalid value for Home Agent Reserved field: {value}. It must be an integer between 0 and 65535")
            return "Invalid parameter"

    def validate_captive_portal_uri(self, value):
        if not value or not isinstance(value, str):
            self.errors.append(f"Invalid Captive Portal URI: {value}. It must be a non-empty string.")
            return "Invalid parameter"
        if len(value.encode('utf-8')) > 2038:
            self.errors.append(f"Invalid Captive Portal URI: URI length exceeds maximum allowed length of 2038 bytes.")
            return "Invalid parameter"
        return value

    def validate_ri_parameter(self, value, arg_name):
        pattern = re.compile(r'^prf=([^;]+);rtlifetime=([^;]+);prefix=([^;]+)$')
        match = pattern.match(value)

        if not match:
            self.errors.append(f"Invalid format for {arg_name}: {value}. Expected format is 'prf=X;rtlifetime=Y;prefix=Z'")
            return "Invalid parameter"

        params = {
            'prf': match.group(1).strip(),
            'rtlifetime': match.group(2).strip(),
            'prefix': match.group(3).strip()
        }

        all_valid = True

        if self.validate_prf(params['prf']) == "Invalid parameter":
            self.errors.append(f"Invalid value for preference in {arg_name}: {params['prf']}")
            all_valid = False

        if self.validate_non_negative_integer(params['rtlifetime'], 'Route Lifetime') == "Invalid parameter":
            self.errors.append(f"Invalid value for route lifetime in {arg_name}: {params['rtlifetime']}")
            all_valid = False

        if self.validate_ipv6_prefix(params['prefix']) == "Invalid parameter":
            self.errors.append(f"Invalid value for prefix in {arg_name}: {params['prefix']}")
            all_valid = False

        if not all_valid:
            return "Invalid parameter"

        return {
            'prf': params['prf'],
            'rtlifetime': int(params['rtlifetime']),
            'prefix': params['prefix']
        }
    
    @staticmethod
    def convert_preference_to_int(prf):
        mapping = {
            'High': 1,
            'Medium': 0,
            'Low': 3,
            'Reserved': 2,
            1: 1,
            0: 0,
            3: 3,
            2: 2,
            '1': 1,
            '0': 0,
            '3': 3,
            '2': 2
        }
        return mapping.get(prf, 1)

    @staticmethod
    def get_mac_address(interface_name):
        '''Return MAC address from a specified network interface'''
        try:
            # Get network interface addresses
            addrs = psutil.net_if_addrs()
            
            # Check if the specified interface exists
            if interface_name not in addrs:
                return None
            
            # Iterate through the addresses of the interface
            for addr in addrs[interface_name]:
                # Check if the address is of type AF_LINK (MAC address)
                if addr.family == psutil.AF_LINK:
                    return addr.address
            
            # If no MAC address is found, return None
            return None
        except Exception as e:
            # If there's any problem, return None
            return None
        
    @staticmethod
    def get_ipv6_address(interface):
        '''Function to retrieve IPv6 address of a given network interface (link-local preferred). If not, return ::'''
        if interface not in netifaces.interfaces():
            return "::"
        
        interface_addrs = netifaces.ifaddresses(interface)
        link_local_address = None
        global_address = None
        
        if netifaces.AF_INET6 in interface_addrs:
            for addr_info in interface_addrs[netifaces.AF_INET6]:
                ipv6_address = addr_info['addr'].split('%')[0]  # Remove the scope ID if present
                if ipv6_address.startswith('fe80::'):
                    link_local_address = ipv6_address
                else:
                    global_address = ipv6_address

        # Prefer the link-local address if available, otherwise return the global address
        return link_local_address if link_local_address else (global_address if global_address else "::")
    
    @staticmethod
    def get_interface_ips(interface) -> list:
        '''Function to retrieve IPs of a given network interface'''
        interface_ips = []
        if interface in netifaces.interfaces():
            interface_addrs = netifaces.ifaddresses(interface)
            for addr_type in (netifaces.AF_INET, netifaces.AF_INET6):
                if addr_type in interface_addrs:
                    for addr_info in interface_addrs[addr_type]:
                        interface_ips.append(addr_info['addr'])
        return interface_ips
    
    @staticmethod
    def reverse_IPadd(ip_address) -> str:
        '''Function to create a reverse pointer record from an IP address'''
        try:
            # Create a reverse pointer record from an IP address
            return ipaddress.ip_address(ip_address).reverse_pointer
        except ValueError:
            # Return None if the IP address is not valid
            return None

    # Define a helper function for logging
    def log_and_set_default(self, value, default, description, warning_message):
        if value is not None:
            self.information.append(f"{description}: {value}")
            return value
       
        else:
            self.warnings.append(f"{warning_message}")
            return default
    
    @staticmethod
    def get_ipv6_prefix_details(prefix):
        '''Return prefix and prefix length from an IPv6 prefix. If at least one part is wrong, return None for both'''
        try:
            # Create an IPv6 network object
            network = ipaddress.IPv6Network(prefix, strict=False)
            
            # Extract the prefix and prefix length
            prefix_address = network.network_address
            prefix_length = network.prefixlen
            
            return str(prefix_address), prefix_length
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
            # Handle invalid IPv6 prefix errors
            return None, None
       
    @staticmethod
    def convert_preferenceRA(prf):
        '''Convert preference of RA from number to string (High, Medium, Low, Reserved)'''
        if prf == 1:
            return "High"
        elif prf == 0:
            return "Medium"
        elif prf == 3:
            return "Low"
        else:
            return "Reserved"
    
    @staticmethod
    def convert_OnOff(flag):
        '''Convert flag with 1/0 to string On/Off'''
        if flag == 1:
            return "On"
        if flag == 0:
            return "Off"
        else:
            return "Unknown"
    
    @staticmethod
    def configure_ipv6_rules(nofwd, set):
        with open(os.devnull, 'w') as devnull:
            try:
                if set:
                    # Dropping Redirect from the attacker
                    subprocess.run(["ip6tables", "-A", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP"], check=True)
                    # Allow or disallow forwarding based on nofwd
                    command = 'sysctl -w net.ipv6.conf.all.forwarding={} >/dev/null'.format(1 if not nofwd else 0)
                    if not nofwd:
                        subprocess.run(["ip6tables", "-A", "FORWARD", "-j", "ACCEPT"], check=True)
                    if nofwd:
                        subprocess.run(["ip6tables", "-A", "FORWARD", "-j", "DROP"], check=True)
            
                else:
                    # Reset Redirect from the attacker
                    subprocess.run(["ip6tables", "-D", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP"], check=True)
                    # Always disallow forwarding when disabling
                    command = 'sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null'
                    subprocess.run(["ip6tables", "-D", "FORWARD", "-j", "DROP"], stderr=subprocess.DEVNULL, check=False)
                    subprocess.run(["ip6tables", "-D", "FORWARD", "-j", "ACCEPT"], stderr=subprocess.DEVNULL, check=False)

                os.system(command)
            except:
                pass
    
    @staticmethod
    def get_payload(length):
        '''Get payload abcdef... with specified length'''
        if length == 0:
            return ''
        if length > 0:
            data = ''
            j = 97
            for i in range(length):
                if j == 120:
                    j = 97
                data += (chr(j))
                j = j + 1
            return data

class CustomArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.utils = ValidationUtils()
        self.parsed_params = []

    def parse_args(self, args=None, namespace=None):
        args, unknown_args = self.parse_known_args(args, namespace)

        list_prefixes = ["-d", "-ai", "-i", "-smac", "-dmac", "-sip", "-dip", "-M", "-O", "-H", "-P", "-res", "-snac", "-prf", "-rlt", "-rcht", "-rtrt", "-chl", "-prefix", "-L", "-A", "-raf", "-pd", "-pres1", "-pres2", "-vlt", "-plt", "-mtu", "-dnssl", "-rdnss", "-ri", "-pref64", "-pref64lt", "-plc", "-raflags", "-hainfo", "-haprf", "-halt", "-hares", "-cportal", "-nofwd", "-j", "-n", "-f", "-fi", "-less"]

        if unknown_args:
            for arg in unknown_args:
                if arg.startswith('-') and arg not in list_prefixes:
                    self.utils.errors.append(f"Unexpected argument: {arg}")

        if args:
            for arg, value in vars(args).items():
                if value is not None:
                    self.parsed_params.append((arg, value))
                if arg in list_prefixes and value is None:
                    self.utils.errors.append(f"Missing value for argument: {arg}")

        if args.i is None:
            self.utils.errors.append(f"No interface is inserted to perform. Program ends")

        if args.rdnss is not None:
            args.rdnss = self.utils.validate_ipv6_address_list(args.rdnss, "DNS server address")

        if args.dnssl is not None:
            args.dnssl = self.utils.validate_dns_suffixes(args.dnssl)
        
        if args.d is not None and args.ai is not None:
            if args.ai > args.d:
               self.utils.errors.append(f"The value of advertisement interval is greater than the value of duration")
        
        if args.prefix is None:
            if args.L:
                self.utils.errors.append(f"L flag is set but Prefix information is not inserted")
            if args.A:
                self.utils.errors.append(f"A flag is set but Prefix information is not inserted")
            if args.raf:
                self.utils.errors.append(f"Router Address flag (raf) is set but Prefix information is not inserted")
            if args.pd:
                self.utils.errors.append(f"DHCPv6-PD flag (pd) is set but Prefix information is not inserted")
            if args.pres1 is not None:
                self.utils.errors.append(f"Prefix flags reserved bits (pres1) is inserted but Prefix information is not inserted")
            if args.pres2 is not None:
                self.utils.errors.append(f"Prefix 32-bit reserved field (pres2) is inserted but Prefix information is not inserted")
            if args.vlt:
                self.utils.errors.append(f"Valid lifetime of prefix is inserted but Prefix information is not inserted")
            if args.plt:
                self.utils.errors.append(f"Preferred lifetime of prefix is inserted but Prefix information is not inserted")

        if args.pref64 is None:
            if args.pref64lt is not None or args.plc is not None:
                self.utils.errors.append("Arguments -pref64lt and -plc can only be used together with -pref64.")
        else:
            if args.plc is None and getattr(self.utils, 'derived_plc', None) is not None:
                args.plc = self.utils.derived_plc

        if not args.hainfo and (args.haprf is not None or args.halt is not None or args.hares is not None):
            args.hainfo = True
            
        if args.f == "random":
            error_msg = "Inserted {} is not applied in the flood mode with type Random"
            
            if args.smac:
                self.utils.errors.append(error_msg.format("source MAC"))
            if args.sip:
                self.utils.errors.append(error_msg.format("source IP"))
            if args.prefix:
                self.utils.errors.append(error_msg.format("prefix information"))
            if args.ri:
                self.utils.errors.append(error_msg.format("route information"))
            if args.ai:
                self.utils.errors.append(error_msg.format("advertisement interval"))

        if args.f is None and args.fi is not None:
            self.utils.errors.append("Argument -fi can only be used together with flood mode (-f).")

        if args.f == "constant":
            error_msg = "Inserted {} is not applied in the flood mode with type Constant"
            if args.ai:
                self.utils.errors.append(error_msg.format("advertisement interval"))
            
        if self.utils.errors:               
            if args.j:
                # JSON error reporting
                pt_json_lib = PtJsonLib()
                pt_json_lib.set_status("error", "Parameter errors encountered")
                pt_json_lib.end_error(message=str(self.utils.errors), condition=True)
                print(pt_json_lib.get_result_json())
            else:
                NonJsonOutput.print_box("Errors about inserted parameter. Try ptnetrouteradvertisement -h for help")
                for error in self.utils.errors:
                    ptprinthelper.ptprint(error, "ERROR") 

            sys.exit(1)
        else:
            self.store_parameters(args)
            if not args.j and not args.less:
                NonJsonOutput.print_box("Information about inserted parameter")
                for info in self.utils.information:
                    ptprinthelper.ptprint(info, "INFO")
                NonJsonOutput.print_box("Warning about inserted parameter")
                for warn in self.utils.warnings:
                    ptprinthelper.ptprint(warn, "WARNING")

        return args

    def error(self, message):
        specific_errors = [
            "expected one argument",
            "expected at least one argument",
            "expected at most one argument"
        ]
        if any(err in message for err in specific_errors):
            self.utils.errors.append(message[0].upper() + message[1:])

    def store_parameters(self, args):
        for arg, value in vars(args).items():
            self.parsed_params.append((arg, value))

        # Log and set defaults
        args.i = self.utils.log_and_set_default(args.i, None, "The interface to perform", "Interface is not specified")
        args.smac = self.utils.log_and_set_default(args.smac, ValidationUtils.get_mac_address(args.i), "Source MAC to perform", f"No value for source MAC is inserted. It is automatically generated from the interface: {ValidationUtils.get_mac_address(args.i)}")
        args.dmac = self.utils.log_and_set_default(args.dmac, "33:33:00:00:00:01", "Destination MAC to perform", "No value for destination MAC is inserted. It is automatically generated: 33:33:00:00:00:01")
        args.sip = self.utils.log_and_set_default(args.sip, ValidationUtils.get_ipv6_address(args.i), "Source IPv6 address to perform", f"No value for source IPv6 address is inserted. It is automatically generated from the interface: {ValidationUtils.get_ipv6_address(args.i)}")
        args.dip = self.utils.log_and_set_default(args.dip, "ff02::1", "Destination IPv6 address to perform", "No value for destination IPv6 address is inserted. It is automatically generated: ff02::1")
        args.chl = self.utils.log_and_set_default(args.chl, 0, "Current hop limit value to perform", "No value for current hop limit is inserted. It is automatically generated: 0")

        # Check all the flags
        flags_router = {
            'M': "Managed address configuration",
            'O': "Other configuration",
            'H': "Mobile IPv6 Home Agent",
            'P': "Neighbor Discovery Proxy",
            'res': "Reserved",
            'snac': "Stub Network Auto-Configuring Router"
        }

        for flag, description in flags_router.items():
            if getattr(args, flag):
                self.utils.information.append(f"{flag} ({description}) flag is set")
            else:
                self.utils.information.append(f"{flag} ({description}) flag is not set")

        args.prf = self.utils.log_and_set_default(args.prf, "High", "Router preference to perform", "No value for router preference is inserted. It is automatically generated: High")

        # Router lifetime
        args.rlt = self.utils.log_and_set_default(args.rlt, 300, "Router lifetime (in seconds) to perform", "No value for router lifetime is inserted. It is automatically generated: 300 s")
        args.rtrt = self.utils.log_and_set_default(args.rtrt, 0, "Retransmisson timer (in seconds) to perform", "No value for retransmission timer is inserted. It is automatically generated: 0 s")
        args.rcht = self.utils.log_and_set_default(args.rcht, 0, "Reachable time (in seconds) to perform", "No value for reachable time is inserted. It is automatically generated: 0 s")
        
        # Prefix option
        if args.prefix is not None:
            self.utils.information.append(f"Prefix to perform: {args.prefix}")

            flags_prefix = {
                'L': "On-link",
                'A': "Address Configuration",
                'raf': "Router Address",
                'pd': "DHCPv6-PD"
            }

            for flag, description in flags_prefix.items():
                if getattr(args, flag):
                    self.utils.information.append(f"{flag} ({description}) flag is set")
                else:
                    self.utils.information.append(f"{flag} ({description}) flag is not set")
            
            args.pres1 = self.utils.log_and_set_default(args.pres1, 0, "Prefix flags reserved bits (pres1) to perform", "No value for Prefix flags reserved bits is inserted. It is automatically generated: 0")
            args.pres2 = self.utils.log_and_set_default(args.pres2, 0, "Prefix 32-bit reserved field (pres2) to perform", "No value for Prefix 32-bit reserved field is inserted. It is automatically generated: 0")
            args.vlt = self.utils.log_and_set_default(args.vlt, 300, "Valid lifetime of prefix (in seconds) to perform", "No value for valid lifetime of prefix is inserted. It is automatically generated: 300 s")
            args.plt = self.utils.log_and_set_default(args.plt, 300, "Preferred lifetime of prefix (in seconds) to perform", "No value for preferred lifetime of prefix is inserted. It is automatically generated: 300 s")
        if args.prefix is None:
            self.utils.warnings.append("No value for prefix is inserted. The prefix information option is not included")
            
        # MTU
        args.mtu = self.utils.log_and_set_default(args.mtu, None, "Value of MTU to perform", "No value for MTU is inserted. The MTU option is not included")

        # DNS
        args.rdnss = self.utils.log_and_set_default(args.rdnss, None, "Recursive DNS Server option to perform", "No value for recursive DNS server option is inserted. This option is not included")
        args.dnssl = self.utils.log_and_set_default(args.dnssl, None, "DNS Search List option to perform", "No value for DNS search list option is inserted. This option is not included")
        args.dnslt = self.utils.log_and_set_default(args.dnslt, 300, "DNS lifetime (in seconds) to perform", "No value for DNS lifetime is inserted. It is automatically generated: 300 s")

        # Route Information
        if args.ri is not None:
            if args.ri['prefix']:
                self.utils.information.append(f"Prefix of route: {args.ri['prefix']}")
            if args.ri['prf']:
                self.utils.information.append(f"Preference of route: {args.ri['prf']}")
            if args.ri['rtlifetime']:
                self.utils.information.append(f"Lifetime in second of route: {args.ri['rtlifetime']} s")
        if args.ri is None:
            self.utils.warnings.append("No value for Route information is inserted. The route information option is not included")

        # PREF64 Option
        if args.pref64 is not None:
            self.utils.information.append(f"PREF64 NAT64 Prefix to perform: {args.pref64}")
            args.pref64lt = self.utils.log_and_set_default(args.pref64lt, 300, "PREF64 Scaled Lifetime (in seconds) to perform", "No value for PREF64 Scaled Lifetime is inserted. It is automatically generated: 300 s") 
            
            plc_map = {0: "/96", 1: "/64", 2: "/56", 3: "/48", 4: "/40", 5: "/32"}
            if args.plc is not None:
                args.plc = self.utils.log_and_set_default(args.plc, 0, f"PREF64 Prefix Length Code (PLC) to perform (maps to {plc_map.get(args.plc, 'Unknown')})", "")
            else:
                args.plc = self.utils.log_and_set_default(args.plc, 0, "PREF64 Prefix Length Code (PLC) to perform", "No value for PREF64 PLC is inserted. It is automatically generated: 0 (maps to /96)")

        if args.pref64 is None:
            self.utils.warnings.append("No value for PREF64 prefix is inserted. The PREF64 option is not included")


        if args.raflags is not None:
            self.utils.information.append(f"RA Flags Option to perform: 0x{args.raflags:012x} ({args.raflags})")
        if args.raflags is None:
            self.utils.warnings.append("No value for RA Flags is inserted. The RA Flags option is not included")


        if args.hainfo:
            self.utils.information.append("Home Agent Information option is enabled")
            args.haprf = self.utils.log_and_set_default(args.haprf, 0, "Home Agent Preference to perform", "No value for Home Agent Preference is inserted. It is automatically generated: 0")
            args.halt = self.utils.log_and_set_default(args.halt, 300, "Home Agent Lifetime (in seconds) to perform", "No value for Home Agent Lifetime is inserted. It is automatically generated: 300 s")
            args.hares = self.utils.log_and_set_default(args.hares, 0, "Home Agent Reserved field to perform", "No value for Home Agent Reserved field is inserted. It is automatically generated: 0")
        else:
            self.utils.warnings.append("Home Agent Information option is not included")

        if args.cportal is not None:
            self.utils.information.append(f"Captive-Portal URI to perform: {args.cportal}")
        if args.cportal is None:
            self.utils.warnings.append("No value for Captive-Portal URI is inserted. The Captive-Portal option is not included")
            
        # Duration and advertisement interval
        args.d = self.utils.log_and_set_default(args.d, 10, "Duration (in seconds) to perform", "No value for duration is inserted. It is automatically generated: 10 s")
        args.ai = self.utils.log_and_set_default(args.ai, args.d, "Advertisement interval (in seconds) to perform", f"No value for advertisement is inserted. It is automatically generated: {args.d} s")
        
        if args.j:
            self.utils.information.append("JSON output is enabled")
        if not args.j:
            self.utils.information.append("JSON output is disabled")

        if args.nofwd:
            self.utils.information.append("No forwarding through sender is enabled")
        if not args.nofwd:
            self.utils.information.append("Forwarding through sender is enabled")

        if args.n:
            self.utils.information.append("Temporary files is not deleted after finishing")
        if not args.n:
            self.utils.information.append("Temporary files is deleted after finishing")

        args.f = self.utils.log_and_set_default(args.f, None, "Flood mode to perform", "No value for flood mode is inserted. This option is not included")
        if args.f is not None:
            if args.fi is not None and args.fi > 0:
                self.utils.information.append(f"Flood interval between packets: {args.fi} ms (slow flood mode)")
            else:
                args.fi = 0
                self.utils.information.append("Flood interval is not set. Default fast flood mode will be performed")
        else:
            args.fi = None

def get_ip_addresses(interface):
    """ Get both IPv4 and IPv6 addresses for the given interface. """
    result = subprocess.run(["ip", "addr", "show", interface], capture_output=True, text=True)
    output = result.stdout

    # Regex patterns to capture IP addresses
    ipv4_pattern = r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)'
    ipv6_pattern = r'inet6\s+([a-fA-F0-9:]+/\d+)'
    
    ipv4_addresses = re.findall(ipv4_pattern, output)
    ipv6_addresses = re.findall(ipv6_pattern, output)

    return ipv4_addresses, ipv6_addresses

def is_ip_assigned(interface, ip_address):
    """ Check if a given IP address is already assigned to the interface. """
    result = subprocess.run(["ip", "addr", "show", interface], capture_output=True, text=True)
    return ip_address in result.stdout

def restore_ip_addresses(interface, ipv4_addresses, ipv6_addresses):
    """ Reapply the saved IP addresses to the interface, avoiding duplicates. """
    for ipv4 in ipv4_addresses:
        if not is_ip_assigned(interface, ipv4):
            subprocess.run(["sudo", "ip", "addr", "add", ipv4, "dev", interface])

    for ipv6 in ipv6_addresses:
        if not is_ip_assigned(interface, ipv6):
            subprocess.run(["sudo", "ip", "addr", "add", ipv6, "dev", interface])

def block_and_restore(interface):
    # Get the current IP addresses (IPv4 and IPv6)
    ipv4_addresses, ipv6_addresses = get_ip_addresses(interface)

    # Bring the interface down (stop communication)
    subprocess.run(["sudo", "ip", "link", "set", interface, "down"])
    
    # Wait for 1 second
    time.sleep(1)
    
    # Bring the interface back up (restore communication)
    subprocess.run(["sudo", "ip", "link", "set", interface, "up"])

    # Reapply the IP addresses (IPv4 and IPv6), avoiding duplicates
    restore_ip_addresses(interface, ipv4_addresses, ipv6_addresses)

def parse_arguments():
    parser = CustomArgumentParser(description='Perform IPv6 scanning, data retrieval, and attack simulation with Router Advertisement.')
    parser.add_argument('-d', type=partial(parser.utils.validate_non_negative_float, arg_name='duration of scanning'), help="Duration of scanning")
    parser.add_argument('-ai', type=partial(parser.utils.validate_non_negative_float, arg_name='advertisement interval'), help="Advertisement Interval. The interval at which the sending router sends unsolicited multicast Router Advertisements")
    parser.add_argument('-i', type=parser.utils.validate_interface, help="Network interface to use")
    parser.add_argument('-smac', type=partial(parser.utils.validate_mac_address, arg_name='source MAC address'), help="Source MAC address")
    parser.add_argument('-dmac', type=partial(parser.utils.validate_mac_address, arg_name='destination MAC address'), help="Destination MAC address")
    parser.add_argument('-sip', type=partial(parser.utils.validate_ipv6_address_string, arg_name='source IPv6 address'), help="Source IPv6 address")
    parser.add_argument('-dip', type=partial(parser.utils.validate_ipv6_address_string, arg_name='destination IPv6 address'), help="Destination IPv6 address")
    parser.add_argument('-M', action="store_true", help="Managed address configuration flag. When set, it indicates that addresses are available via DHCPv6")
    parser.add_argument('-O', action="store_true", help="Other configuration flag. When set, it indicates that other configuration information is available via DHCPv6")
    parser.add_argument('-H', action="store_true", help="Mobile IPv6 Home Agent flag. When set, it indicates that the router sending the Advertisement message is serving as a home agent on this link")
    parser.add_argument('-P', action="store_true", help="Neighbor Discovery Proxy flag. When set, it signals to the receiving hosts that the router is capable of acting as an ND proxy")
    parser.add_argument('-res', action="store_true", help="Reserved flag. When set, it indicates that the reserved bit in the Router Advertisement header is set")
    parser.add_argument('-snac', action="store_true", help="SNAC Router flag (Stub Network Auto-Configuring). When set, it signals that the router is a SNAC router")
    parser.add_argument('-prf', type=parser.utils.validate_prf, help="Router preference flag (High, Medium, Low, Reserved)")
    parser.add_argument('-rlt', type=partial(parser.utils.validate_non_negative_integer, arg_name='router lifetime'), help="Router Lifetime")
    parser.add_argument('-rcht', type=partial(parser.utils.validate_non_negative_integer, arg_name='reachable time'), help="Reachable Time")
    parser.add_argument('-rtrt', type=partial(parser.utils.validate_non_negative_integer, arg_name='retransmission timer'), help="Retrans Timer")
    parser.add_argument('-chl', type=partial(parser.utils.validate_integer_in_range, arg_name='current hop limit'), help="Current Hop Limit")

    parser.add_argument('-prefix', type=parser.utils.validate_ipv6_prefix, help="Prefix information advertised by the router")
    parser.add_argument('-L', action="store_true", help="On-link flag. When set, the prefix can be used for on-link determination (IPv6 addresses within that prefix are on the same L2 subnet)")
    parser.add_argument('-A', action="store_true", help="Address Configuration flag. When set, the prefix can be used for stateless address configuration")
    parser.add_argument('-raf', action="store_true", help="Router Address flag (R-bit). When set, it indicates that the prefix contains a complete IP address assigned to the sending router")
    parser.add_argument('-pd', action="store_true", help="DHCPv6 Prefix Delegation flag (P-bit). When set, it indicates that DHCPv6 Prefix Delegation is available and preferred")
    parser.add_argument('-pres1', type=parser.utils.validate_prefix_res1, help="Reserved bits in Prefix flags (4 bits, 0-15 / 0x0-0xF)")
    parser.add_argument('-pres2', type=parser.utils.validate_prefix_res2, help="Reserved 32-bit field in Prefix option (4 bytes, 0-4294967295 / 0x0-0xFFFFFFFF)")
    parser.add_argument('-vlt', type=partial(parser.utils.validate_non_negative_integer, arg_name='valid lifetime of prefix'), help="Valid Lifetime of prefix")
    parser.add_argument('-plt', type=partial(parser.utils.validate_non_negative_integer, arg_name='preferred lifetime of prefix'), help="Preferred Lifetime of prefix")

    parser.add_argument('-mtu', type=partial(parser.utils.validate_non_negative_integer, arg_name= 'MTU'), help="MTU")
    parser.add_argument('-dnssl', nargs="+", help="DNS Search List Option (DNS suffixes)")
    parser.add_argument('-rdnss', nargs="+", help="Recursive DNS Server Option")
    parser.add_argument('-dnslt', type=partial(parser.utils.validate_non_negative_integer, arg_name='DNS lifetime'), help="DNS lifetime (in seconds) for RDNSS and DNSSL options")
    parser.add_argument('-ri', type=partial(parser.utils.validate_ri_parameter, arg_name='route information'), help="Route Information Option. When defined, indicates whether to prefer the router associated with this prefix over others, when multiple identical prefixes (for different routers) have been received")

    # PREF64 Option parameters
    parser.add_argument('-pref64', type=parser.utils.validate_pref64_prefix, help="The NAT64 prefix to be advertised.")
    parser.add_argument('-pref64lt', type=partial(parser.utils.validate_non_negative_integer, arg_name='PREF64 lifetime'), help="Scaled Lifetime for the NAT64 prefix in seconds.")
    parser.add_argument('-plc', type=partial(parser.utils.validate_integer_in_range, arg_name='Prefix Length Code', min_value=0, max_value=5), help="Prefix Length Code (0-5).")

    # IPv6 RA Flags Option parameters
    parser.add_argument('-raflags', type=parser.utils.validate_ra_flags, help="IPv6 Router Advertisement Flags Option (48-bit bit field, 0 to 281474976710655 / 0x0 to 0xFFFFFFFFFFFF)")

    # Home Agent Information Option parameters
    parser.add_argument('-hainfo', action="store_true", help="Home Agent Information Option. When set, Home Agent Information option is included")
    parser.add_argument('-haprf', type=partial(parser.utils.validate_integer_in_range, arg_name='Home Agent Preference', min_value=0, max_value=65535), help="Home Agent Preference (0-65535) for Home Agent Information option")
    parser.add_argument('-halt', type=partial(parser.utils.validate_integer_in_range, arg_name='Home Agent Lifetime', min_value=0, max_value=65535), help="Home Agent Lifetime in seconds (0-65535) for Home Agent Information option")
    parser.add_argument('-hares', type=parser.utils.validate_ha_res, help="Reserved 16-bit field (0-65535 / 0x0-0xFFFF) for Home Agent Information option")

    # Captive-Portal Option parameters
    parser.add_argument('-cportal', type=parser.utils.validate_captive_portal_uri, help="Captive-Portal Option. URI of the captive portal API endpoint (e.g. https://portal.example.com)")
    
    parser.add_argument('-nofwd', action="store_true", default=False, help="Do not allow packets to go through the sender (MiTM)")
    parser.add_argument('-j', action="store_true", default=False, help="Allow json output")
    parser.add_argument('-n', action="store_true", default=False, help="Do not delete temporary files after finishing")
    parser.add_argument('-less', action="store_true", help="Showing only the vulnerabilities of network and hosts") 
    parser.add_argument("-f", type=parser.utils.validate_flood, help="Flood the target with option: sending RA messages using only the defined addresses (constant), or sending RA messages with many random addresses and prefixes (random)")
    parser.add_argument("-fi", type=parser.utils.validate_flood_interval, help="Flood interval in milliseconds between packets in flood mode (-f) for slow flood. Must be greater than 0. Default: not set (fast flood)")

    # Print help message if no arguments provided or "-h" is used
    if len(sys.argv) == 1 or "-h" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()

    # if parser.utils.errors:
    #     NonJson.print_box("Errors about inserted parameter")
    #     for error in parser.utils.errors:
    #         ptprinthelper.ptprint(error, "ERROR")
    #     sys.exit(1)

    return args

def get_help():
    return [
        {"description": ["Perform IPv6 scanning, data retrieval, and attack simulation with Router Advertisement."]},
        {"usage": ["ptnetrouteradvertisement -i eth0 -prefix 2001::/64 -A -L -less"]},
        {"General parameters": [
            ["-i", "  Network interface to use (required)."],
            ["-smac", "  Source MAC address. Auto-generated from the interface if not provided."],
            ["-dmac", "  Destination MAC address. Default: 33:33:00:00:00:01."],
            ["-sip", "  Source IPv6 address. Auto-generated from the interface if not provided (prefers link-local)."],
            ["-dip", "  Destination IPv6 address. Default: ff02::1."],
            ["-M", "  Managed Address Configuration flag. Indicates addresses available via DHCPv6 when set. Default: 0 (Not set)."],
            ["-O", "  Other Configuration flag. Indicates other DHCPv6 configuration information available when set. Default: 0 (Not set)."],
            ["-H", "  Mobile IPv6 Home Agent flag. Indicates the router is serving as a home agent on this link when set. Default: 0 (Not set)."],
            ["-P", "  Neighbor Discovery Proxy flag. Signals the router can act as an ND proxy when set. Default: 0 (Not set)."],
            ["-res", "  Reserved flag. Sets the reserved bit in the RA header when set. Default: 0 (Not set)."],
            ["-snac", "  SNAC Router flag (Stub Network Auto-Configuring). Signals that the router is a SNAC router when set. Default: 0 (Not set)."],
            ["-prf", "  Router Preference flag (High, Medium, Low, Reserved). Default: High."],
            ["-rlt", "  Router Lifetime in seconds. Default: 300 s."],
            ["-rcht", "  Reachable Time in seconds. Default: 300 s."],
            ["-rtrt", "  Retrans Timer in seconds. Default: 300 s."],
            ["-chl", "  Current Hop Limit. Default: 0."],
            ["-nofwd", "  Do not allow any traffic through the sender. Default: Not set (allow MiTM)."],
            ["-j", "  Allow JSON output. Terminal output only if not set."],
            ["-n", "  Do not delete temporary files after finishing. Temporary files removed if not set."],
            ["-d", "  Duration of scanning in seconds. Default: 10 s."],
            ["-ai", "  Advertisement interval in seconds. Not usable in flood mode (-f). Default: same as duration."],
            ["-f", "  Flood target with RA messages with the same inserted parameters, or random parameters using: -f constant or -f random, respectively. Not included if not set."],
            ["-fi", "  Flood interval in milliseconds between packets in flood mode (-f) for slow flood. Must be greater than 0. Default: not set (fast flood). Usable only together with -f."],
            ["-less", "  Showing only the vulnerabilities of network and hosts. Default: Not set. Displaying both vulnerabilities and json information when combined with +j."],
            ["-h", "  Show this help message and exit."]
        ]},
        {"Prefix Option parameters": [
            ["-prefix", " Prefix Information advertised by the router. Not included if not set."],
            ["-L", " On-link flag. Prefix can be used for on-link determination when set. Default: 0 (Not set). Usable only together with -prefix."],
            ["-A", " Address Configuration flag. Prefix can be used for SLAAC when set. Default: 0 (Not set). Usable only together with -prefix."],
            ["-raf", " Router Address flag. Prefix contains complete IP address of the router when set. Default: 0 (Not set). Usable only together with -prefix."],
            ["-pd", " DHCPv6-PD flag. Indicates DHCPv6-PD availability/preference when set. Default: 0 (Not set). Usable only together with -prefix."],
            ["-pres1", " Reserved bits in Prefix flags (4 bits). Allowed range: 0-15 (or 0x0-0xF). Default: 0. Usable only together with -prefix."],
            ["-pres2", " Reserved 32-bit field in Prefix option (4 bytes). Allowed range: 0-4294967295 (or 0x0-0xFFFFFFFF). Default: 0. Usable only together with -prefix."],
            ["-vlt", " Valid Lifetime of prefix in seconds. Default: 300 s. Usable only together with -prefix."],
            ["-plt", " Preferred Lifetime of prefix in seconds. Default: 300 s. Usable only together with -prefix."]
        ]},
        {"DNS Option parameters": [
            ["-dnssl", "  DNS Search List Option (DNS suffixes). Multiple suffixes can be inserted (separated by space). Not included if not set."],
            ["-rdnss", "  Recursive DNS Server Option. Multiple addresses can be inserted (separated by space). Not included if not set."],
            ["-dnslt", "  DNS Lifetime in seconds for RDNSS and DNSSL options. Default: 300 s."]
        ]},
        {"PREF64 Option parameters": [
            ["-pref64", " The NAT64 prefix to be advertised. Not included if not set."],
            ["-pref64lt", " Scaled Lifetime for the NAT64 prefix in seconds. Default: 300s. Usable only with -pref64."],
            ["-plc", " Prefix Length Code (0-5). Defines the prefix length (0=/96, 1=/64, 2=/56, 3=/48, 4=/40, 5=/32). Default: 0. Usable only with -pref64."]
        ]},
        {"IPv6 RA Flags Option parameters": [
            ["-raflags", " IPv6 Router Advertisement Flags Option. 48-bit flags value (0-281474976710655 / 0x0-0xFFFFFFFFFFFF). Not included if not set."]
        ]},
        {"Home Agent Information Option parameters": [
            ["-hainfo", " Home Agent Information Option. Indicates inclusion of Home Agent Information. Not included if not set."],
            ["-haprf", " Home Agent Preference (0-65535). Default: 0. Usable only with Home Agent Information option."],
            ["-halt", " Home Agent Lifetime in seconds (0-65535). Default: 300 s. Usable only with Home Agent Information option."],
            ["-hares", " Reserved 16-bit field (0-65535 / 0x0-0xFFFF). Default: 0. Usable only with Home Agent Information option."]
        ]},
        {"Captive-Portal Option parameters": [
            ["-cportal", " Captive-Portal Option. URI of the captive portal API endpoint. Not included if not set."]
        ]},
        {"Other Option parameters": [
            ["-mtu", "    MTU advertised as an option. Not included if not set."],
            ["-ri", "    Route Information Option. Indicates router preference when multiple identical prefixes received. Not included if not set."]
        ]},
        {"Examples": [
            ["Send mode:", "Run send mode with interface eth0, within 30 s, JSON output, advertised prefix, SLAAC mode and showing only vulnerabilities"],
            ["", "ptnetrouteradvertisement -i eth0 -d 30, -j -prefix 2001::/64 -A -L -less"],
            ["Send mode:", "Run send mode with interface eth0, advertised prefix, SLAAC mode, Route information: prefix 2001:dead::/64, preference High and route lifetime 100 s"],
            ["", "ptnetrouteradvertisement -i eth0 -prefix 2001::/64 -A -L -ri 'prf=High;rtlifetime=100;prefix=2001:dead::/64'"],
            ["Send mode:", "Run send mode with interface eth0, advertised prefix, SLAAC mode, multiple DNS suffixes, and multiple recursive DNS servers"],
            ["", "ptnetrouteradvertisement -i eth0 -prefix 2001::/64 -A -L -rdnss 2001::1 2002::2 -dnssl fekt.cz aws.com"],
            ["Flood mode:", "Flood the network with interface eth0, within 30 s, and random multiple options and parameters"],
            ["", "ptnetrouteradvertisement -i eth0 -f random -d 30"],
            ["Flood mode (slow):", "Flood the network with interface eth0, random parameters, with 50 ms delay between packets"],
            ["", "ptnetrouteradvertisement -i eth0 -f random -fi 50 -d 30"],
        ]}
    ]