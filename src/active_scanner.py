import csv
import ipaddress
import psutil
from scapy.all import *
from scapy.layers.inet import Ether, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptMTU, ICMPv6NDOptDNSSL, ICMPv6NDOptRDNSS, ICMPv6NDOptRouteInfo, ICMPv6NDOptAdvInterval, ICMPv6NDOptEFA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptPREF64, ICMPv6NDOptHAInfo, ICMPv6EchoRequest, IPv6ExtHdrDestOpt, HBHOptUnknown, ICMPv6ND_RS, IPv6ExtHdrHopByHop, RouterAlert, ICMPv6MLQuery2, ICMPv6MLQuery, icmp6ndopts
from scapy.fields import ByteEnumField, ByteField, BitField, StrField, ShortField
from scapy.packet import Packet
from scapy.config import conf

# RFC 5175 - IPv6 Router Advertisement Flags Option (Type 26)
class ICMPv6NDOptRAFlags(Packet):
    name = "ICMPv6 Neighbor Discovery Option - RA Flags"
    fields_desc = [
        ByteEnumField("type", 26, icmp6ndopts),
        ByteField("len", 1),
        BitField("flags", 0, 48),
    ]

    def extract_padding(self, p):
        return b"", p

    def default_payload_class(self, p):
        return conf.padding_layer

# RFC 8910 / RFC 7710 - Captive-Portal Option (Type 37)
class ICMPv6NDOptCaptivePortal(Packet):
    name = "ICMPv6 Neighbor Discovery Option - Captive Portal"
    fields_desc = [
        ByteEnumField("type", 37, icmp6ndopts),
        ByteField("len", None),
        StrField("uri", ""),
    ]

    def post_build(self, p, pay):
        uri_val = self.getfieldval("uri")
        uri_bytes = uri_val.encode('utf-8') if isinstance(uri_val, str) else (uri_val or b"")
        opt_len = self.len if self.len is not None else ((len(uri_bytes) + 2 + 7) // 8)
        pad_len = max(0, (opt_len * 8) - 2 - len(uri_bytes))
        p = bytes([p[0], opt_len]) + uri_bytes + (b'\x00' * pad_len)
        return p + pay

    def extract_padding(self, p):
        if self.len:
            opt_total_len = self.len * 8
            uri_and_pad_len = max(0, opt_total_len - 2)
            return p[:uri_and_pad_len], p[uri_and_pad_len:]
        return p, b""

    def default_payload_class(self, p):
        return conf.padding_layer

try:
    from scapy.layers.inet6 import _nd_opt_cls
    _nd_opt_cls[26] = ICMPv6NDOptRAFlags
    _nd_opt_cls[37] = ICMPv6NDOptCaptivePortal
except Exception:
    pass
import time
from src.csv_process import Flood, has_data_csv
from src.utils import ValidationUtils
from src.passive_scanner import PassiveScanner
from ptlibs import ptprinthelper
import random

# Global flag to stop the packet sending
stop_sending = False

class ActiveScanner:
    def __init__(self, duration, advertisement_interval, interface, src_MAC, dst_MAC, src_IP, dst_IP, M_flag, O_flag, H_flag, P_flag, Res_flag, snac_flag, Prf_flag, Router_lifetime, Reachable_time, Retrans_timer, Cur_hop_limit, Prefix=None, L_flag=None, A_flag=None, RAF_flag=None, PD_flag=None, pres1=0, pres2=0, Valid_lifetime=None, Preferred_lifetime=None, MTU=None, DNS_search_list=None, DNS_server=None, Route_info=None, DNS_lifetime=None, flood=None, flood_interval=None, Pref64=None, Pref64_lifetime=None, PLC=None, ra_flags=None, hainfo=False, ha_pref=None, ha_lifetime=None, ha_res=None, cportal=None):
        self.duration = duration
        self.advertisement_interval = advertisement_interval
        self.interface = interface
        self.src_MAC = src_MAC
        self.dst_MAC = dst_MAC
        self.src_IP = src_IP
        self.dst_IP = dst_IP
        self.M_flag = M_flag
        self.O_flag = O_flag
        self.H_flag = H_flag
        self.P_flag = P_flag
        self.Res_flag = Res_flag
        self.snac_flag = snac_flag
        self.Prf_flag = Prf_flag
        self.Router_lifetime = Router_lifetime
        self.Reachable_time = Reachable_time
        self.Retrans_timer = Retrans_timer
        self.Cur_hop_limit = Cur_hop_limit
        self.Prefix = Prefix
        self.L_flag = L_flag
        self.A_flag = A_flag
        self.RAF_flag = RAF_flag
        self.PD_flag = PD_flag
        self.pres1 = pres1 if pres1 is not None else 0
        self.pres2 = pres2 if pres2 is not None else 0
        self.Valid_lifetime = Valid_lifetime
        self.Preferred_lifetime = Preferred_lifetime
        self.DNS_search_list = DNS_search_list
        self.DNS_server = DNS_server
        self.MTU = MTU
        self.Route_info = Route_info
        self.DNS_lifetime = DNS_lifetime
        self.flood = flood
        self.flood_interval = flood_interval
        self.Pref64 = Pref64
        self.Pref64_lifetime = Pref64_lifetime
        self.PLC = PLC
        self.ra_flags = ra_flags
        self.hainfo = hainfo
        self.ha_pref = ha_pref
        self.ha_lifetime = ha_lifetime
        self.ha_res = ha_res
        self.cportal = cportal

    def generate_random_mac():
        return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

    def generate_random_ipv6_link_local():
        # Generate a random interface identifier (64 bits)
        random_interface_id = random.randint(1, 2**64 - 1)
        
        # Format the IPv6 link-local address with the fe80::/64 prefix
        random_link_local = "fe80::{:x}:{:x}:{:x}:{:x}".format(
            (random_interface_id >> 48) & 0xffff,
            (random_interface_id >> 32) & 0xffff,
            (random_interface_id >> 16) & 0xffff,
            random_interface_id & 0xffff
        )
    
        return random_link_local
    
    def generate_random_ipv6_prefix():
        # Generate random 64-bit network prefix
        prefix_bits = random.getrandbits(64)
        
        # Convert to IPv6 address
        prefix = ipaddress.IPv6Address(prefix_bits << 64)
        
        # Return prefix in standard notation with /64 prefix length
        return f"{prefix}"

    def create_ra_packet(self):
        # Create Ethernet frame
        ether = Ether(src=self.src_MAC, dst=self.dst_MAC)

        # Create IPv6 packet
        ipv6 = IPv6(src=self.src_IP, dst=self.dst_IP)
        
        prf_value = ValidationUtils.convert_preference_to_int(self.Prf_flag)
        ra_res = (2 if self.snac_flag else 0) | (1 if self.Res_flag else 0)
        # Create ICMPv6 Router Advertisement
        ra = ICMPv6ND_RA(
            chlim=self.Cur_hop_limit,
            M=self.M_flag,
            O=self.O_flag,
            H=self.H_flag,
            P=self.P_flag,
            res=ra_res,
            prf=prf_value,
            routerlifetime=self.Router_lifetime,
            reachabletime=self.Reachable_time,
            retranstimer=self.Retrans_timer
        )
        
        # Create options
        options = [ICMPv6NDOptSrcLLAddr(lladdr=self.src_MAC)]
        
        if self.MTU is not None:
            options.append(ICMPv6NDOptMTU(mtu=self.MTU))
        
        if self.Prefix is not None:
            prefix, prefixlen = ValidationUtils.get_ipv6_prefix_details(self.Prefix)
            if prefix is not None or prefixlen is not None:
                prefix_res1 = (16 if self.PD_flag else 0) | (self.pres1 & 0x0F)
                options.append(ICMPv6NDOptPrefixInfo(
                    prefix=prefix,
                    prefixlen=prefixlen,
                    L=self.L_flag,
                    A=self.A_flag,
                    R=1 if self.RAF_flag else 0,
                    res1=prefix_res1,
                    res2=self.pres2,
                    validlifetime=self.Valid_lifetime,
                    preferredlifetime=self.Preferred_lifetime
                ))
        
        if self.DNS_server is not None:
            options.append(ICMPv6NDOptRDNSS(lifetime=self.DNS_lifetime, dns=self.DNS_server))
        
        if self.DNS_search_list is not None:
            options.append(ICMPv6NDOptDNSSL(lifetime=self.DNS_lifetime, searchlist=self.DNS_search_list))
        
        if self.Route_info is not None:
            route_preference = ValidationUtils.convert_preference_to_int(self.Route_info['prf'])
            route_prefix = self.Route_info['prefix']
            prefix, prefixlen = ValidationUtils.get_ipv6_prefix_details(route_prefix)
            route_lifetime = self.Route_info['rtlifetime']
            options.append(ICMPv6NDOptRouteInfo(prf=route_preference, rtlifetime=route_lifetime, prefix=prefix, plen=prefixlen))

        if self.Pref64 is not None:
            # Scaled Lifetime is a 13-bit field (0-8191) in units of 8 seconds (RFC 8781)
            scaled_lifetime = min(8191, int(self.Pref64_lifetime // 8)) if self.Pref64_lifetime is not None else 0
            options.append(ICMPv6NDOptPREF64(
                scaledlifetime=scaled_lifetime,
                plc=self.PLC,
                prefix=self.Pref64
            ))

        if self.ra_flags is not None:
            options.append(ICMPv6NDOptRAFlags(flags=self.ra_flags))

        if self.hainfo or self.ha_pref is not None or self.ha_lifetime is not None or self.ha_res is not None:
            ha_res = self.ha_res if self.ha_res is not None else 0
            ha_pref = self.ha_pref if self.ha_pref is not None else 0
            ha_lifetime = self.ha_lifetime if self.ha_lifetime is not None else 300
            options.append(ICMPv6NDOptHAInfo(res=ha_res, pref=ha_pref, lifetime=ha_lifetime))

        if self.cportal is not None:
            options.append(ICMPv6NDOptCaptivePortal(uri=self.cportal))

        # Construct the full packet
        packet = ether / ipv6 / ra
        for option in options:
            packet /= option
    
        # Handle flood logic
        if self.flood is None:
            return packet
        elif self.flood == 'constant':
            return [packet] * 100
        elif self.flood == 'random':
            packets = []
            for _ in range(100):
                random_src_mac = ActiveScanner.generate_random_mac()
                random_src_ip = ActiveScanner.generate_random_ipv6_link_local()
                rand_ether = Ether(src=random_src_mac, dst=self.dst_MAC)
                rand_ipv6 = IPv6(src=random_src_ip, dst=self.dst_IP)
                rand_options = [ICMPv6NDOptSrcLLAddr(lladdr=random_src_mac)]
                
                # Add random ICMPv6NDOptPrefixInfo options
                rand_prefix = ActiveScanner.generate_random_ipv6_prefix()
                rand_prefixlen = random.randint(64, 128)
                rand_options.append(ICMPv6NDOptPrefixInfo(
                    prefix=rand_prefix,
                    prefixlen=64,
                    L=True,
                    A=True,
                    validlifetime=self.Router_lifetime,
                    preferredlifetime=self.Router_lifetime
                ))

                # Add random ICMPv6NDOptRouteInfo options
                rand_route_prefix = ActiveScanner.generate_random_ipv6_prefix()
                rand_route_prefixlen = 64
                rand_options.append(ICMPv6NDOptRouteInfo(
                    prf=0x01,  # High preference
                    rtlifetime=self.Router_lifetime,
                    prefix=rand_route_prefix,
                    plen=rand_route_prefixlen
                ))
                
                # Add the other default options except the first one
                rand_options.extend(options[1:])
                
                rand_packet = rand_ether / rand_ipv6 / ra
                for option in rand_options:
                    rand_packet /= option
                packets.append(rand_packet)

                Flood(random_src_mac, random_src_ip, rand_prefix, rand_route_prefix).save_packet("src/tmp")

            return packets

    def send_kill_ra_packet(self):
        
        if self.flood == 'random':
            packets = []
            if not has_data_csv('src/tmp/random_flood.csv'):
                return
            
            # Open the file and read the header
            with open('src/tmp/random_flood.csv', 'r', newline='') as csv_file:
                csv_reader = csv.reader(csv_file)
                csv_header = next(csv_reader)

                # Indexes of relevant columns
                src_mac_index = csv_header.index('src_MAC')
                src_ip_index = csv_header.index('src_IP')
                prefix_index = csv_header.index('Prefix')
                route_prefix_index = csv_header.index('Route_prefix')

                # Check for the legitimate default router being stolen
                for row in csv_reader:
                    # Create Ethernet frame
                    ether = Ether(src=row[src_mac_index], dst=self.dst_MAC)
                    
                    # Create IPv6 packet
                    ipv6 = IPv6(src=row[src_ip_index], dst=self.dst_IP)
                    
                    prf_value = ValidationUtils.convert_preference_to_int(self.Prf_flag)
                    ra_res = (2 if self.snac_flag else 0) | (1 if self.Res_flag else 0)
                    # Create ICMPv6 Router Advertisement with all timers set to 0
                    ra = ICMPv6ND_RA(
                        chlim=self.Cur_hop_limit,
                        M=self.M_flag,
                        O=self.O_flag,
                        H=self.H_flag,
                        P=self.P_flag,
                        res=ra_res,
                        prf=prf_value,
                        routerlifetime=0,  # Set Router Lifetime to 0
                        reachabletime=0,   # Set Reachable Time to 0
                        retranstimer=0     # Set Retrans Timer to 0
                    )
                    
                    # Create options with relevant lifetimes set to 0
                    options = [ICMPv6NDOptSrcLLAddr(lladdr=row[src_mac_index])]
                    
                    if self.MTU is not None:
                        options.append(ICMPv6NDOptMTU(mtu=self.MTU))
                    
                    options.append(ICMPv6NDOptPrefixInfo(
                        prefix=row[prefix_index],
                        prefixlen=64,
                        L=True,
                        A=True,
                        validlifetime=0,      # Set Valid Lifetime to 0
                        preferredlifetime=0   # Set Preferred Lifetime to 0
                    ))
                    
                    if self.DNS_server is not None:
                        options.append(ICMPv6NDOptRDNSS(lifetime=0, dns=self.DNS_server))  # Set RDNSS Lifetime to 0
                    
                    if self.DNS_search_list is not None:
                        options.append(ICMPv6NDOptDNSSL(lifetime=0, searchlist=self.DNS_search_list))  # Set DNSSL Lifetime to 0

                    if self.Pref64 is not None:
                        options.append(ICMPv6NDOptPREF64(scaledlifetime=0, plc=self.PLC, prefix=self.Pref64))
                    

                    route_preference = 0x01
                    route_prefix = row[route_prefix_index]
                    prefix, prefixlen = ValidationUtils.get_ipv6_prefix_details(route_prefix)
                    route_lifetime = 0
                    options.append(ICMPv6NDOptRouteInfo(prf=route_preference, rtlifetime=route_lifetime, prefix=prefix, plen=prefixlen))
                    
                    # Construct the full packet
                    packet = ether / ipv6 / ra
                    for option in options:
                        packet /= option
                    packets.append(packet)
            
            sendp(packets, iface=self.interface, verbose=False)

        else:
            # Create Ethernet frame
            ether = Ether(src=self.src_MAC, dst=self.dst_MAC)
            
            # Create IPv6 packet
            ipv6 = IPv6(src=self.src_IP, dst=self.dst_IP)
            
            prf_value = ValidationUtils.convert_preference_to_int(self.Prf_flag)
            ra_res = (2 if self.snac_flag else 0) | (1 if self.Res_flag else 0)
            # Create ICMPv6 Router Advertisement with all timers set to 0
            ra = ICMPv6ND_RA(
                chlim=self.Cur_hop_limit,
                M=self.M_flag,
                O=self.O_flag,
                H=self.H_flag,
                P=self.P_flag,
                res=ra_res,
                prf=prf_value,
                routerlifetime=0,  # Set Router Lifetime to 0
                reachabletime=0,   # Set Reachable Time to 0
                retranstimer=0     # Set Retrans Timer to 0
            )
            
            # Create options with relevant lifetimes set to 0
            options = [ICMPv6NDOptSrcLLAddr(lladdr=self.src_MAC)]
            
            if self.MTU is not None:
                options.append(ICMPv6NDOptMTU(mtu=self.MTU))
            
            if self.Prefix is not None:
                prefix, prefixlen = ValidationUtils.get_ipv6_prefix_details(self.Prefix)
                if prefix is not None or prefixlen is not None:
                    prefix_res1 = (16 if self.PD_flag else 0) | (self.pres1 & 0x0F)
                    options.append(ICMPv6NDOptPrefixInfo(
                        prefix=prefix,
                        prefixlen=prefixlen,
                        L=self.L_flag,
                        A=self.A_flag,
                        R=1 if self.RAF_flag else 0,
                        res1=prefix_res1,
                        res2=self.pres2,
                        validlifetime=0,      # Set Valid Lifetime to 0
                        preferredlifetime=0   # Set Preferred Lifetime to 0
                    ))
            
            if self.DNS_server is not None:
                options.append(ICMPv6NDOptRDNSS(lifetime=0, dns=self.DNS_server))  # Set RDNSS Lifetime to 0
            
            if self.DNS_search_list is not None:
                options.append(ICMPv6NDOptDNSSL(lifetime=0, searchlist=self.DNS_search_list))  # Set DNSSL Lifetime to 0
            
            if self.Route_info is not None:
                route_preference = ValidationUtils.convert_preference_to_int(self.Route_info['prf'])
                route_prefix = self.Route_info['prefix']
                prefix, prefixlen = ValidationUtils.get_ipv6_prefix_details(route_prefix)
                route_lifetime = 0
                options.append(ICMPv6NDOptRouteInfo(prf=route_preference, rtlifetime=route_lifetime, prefix=prefix, plen=prefixlen))

            if self.Pref64 is not None:
                options.append(ICMPv6NDOptPREF64(scaledlifetime=0, plc=self.PLC, prefix=self.Pref64))

            if self.ra_flags is not None:
                options.append(ICMPv6NDOptRAFlags(flags=self.ra_flags))

            if self.hainfo or self.ha_pref is not None or self.ha_lifetime is not None or self.ha_res is not None:
                ha_res = self.ha_res if self.ha_res is not None else 0
                ha_pref = self.ha_pref if self.ha_pref is not None else 0
                options.append(ICMPv6NDOptHAInfo(res=ha_res, pref=ha_pref, lifetime=0))

            if self.cportal is not None:
                options.append(ICMPv6NDOptCaptivePortal(uri=self.cportal))

            # Construct the full packet
            packet = ether / ipv6 / ra
            for option in options:
                packet /= option
            
            sendp(packet, iface=self.interface, verbose=False)
    
    def get_network_stats(self):
        net_stats = psutil.net_io_counters(pernic=True)
        if self.interface in net_stats:
            return net_stats[self.interface].packets_sent, net_stats[self.interface].bytes_sent
        else:
            raise ValueError(f"Interface {self.interface} not found.")

    def calculate_traffic_rates(self, interval=1):
        packets_sent_start, bytes_sent_start = self.get_network_stats()
        time.sleep(interval)
        packets_sent_end, bytes_sent_end = self.get_network_stats()

        pps = (packets_sent_end - packets_sent_start) / interval
        bps = (bytes_sent_end - bytes_sent_start) / interval

        return int(pps), int(bps)

    def show_traffic_stats(self, start_time):
        while (time.time() - start_time) < self.duration:
            pps, bps = self.calculate_traffic_rates(interval=1)

            # Call ptprint for the traffic stats output
            ptprinthelper.ptprint(
                string=f"Packets per second (PPS): {pps:<10}    Bytes per second (BPS): {bps:<15}",
                bullet_type="INFO",   # Keep the bullet type TEXT as default
                end='',               # Same as the original print, no newline
                flush=True,           # Immediate output
                clear_to_eol=True     # Clear the remaining part of the line
            )

            # Add a carriage return manually at the start of the next print call to move back to the start of the line
            # Move the cursor to the end of the printed string using ANSI escape sequences
            print(f"\r", end='')  # \033[{n}C moves the cursor 'n' positions to the right

            time.sleep(1)

        # Move to a new line after the loop finishes
        ptprinthelper.ptprint(string="\n", end="\n")
    

    def send_ra_packet(self):
        """
        Send RA packet in regular intervals when flooding is not requested.
        """
        packet = self.create_ra_packet()

        # Run in a loop until the specified duration
        end_time = time.time() + self.duration
        while time.time() < end_time:
            packet = self.create_ra_packet()  # Re-create packet for each interval
            sendp(packet, iface=self.interface, verbose=False)  # Send RA packet
            time.sleep(self.advertisement_interval)  # Wait for the next interval

        # # Send a final "kill" RA packet if flood mode is not random
        # if self.flood not in ['random']:
        #     self.send_kill_ra_packet()

    def send_flood_ra_packet(self):
        """
        Flood the network with RA packets either at a constant or random mode.
        """
        # Avoid too short duration
        if self.duration < 0.5:
            return
        
        if self.flood_interval is not None and self.flood_interval > 0:
            sleep_seconds = self.flood_interval / 1000.0
            while not stop_sending:
                packets = self.create_ra_packet()
                if isinstance(packets, list):
                    for pkt in packets:
                        if stop_sending:
                            break
                        sendp(pkt, iface=self.interface, verbose=False)
                        time.sleep(sleep_seconds)
                else:
                    sendp(packets, iface=self.interface, verbose=False)
                    time.sleep(sleep_seconds)
        else:
            packet = self.create_ra_packet()
            while not stop_sending:
                # Run sendpfast for the specified duration
                a = sendpfast(packet, pps = 10000, loop=10, parse_results=True, iface=self.interface)

    def stop_program(self):
        global stop_sending
        # Wait for inserted seconds before stopping the program
        time.sleep(self.duration)
        # Set the stop flag to True to stop sending packets
        stop_sending = True

    def send_ping_packet(self):
        '''Create and send several types of ping (normal, malicious) to the target'''
        packets = []
        def append_packets(packet_list, *packets):
            packet_list.extend(packets)

        for sip in ValidationUtils.get_interface_ips(self.interface):
            # Create Ethernet frame
            ether = Ether(src=self.src_MAC, dst=self.dst_MAC)
            
            # Create IPv6 packet
            ipv6 = IPv6(src=sip, dst=self.dst_IP)

            # Normal IPv6 Ping
            pkt1 = ether / ipv6 / ICMPv6EchoRequest()

            # Ping with Unknown Option
            pkt2 = ether / ipv6 / IPv6ExtHdrDestOpt(nh=58, options=[HBHOptUnknown(otype=128)]) / ICMPv6EchoRequest()

            # Malicious ICMPv6
            pkt3 = ether / ipv6 / IPv6ExtHdrDestOpt(nh=58, options=[HBHOptUnknown(otype=128)]) / ICMPv6EchoRequest(type=254)

            # Append packets to the list
            append_packets(packets, pkt1, pkt2, pkt3)

            # Send the packets
            sendp(packets, iface=self.interface, verbose=False)
    
    def send_multicast_ping_packet(self):
        '''Create and send several types of ping (normal, malicious) to multicast'''
        packets = []
        def append_packets(packet_list, *packets):
            packet_list.extend(packets)

        for sip in ValidationUtils.get_interface_ips(self.interface):
            # Create Ethernet frame
            ether = Ether(src=self.src_MAC, dst="33:33:00:00:00:01")

            # Create IPv6 packet
            ipv6 = IPv6(src=sip, dst="ff02::1")

            # Normal IPv6 Ping
            pkt1 = ether / ipv6 / ICMPv6EchoRequest()

            # Ping with Unknown Option
            pkt2 = ether / ipv6 / IPv6ExtHdrDestOpt(nh=58, options=[HBHOptUnknown(otype=128)]) / ICMPv6EchoRequest()

            # Malicious ICMPv6
            pkt3 = ether / ipv6 / IPv6ExtHdrDestOpt(nh=58, options=[HBHOptUnknown(otype=128)]) / ICMPv6EchoRequest(type=254)

            # Append packets to the list
            append_packets(packets, pkt1, pkt2, pkt3)

            # Send the packets
            sendp(packets, iface=self.interface, verbose=False)
    
    def send_rs_packet(self):
        '''Send Router Solicitation packet to find routers'''
        # Create Ethernet frame
        ether = Ether(src=self.src_MAC, dst="33:33:00:00:00:02")
        
        # Create IPv6 packet
        ipv6 = IPv6(src=self.src_IP, dst="ff02::2", hlim=255)

        # Normal IPv6 Ping
        pkt = ether / ipv6 / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=self.src_MAC)

        # Send the packets
        sendp(pkt, iface=self.interface, verbose=False)
    
    def send_ptr_ipv6_mdns(self, ipv6_address_target):
        '''Function to send an IPv6 mDNS PTR query and save the response to get the local name'''
        query = ValidationUtils.reverse_IPadd(ipv6_address_target)
        if query is None:
            return

        interface_ip_addresses = ValidationUtils.get_interface_ips(self.interface)
        if not interface_ip_addresses:
            return

        if ipv6_address_target in interface_ip_addresses or ipv6_address_target == self.src_IP[:-5]:
            return

        # Construct the mDNS packet with the PTR query
        pkt = (Ether(src=self.src_MAC, dst="33:33:00:00:00:fb") /
               IPv6(src=self.src_IP, dst="ff02::fb", hlim=1) /
               UDP(sport=53530, dport=5353) /
               DNS(rd=1, qd=DNSQR(qname=query, qtype=12)))

        try:
            # Send the mDNS packet
            ans, uans = srp(pkt, multi=True, timeout=0.2, iface=self.interface, verbose=False)
            # Parse the domain name from the response
            if ans:
                rdata = ans[0][1][DNS].an.rdata
                if isinstance(rdata, bytes):
                    return rdata.decode()
                return rdata
        except Exception:
            return None
    
    def send_ptr_ipv6_llmnr(self, ipv6_address_target):
        '''Function to send an IPv6 LLMNR PTR query and save the response to get the local name'''
        query = ValidationUtils.reverse_IPadd(ipv6_address_target)
        if query is None:
            return

        interface_ip_addresses = ValidationUtils.get_interface_ips(self.interface)
        if not interface_ip_addresses:
            return

        if ipv6_address_target in interface_ip_addresses or ipv6_address_target == self.src_IP[:-5]:
            return

        # Construct the LLMNR packet with the PTR query
        pkt = (Ether(src=self.src_MAC, dst="33:33:00:01:00:03") /
               IPv6(src=self.src_IP, dst="ff02::1:3", hlim=1) /
               UDP(sport=53550, dport=5355) /
               LLMNRQuery(qd=DNSQR(qname=query, qtype="PTR")))

        try:
            response = AsyncSniffer(iface=self.interface)
            response.start()
            sendp(pkt, iface=self.interface, verbose=False)
            time.sleep(0.2)
            # Parse the domain name from the response
            response.stop()
            for packet in response.results:
                if packet.haslayer(UDP) and packet.haslayer(LLMNRResponse) and packet[DNSRR].rrname.decode("utf-8")[:-1] == query:
                    return packet[DNSRR].rdata.decode("utf-8")
        except Exception:
            return None
    
    def send_any_ipv6_mdns(self, query_name):
        '''Function to send an IPv6 mDNS query after getting the name'''
        def full_name_mdns(name):
            '''Function to complete mDNS name to use for asking about IP'''
            if ".local" in name:
                return name
            else:
                return name + "local"

        try:
            # Complete the mDNS name
            query_name = full_name_mdns(query_name)

            # Create the mDNS packets
            pkt_any = (Ether(src=self.src_MAC, dst="33:33:00:00:00:fb") /
                       IPv6(src=self.src_IP, dst="ff02::fb", hlim=1) /
                       UDP(sport=53530, dport=5353) /
                       DNS(rd=1, qd=DNSQR(qname=query_name, qtype=255, qclass=1)))

            pkt_a = (Ether(src=self.src_MAC, dst="33:33:00:00:00:fb") /
                     IPv6(src=self.src_IP, dst="ff02::fb", hlim=1) /
                     UDP(sport=53530, dport=5353) /
                     DNS(rd=1, qd=DNSQR(qname=query_name, qtype=1, qclass=1)))

            pkt_aaaa = (Ether(src=self.src_MAC, dst="33:33:00:00:00:fb") /
                        IPv6(src=self.src_IP, dst="ff02::fb", hlim=1) /
                        UDP(sport=53530, dport=5353) /
                        DNS(rd=1, qd=DNSQR(qname=query_name, qtype=28, qclass=1)))

            # Combine packets into a list
            pkt = [pkt_a, pkt_aaaa, pkt_any]

            # Send the mDNS packets
            sendp(pkt, iface=self.interface, verbose=False)

        except Exception as e:
            return None
    
    def send_any_ipv6_llmnr(self, query_name):
        '''Function to send an IPv6 LLMNR query after getting the name'''     
        def full_name_llmnr(name):
            '''Function to complete LLMNR name to use for asking about IP'''
            if name.endswith('.local.'):
                return name[:-6]
            else:
                return name

        try:
            # Complete the mDNS name
            query_name = full_name_llmnr(query_name)

            # Create the mDNS packets
            pkt_any = (Ether(src=self.src_MAC, dst="33:33:00:01:00:03") /
                       IPv6(src=self.src_IP, dst="ff02::1:3", hlim=1) /
                       UDP(sport=53550, dport=5355) /
                        DNS(rd=1, qd=DNSQR(qname=query_name, qtype=255, qclass=1)))

            pkt_a = (Ether(src=self.src_MAC, dst="33:33:00:01:00:03") /
                       IPv6(src=self.src_IP, dst="ff02::1:3", hlim=1) /
                       UDP(sport=53550, dport=5355) /
                        DNS(rd=1, qd=DNSQR(qname=query_name, qtype=1, qclass=1)))

            pkt_aaaa = (Ether(src=self.src_MAC, dst="33:33:00:01:00:03") /
                       IPv6(src=self.src_IP, dst="ff02::1:3", hlim=1) /
                       UDP(sport=53550, dport=5355) /
                        DNS(rd=1, qd=DNSQR(qname=query_name, qtype=28, qclass=1)))

            # Combine packets into a list
            pkt = [pkt_a, pkt_aaaa, pkt_any]

            # Send the mDNS packets
            sendp(pkt, iface=self.interface, verbose=False)

        except Exception as e:
            return None
          
    def send_test_mdns_llmnr_ipv6(self, time_all_path):
        '''Function to get all possible IP with mDNS and LLMNR'''
        try:
            target_ip = []
            with open(time_all_path, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    src_ip = row['src_IP']
                    try:
                        # Validate if src_IP is a valid IPv6 address
                        ip = ipaddress.ip_address(src_ip)
                        if ip not in target_ip:
                            target_ip.append(ip)
                            if ip.version == 6 and (ip.is_link_local or ip.is_global):
                                # Perform the mDNS PTR query
                                name = self.send_ptr_ipv6_llmnr(src_ip)
                                if not name:
                                    name = self.send_ptr_ipv6_mdns(src_ip)
                                if name:
                                    # Perform the mDNS query with the returned name
                                    self.send_any_ipv6_mdns(name)
                                    self.send_any_ipv6_llmnr(name)
                    except ValueError:
                        continue
        except Exception as e:
            ptprinthelper.ptprint(f"An error occurred while processing the CSV file: {e}", "ERROR")
    
    def send_mld_query(self):
        '''Function to send an MLD query (two versions) to an IPv6 multicast address'''
        try:
            mac = Ether(src=self.src_MAC, dst="33:33:00:00:00:01")
            # Create an IPv6 packet with a hop limit of 1 and a multicast source address
            ipv6_packet = IPv6(src=self.src_IP, dst="ff02::1", hlim=1)

            # Create an IPv6 Extension Header for Hop-by-Hop options with Router Alert
            hbh_header = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))

            # Create an MLD query message with a maximum response delay of 10 seconds, querying for the specific multicast group
            mld_query_v1 = ICMPv6MLQuery(mrd=1, mladdr='::')
            mld_query_v2 = ICMPv6MLQuery2(type=130, mladdr="::", sources=[], mrd=1, S=0, QRV=2, QQIC=125)

            # Add the Hop-by-Hop Options header to the IPv6 packet
            query_v1 = mac / ipv6_packet / hbh_header / mld_query_v1
            query_v2 = mac / ipv6_packet / hbh_header / mld_query_v2

            # Send the MLD query packet
            sendp(query_v2*2, iface=self.interface, verbose=False)
            time.sleep(0.1)
            sendp(query_v1*2, iface=self.interface, verbose=False)
        except Exception as e:
            return None

    def send_probe_packets(self):
        '''Function to send packets except for RA for probing information or helping RA'''
        # First sending Ping
        passivescanner_object = PassiveScanner(self.interface, self.duration)
        pkts = passivescanner_object.sniff_async()
        pkts.start()
        self.send_mld_query()
        self.send_ping_packet()
        self.send_multicast_ping_packet()
        self.send_rs_packet()
        time.sleep(self.duration)
        pkts.stop()
        passivescanner_object.capture_packets(self.src_MAC, pkts.results)

        # Then sending mDNS and LLMNR to find more addresses
        pkts = passivescanner_object.sniff_async()
        pkts.start()
        self.send_test_mdns_llmnr_ipv6("src/tmp/time_all.csv")
        time.sleep(2)
        pkts.stop()
        passivescanner_object.capture_packets(self.src_MAC, pkts.results)
