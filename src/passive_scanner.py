from scapy.all import *
from src.csv_process import Time, Router
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptMTU, ICMPv6NDOptDNSSL, ICMPv6NDOptRDNSS, ICMPv6NDOptRouteInfo, ICMPv6NDOptAdvInterval, ICMPv6NDOptEFA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptPREF64, ICMPv6NDOptHAInfo, ICMPv6ND_NA, ICMPv6DestUnreach, ICMPv6ParamProblem, ICMPv6MLReport2, ICMPv6MLDMultAddrRec, ICMPv6MLReport, ICMPv6MLDone, icmp6ndopts
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
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from src.utils import ValidationUtils

class PassiveScanner:
    def __init__(self, interface, duration, smac):
        self.interface = interface
        self.duration = duration
        self.smac = smac

    def sniff_duration(self):
        """Sniff all packets for a specified duration."""
        packets = sniff(iface=self.interface, timeout=self.duration)
        self.capture_packets(packets)
    
    def sniff_async(self):
        """Function to start asynchronous sniffing and return a list of packets"""
        packets = AsyncSniffer(iface=self.interface)
        return packets
    
    def capture_packets(self, packets):
        '''Function to store specified packets into csv files'''
        for packet in packets:
            # Storing all packets to time
            if any(proto in packet for proto in (IP, IPv6)):
                smac = packet[0].src
                sip = packet[0][1].src
                dmac = packet[0].dst
                dip = packet[0][1].dst
            else:
                smac = packet[0].src
                sip = ""
                dmac = packet[0].dst
                dip = ""

            time_data = Time.convert_timestamp_to_date(packet.time)
            summary = str(packet.summary())

            if smac != self.smac:
                Time(time_data, smac, dmac, sip, dip, summary, "src/tmp").save_time()
                # mDNS responses or DNS
                if DNSRR in packet and DNS in packet:
                    for i in range(packet[1][DNS].ancount):
                        if packet.an[i].type == 1 or packet.an[i].type == 28:
                            Time(time_data, smac, dmac, packet[0].an[i].rdata, dip, summary, "src/tmp").save_time()
                
                # LLMNR responses
                if UDP in packet:
                    if packet[UDP].sport == 5355:
                        if ICMPv6ParamProblem not in packet and ICMPv6DestUnreach not in packet:
                            if packet.haslayer(LLMNRResponse) and DNSRR in packet:
                                for i in range(packet[LLMNRResponse].ancount):
                                    try:                
                                        if packet[LLMNRResponse].an[i].type == 1 or packet[LLMNRResponse].an[i].type == 28:
                                            Time(time_data, smac, dmac, packet[LLMNRResponse].an[i].rdata, dip, summary, "src/tmp").save_time()
                                    except:
                                        pass
                
                # MLD responses
                if ICMPv6MLReport2 in packet:            
                    for i in range(packet[0][ICMPv6MLReport2].records_number):
                        if in6_isllsnmaddr(packet[0][ICMPv6MLDMultAddrRec][i].dst):
                            Time(time_data, smac, dmac, packet[0][ICMPv6MLDMultAddrRec][i].dst, dip, summary, "src/tmp").save_time()

                if ICMPv6MLReport in packet or ICMPv6MLDone in packet:
                    Time(time_data, smac, dmac, packet[0].mladdr, dip, summary, "src/tmp").save_time()

            
            # Storing RA packets except for the one that we send
            if ICMPv6ND_RA in packet and packet[0].src != self.smac:
                ra = packet[ICMPv6ND_RA]
                smac = packet[0].src
                sip = packet[0][1].src

                M_flag = ValidationUtils.convert_OnOff(ra.M)
                O_flag = ValidationUtils.convert_OnOff(ra.O)
                H_flag = ValidationUtils.convert_OnOff(ra.H)
                P_flag = ValidationUtils.convert_OnOff(ra.P)
                Res_flag = ValidationUtils.convert_OnOff(1 if (getattr(ra, 'res', 0) and (ra.res & 1) != 0) else 0)
                SNAC_flag = ValidationUtils.convert_OnOff(1 if (getattr(ra, 'res', 0) and (ra.res & 2) != 0) else 0)
                Prf_flag = ValidationUtils.convert_preferenceRA(ra.prf)
                Router_lifetime = (ra.routerlifetime)
                Reachable_time = (ra.reachabletime)
                Retrans_timer = (ra.retranstimer)
                Cur_hop_limit = (ra.chlim)

                rdnss = (packet[ICMPv6NDOptRDNSS].dns) if ICMPv6NDOptRDNSS in packet else ""
                dnssl = (packet[ICMPv6NDOptDNSSL].searchlist) if ICMPv6NDOptDNSSL in packet else ""
                mtu = (packet[ICMPv6NDOptMTU].mtu) if ICMPv6NDOptMTU in packet else ""

                prefix = ""
                Valid_lifetime = ""
                Preferred_lifetime = ""
                A_flag = ""
                L_flag = ""
                RAF_flag = ""
                PD_flag = ""
                Pres1 = ""
                Pres2 = ""

                if ICMPv6NDOptPrefixInfo in packet:
                    prefix_info = packet[ICMPv6NDOptPrefixInfo]
                    prefix = f"{prefix_info.prefix}/{prefix_info.prefixlen}"
                    Valid_lifetime = (prefix_info.validlifetime)
                    Preferred_lifetime = (prefix_info.preferredlifetime)
                    A_flag = ValidationUtils.convert_OnOff(getattr(prefix_info, 'A', 0))
                    L_flag = ValidationUtils.convert_OnOff(getattr(prefix_info, 'L', 0))
                    RAF_flag = ValidationUtils.convert_OnOff(getattr(prefix_info, 'R', 0))
                    PD_flag = ValidationUtils.convert_OnOff(1 if (getattr(prefix_info, 'res1', 0) and (prefix_info.res1 & 16) != 0) else 0)
                    Pres1 = (getattr(prefix_info, 'res1', 0) & 0x0F) if getattr(prefix_info, 'res1', None) is not None else ""
                    Pres2 = getattr(prefix_info, 'res2', "") if getattr(prefix_info, 'res2', None) is not None else ""

                Route_info = {}
                if ICMPv6NDOptRouteInfo in packet:
                    route_info = packet[ICMPv6NDOptRouteInfo]
                    Route_info = {
                        'prf': ValidationUtils.convert_preferenceRA(route_info.prf),
                        'rtlifetime': str(route_info.rtlifetime),
                        'prefix': route_info.prefix
                    }

                Pref64 = {}
                if ICMPv6NDOptPREF64 in packet:
                    pref64_info = packet[ICMPv6NDOptPREF64]
                    plc_map = {0: 96, 1: 64, 2: 56, 3: 48, 4: 40, 5: 32}
                    prefix_len = plc_map.get(pref64_info.plc, 96)
                    Pref64 = {
                        'prefix': f"{pref64_info.prefix}/{prefix_len}" if pref64_info.prefix else "",
                        'prefix_address': pref64_info.prefix,
                        'plc': pref64_info.plc,
                        'prefix_length': prefix_len,
                        'scaledlifetime': pref64_info.scaledlifetime,
                        'lifetime': pref64_info.scaledlifetime * 8
                    }

                ra_flags = ""
                if ICMPv6NDOptRAFlags in packet:
                    ra_flags = getattr(packet[ICMPv6NDOptRAFlags], 'flags', "")

                HA_info = {}
                if ICMPv6NDOptHAInfo in packet:
                    ha_opt = packet[ICMPv6NDOptHAInfo]
                    HA_info = {
                        'pref': getattr(ha_opt, 'pref', 0),
                        'lifetime': getattr(ha_opt, 'lifetime', 0),
                        'res': getattr(ha_opt, 'res', 0)
                    }

                Captive_portal = ""
                if ICMPv6NDOptCaptivePortal in packet:
                    raw_uri = getattr(packet[ICMPv6NDOptCaptivePortal], 'uri', "")
                    if isinstance(raw_uri, bytes):
                        Captive_portal = raw_uri.rstrip(b'\x00').decode('utf-8', errors='ignore')
                    else:
                        Captive_portal = str(raw_uri).rstrip('\x00')
                
                Router(smac, sip, M_flag, O_flag, H_flag, P_flag, Res_flag, SNAC_flag, Prf_flag, Router_lifetime, Reachable_time, Retrans_timer, Cur_hop_limit, prefix, L_flag, A_flag, RAF_flag, PD_flag, Pres1, Pres2, Valid_lifetime, Preferred_lifetime, dnssl, rdnss, mtu, Route_info, Pref64, ra_flags, HA_info, Captive_portal).save_packet("src/tmp")
            




                








