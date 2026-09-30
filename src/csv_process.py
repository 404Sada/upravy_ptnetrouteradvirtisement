import csv
import datetime
import os

def create_csv(directory):
    '''Create the initial CSV files'''

    with open(f"{directory}/RA.csv", 'w', newline='') as csvfile:
        fieldnames = ['src_MAC', 'src_IP', 'M_flag', 'O_flag', 'H_flag', 'P_flag', 'Res_flag', 'SNAC_flag', 'Prf_flag', 'Router_lifetime', 'Reachable_time', 'Retrans_timer', 'Cur_hop_limit', 'Prefix', 'L_flag', 'A_flag', 'RAF_flag', 'PD_flag', 'Pres1', 'Pres2', 'Valid_lifetime', 'Preferred_lifetime', 'DNS_search_list', 'DNS_server', 'MTU', 'Route_info', 'Pref64', 'RA_flags', 'HA_info', 'Captive_portal']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    # For storing the role of every device (host, router, preferred router)
    with open(f"{directory}/role_node.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP', 'Device_number', 'Role']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    with open(f"{directory}/time_all.csv", 'w', newline='') as csvfile:
        fieldnames = ['time', 'src_MAC', 'dst_MAC', 'src_IP', 'dst_IP', 'packet']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
    with open(f"{directory}/start_end_mode.csv", 'w', newline='') as csvfile:
        fieldnames = ['time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
    with open(f"{directory}/random_flood.csv", 'w', newline='') as csvfile:
        fieldnames = ['src_MAC', 'src_IP', 'Prefix', 'Route_prefix']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
def del_tmp_csv(directory):
    '''Function to delete temporary csv files'''
    file_list = os.listdir(directory)
    for file_name in file_list:
        file_path = os.path.join(directory, file_name)
        os.remove(file_path)

def remove_duplicates_from_csv(input_file):
    '''Function to remove duplicates from csv file'''
    try:
        # Use a set to track seen rows
        seen = set()
        rows = []

        # Read the input CSV file and filter out duplicates
        with open(input_file, 'r', newline='') as infile:
            reader = csv.reader(infile)
            header = next(reader)  # Read the header
            rows.append(header)
            for row in reader:
                row_tuple = tuple(row)
                if row_tuple not in seen:
                    seen.add(row_tuple)
                    rows.append(row)

        # Write the cleaned rows back to the same input CSV file
        with open(input_file, 'w', newline='') as outfile:
            writer = csv.writer(outfile)
            writer.writerows(rows)
    except FileNotFoundError:
        pass
    except Exception:
        pass

def has_data_csv(file_path):
    '''This function checks if a file has additional data rows other than the header'''
    if file_path is None:
        return False
    
    with open(file_path, 'r') as csv_file:
        reader = csv.reader(csv_file)

        # Skip the first line (header)
        next(reader)

        # Check if there are any additional lines
        for row in reader:
            if row:  # If a row is not empty, return True
                return True

        return False  # Return False if all rows were empty

class Time:

    def __init__(self, time:str, src_MAC:str, dst_MAC:str, src_IP:str, dst_IP:str, packet:str, directory:str):
        # Assign to self object
        self.time = time
        self.src_MAC = src_MAC
        self.dst_MAC = dst_MAC
        self.src_IP = src_IP
        self.dst_IP = dst_IP
        self.packet = packet
        self.directory = directory
    
    @staticmethod
    def convert_timestamp_to_date(timestamp):
        # type: (float) -> str
        """
        Convert timestamp in float to date object in string
        """

        date = datetime.datetime.fromtimestamp(timestamp)
        return str(date)

    def save_time(self):
        # Function to save time and packet to a CSV file
        with open(f'{self.directory}/time_all.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
            csvfile.seek(0)  # move the file pointer to the beginning of the file
                
            fieldnames = ['time', 'src_MAC', 'dst_MAC', 'src_IP', 'dst_IP', 'packet']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'time': self.time,
                'src_MAC': self.src_MAC,
                'dst_MAC': self.dst_MAC,
                'src_IP': self.src_IP,
                'dst_IP': self.dst_IP,
                'packet': self.packet
            })
        
    @staticmethod
    def save_start_end_tool(self, time):
        # Function to save time and packet to a CSV file
        with open(f'{self.directory}/start_end_mode.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
            csvfile.seek(0)  # move the file pointer to the beginning of the file
                
            fieldnames = ['time']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'time': time
            })


class Router:
    def __init__(self, src_MAC:str, src_IP:str, M_flag:str, O_flag:str, H_flag:str, P_flag:str, Res_flag:str, SNAC_flag:str, Prf_flag:str, Router_lifetime:int, Reachable_time:int, Retrans_timer:int, Cur_hop_limit:int, Prefix:str, L_flag:str, A_flag:str, RAF_flag:str, PD_flag:str, Pres1:str, Pres2:str, Valid_lifetime:int, Preferred_lifetime:int, DNS_search_list:list, DNS_server:list, MTU:int, Route_info:dict, Pref64:dict=None, RA_flags:str=None, HA_info:dict=None, Captive_portal:str=None):
        self.smac = src_MAC
        self.sip = src_IP

        self.M_flag = M_flag
        self.O_flag = O_flag
        self.H_flag = H_flag
        self.P_flag = P_flag
        self.Res_flag = Res_flag
        self.SNAC_flag = SNAC_flag
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
        self.Pres1 = Pres1
        self.Pres2 = Pres2
        self.Valid_lifetime = Valid_lifetime
        self.Preferred_lifetime = Preferred_lifetime

        self.DNS_search_list = DNS_search_list
        self.DNS_server = DNS_server
        self.MTU = MTU
        self.Route_info = Route_info
        self.Pref64 = Pref64 if Pref64 is not None else {}
        self.RA_flags = RA_flags if RA_flags is not None else ""
        self.HA_info = HA_info if HA_info is not None else {}
        self.Captive_portal = Captive_portal if Captive_portal is not None else ""
    
    def save_packet(self, directory:str):
        # Function to save time and packet to a CSV file
        with open(f'{directory}/RA.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
            csvfile.seek(0)  # move the file pointer to the beginning of the file
                
            fieldnames = ['src_MAC', 'src_IP', 'M_flag', 'O_flag', 'H_flag', 'P_flag', 'Res_flag', 'SNAC_flag', 'Prf_flag', 'Router_lifetime', 'Reachable_time', 'Retrans_timer', 'Cur_hop_limit', 'Prefix', 'L_flag', 'A_flag', 'RAF_flag', 'PD_flag', 'Pres1', 'Pres2', 'Valid_lifetime', 'Preferred_lifetime', 'DNS_search_list', 'DNS_server', 'MTU', 'Route_info', 'Pref64', 'RA_flags', 'HA_info', 'Captive_portal']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writerow({
                'src_MAC': self.smac,
                'src_IP': self.sip,
                'M_flag': self.M_flag,
                'O_flag': self.O_flag,
                'H_flag': self.H_flag,
                'P_flag': self.P_flag,
                'Res_flag': self.Res_flag,
                'SNAC_flag': self.SNAC_flag,
                'Prf_flag': self.Prf_flag,
                'Router_lifetime': self.Router_lifetime,
                'Reachable_time': self.Reachable_time,
                'Retrans_timer': self.Retrans_timer,
                'Cur_hop_limit': self.Cur_hop_limit,
                'Prefix': self.Prefix,
                'L_flag': self.L_flag,
                'A_flag': self.A_flag,
                'RAF_flag': self.RAF_flag,
                'PD_flag': self.PD_flag,
                'Pres1': self.Pres1,
                'Pres2': self.Pres2,
                'Valid_lifetime': self.Valid_lifetime,
                'Preferred_lifetime': self.Preferred_lifetime,
                'DNS_search_list': self.DNS_search_list,
                'DNS_server': self.DNS_server,
                'MTU': self.MTU,
                'Route_info': self.Route_info,
                'Pref64': self.Pref64,
                'RA_flags': self.RA_flags,
                'HA_info': self.HA_info,
                'Captive_portal': self.Captive_portal
            })
    
class Flood:
    def __init__(self, src_MAC:str, src_IP:str, Prefix:str, Route_prefix:str):
        self.smac = src_MAC
        self.sip = src_IP
        self.Prefix = Prefix
        self.Route_prefix = Route_prefix
    
    def save_packet(self, directory:str):
        # Function to save time and packet to a CSV file
        with open(f'{directory}/random_flood.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
            csvfile.seek(0)  # move the file pointer to the beginning of the file
                
            fieldnames = ['src_MAC', 'src_IP', 'Prefix', 'Route_prefix']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writerow({
                'src_MAC': self.smac,
                'src_IP': self.sip,
                'Prefix': self.Prefix,
                'Route_prefix': self.Route_prefix
            })   

        
