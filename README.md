```
 ____            _                        _____           _
|  _ \ ___ _ __ | |_ ___ _ __ ___ _ __   |_   _|__   ___ | |___
| |_) / _ \ '_ \| __/ _ \ '__/ _ \ '_ \    | |/ _ \ / _ \| / __|
|  __/  __/ | | | ||  __/ | |  __/ |_) |   | | (_) | (_) | \__ \
|_|   \___|_| |_|\__\___|_|  \___| .__/    |_|\___/ \___/|_|___/
                                 |_|ptnetrouteradvertisement v0.0.12
                                       https://www.penterep.com

```

<span style="color:orange;">ptnetrouteradvertisement</span> is a versatile tool designed to 
perform comprehensive scans over IPv6 networks, find vulnerabilities, and simulate attacks using Router Advertisement.


## Install Requirements  
 
Before proceeding, it is recommended to update your system to ensure compatibility:  
```bash  
sudo apt update && sudo apt upgrade -y  
```  

This application requires **Python3**. Make sure it is installed, along with the `python3-venv` package, for managing virtual environments:  
```bash  
sudo apt install python3 python3-venv -y  
```  

### Steps to Install Dependencies  

#### 1. **Create a Virtual Environment (if not already created)**  
You can create a virtual environment with any name you prefer. Replace `<env_name>` with your chosen name in the following command:  
```bash
python3 -m venv <env_name>
```
For example, if you want to name your virtual environment `myenv`, use:  
```bash
python3 -m venv myenv
```

#### 2. **Activate the Virtual Environment**  
After creating the virtual environment, activate it by specifying its name. Replace `<env_name>` with the name you used during creation:  
```bash
source <env_name>/bin/activate
```
For instance, if the name is `myenv`, use:  
```bash
source myenv/bin/activate
```

#### 3. **Install Requirements**  
With the virtual environment activated, install the required dependencies:  
```bash  
python3 -m pip install -r requirements.txt  
```  

### Important Notes  
For future use, you don’t need to reinstall the dependencies. Simply activate the created virtual environment before running the application:  
```bash  
source myenv/bin/activate 
```  
By following these steps, you ensure a clean and consistent installation process while avoiding potential errors due to system-level dependency conflicts or pip management. 


## Usage
The tool must be run under the <span style="color:red;">**root**</span> user in Linux (```sudo```). The meaning of every mode and parameters are explained below.

```bash
./ptnetrouteradvertisement -i eth0 -prefix 2001::/64 -A -L -less
```

## Parameters

### General Parameters
| Parameter       | Description                                                                                 | Default Value              |
|-----------------|---------------------------------------------------------------------------------------------|----------------------------|
| `-i`           | Specify the network interface to use (required).                                            | None                       |
| `-smac`        | Source MAC address. Auto-generated if not provided.                                         | Auto-generated             |
| `-dmac`        | Destination MAC address.                                                                    | `33:33:00:00:00:01`        |
| `-sip`         | Source IPv6 address. Auto-generated if not provided.                                        | Auto-generated (link-local)|
| `-dip`         | Destination IPv6 address.                                                                   | `ff02::1`                  |
| `-M`           | Managed Address Configuration flag.                                                         | `0` (Not set)              |
| `-O`           | Other Configuration flag.                                                                    | `0` (Not set)              |
| `-H`           | Mobile IPv6 Home Agent flag.                                                                | `0` (Not set)              |
| `-P`           | Neighbor Discovery Proxy flag.                                                              | `0` (Not set)              |
| `-res`         | Reserved flag in RA header.                                                                 | `0` (Not set)              |
| `-snac`        | SNAC Router flag (Stub Network Auto-Configuring).                                           | `0` (Not set)              |
| `-prf`         | Router preference flag (`High`, `Medium`, `Low`, `Reserved`).                               | `High`                     |
| `-rlt`         | Router Lifetime in seconds.                                                                 | `300 s`                    |
| `-rcht`        | Reachable Time in seconds.                                                                  | `300 s`                    |
| `-rtrt`        | Retrans Timer in seconds.                                                                   | `300 s`                    |
| `-nofwd`       | Disable traffic forwarding.                                                                 | Not set (MiTM allowed)     |
| `-j`           | Enable JSON output.                                                                         | Not set                    |
| `-n`           | Keep temporary files after execution.                                                       | Not set                    |
| `-d`           | Scanning duration in seconds.                                                               | `10 s`                     |
| `-ai`          | Advertisement interval in seconds.                                                          | Same as duration           |
| `-f`           | Flood mode with either constant or random parameters.                                       | Not set                    |
| `-fi`          | Flood interval in milliseconds between packets in flood mode (`-f`) for slow flood (> 0).  | Not set (fast flood)       |

### Prefix Option Parameters
| Parameter       | Description                                                                                 | Default Value              |
|-----------------|---------------------------------------------------------------------------------------------|----------------------------|
| `-prefix`       | Advertised prefix.                                                                          | Not set                    |
| `-L`            | On-link flag. Prefix can be used for on-link determination when set.                        | `0` (Not set)              |
| `-A`            | SLAAC address configuration flag.                                                          | `0` (Not set)              |
| `-raf`          | Router Address flag (R-bit). Prefix contains complete IP address of the sending router.     | `0` (Not set)              |
| `-pd`           | DHCPv6 Prefix Delegation flag (P-bit). Indicates DHCPv6-PD availability/preference.        | `0` (Not set)              |
| `-pres1`        | Reserved bits in Prefix flags (4 bits, 0–15 / `0x0`–`0xF`).                                 | `0`                        |
| `-pres2`        | Reserved 32-bit field in Prefix option (4 bytes, 0–4294967295 / `0x0`–`0xFFFFFFFF`).         | `0`                        |
| `-vlt`          | Valid Lifetime of prefix in seconds.                                                       | `300 s`                    |
| `-plt`          | Preferred Lifetime of prefix in seconds.                                                   | `300 s`                    |

### DNS Option Parameters
| Parameter       | Description                                                                                 | Default Value              |
|-----------------|---------------------------------------------------------------------------------------------|----------------------------|
| `-dnssl`        | DNS Search List Option (e.g., domain suffixes).                                             | Not set                    |
| `-rdnss`        | Recursive DNS Server Option (e.g., DNS server addresses).                                   | Not set                    |
| `-dnslt`        | DNS Lifetime in seconds for RDNSS and DNSSL options. Only applicable when `-dnssl` or `-rdnss` is set. | `300 s`                    |

### PREF64 Option Parameters
| Parameter       | Description                                                                                 | Default Value              |
|-----------------|---------------------------------------------------------------------------------------------|----------------------------|
| `-pref64`       | The NAT64 prefix to be advertised.                                                          | Not set                    |
| `-pref64lt`     | Scaled Lifetime for the NAT64 prefix in seconds. Usable only with `-pref64`.                | `300 s`                    |
| `-plc`          | Prefix Length Code (0-5) defining length (0=/96, 1=/64, 2=/56, 3=/48, 4=/40, 5=/32). Default: `0`. Usable only with `-pref64`. | `0` (/96)         |

### IPv6 RA Flags Option Parameters
| Parameter       | Description                                                                                 | Default Value              |
|-----------------|---------------------------------------------------------------------------------------------|----------------------------|
| `-raflags`      | IPv6 Router Advertisement Flags Option (RFC 5175). 48-bit bit field (`0` to `281474976710655` / `0x0` to `0xFFFFFFFFFFFF`). | Not set                    |

### Home Agent Information Option Parameters
| Parameter       | Description                                                                                 | Default Value              |
|-----------------|---------------------------------------------------------------------------------------------|----------------------------|
| `-hainfo`       | Home Agent Information Option (RFC 6275). Enables inclusion of the Home Agent Information option. | `0` (Not set)              |
| `-haprf`        | Home Agent Preference (`0` to `65535`). Higher value indicates higher preference.           | `0`                        |
| `-halt`         | Home Agent Lifetime in seconds (`0` to `65535`).                                            | `300 s`                    |
| `-hares`        | Reserved 16-bit field (`0` to `65535` / `0x0` to `0xFFFF`).                                 | `0`                        |

### Captive-Portal Option Parameters
| Parameter       | Description                                                                                 | Default Value              |
|-----------------|---------------------------------------------------------------------------------------------|----------------------------|
| `-cportal`      | Captive-Portal Option (RFC 8910). URI string of the captive portal API endpoint.            | Not set                    |

### Other Parameters
| Parameter       | Description                                                                                 | Default Value              |
|-----------------|---------------------------------------------------------------------------------------------|----------------------------|
| `-mtu`          | Advertised MTU.                                                                             | Not set                    |
| `-ri`           | Route Information Option (e.g., router preference).                                         | Not set                    |


## Examples
1. **Send mode**: Advertise a prefix, enable SLAAC mode, and show vulnerabilities:
   ```bash
   ./ptnetrouteradvertisement -i eth0 -d 30 -j -prefix 2001::/64 -A -L -less
   ```
2. **Send mode**: Include route information with high preference:
   ```bash
   ./ptnetrouteradvertisement -i eth0 -prefix 2001::/64 -A -L -ri 'prf=High;rtlifetime=100;prefix=2001:dead::/64'
   ```
3. **Send mode**: Advertise multiple DNS suffixes and recursive DNS servers:
   ```bash
   ./ptnetrouteradvertisement -i eth0 -prefix 2001::/64 -A -L -rdnss 2001::1 2002::2 -dnssl fekt.cz aws.com
   ```
4. **Send mode**: Advertise a PREF64 NAT64 prefix with custom lifetime and Prefix Length Code:
   ```bash
   ./ptnetrouteradvertisement -i eth0 -pref64 64:ff9b:: -plc 0 -pref64lt 300
   ```
5. **Flood mode**: Flood the network with random options:
   ```bash
   ./ptnetrouteradvertisement -i eth0 -f random -d 30
   ```
6. **Flood mode (slow)**: Flood the network with random options and 50 ms delay between packets:
   ```bash
   ./ptnetrouteradvertisement -i eth0 -f random -fi 50 -d 30
   ```

## License
Copyright (c) 2025 Penterep Security s.r.o.

ptnetrouteradvertisement is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Founsdation, either version 3 of the License, or (at your option) any later version.

ptnetrouteradvertisement is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptmethods. If not, see https://www.gnu.org/licenses/

## Sponsor

<p align="center">
  <a href="https://www.penterep.com/">
    <img alt="Penterep" width="300" src="https://cms.penterep.com/uploads/horizontal_penterep_logo_normal_3562db3de4.svg" />
  </a>
</p>


## Disclaimer

```
This program must be performed with proper authorization or Educational purpose ONLY. Do not use it without permission. 
The usual disclaimer applies, especially the fact that us (Penterep) is not liable for any damages caused by direct or 
indirect use of the functionality provided by this program. The author bears NO responsibility for content or misuse of 
this program or any derivatives thereof. 
```
