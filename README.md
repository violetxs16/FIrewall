# SDN Firewall Project

## Project Overview

This project implements a Software-Defined Networking (SDN) firewall using OpenFlow protocols. The firewall selectively allows or blocks network traffic based on packet types, implementing basic network security policies through flow table rules.

## Project Goal

The primary objective is to create an intelligent network firewall that:
- **Allows essential network protocols** (ARP for network discovery)
- **Permits application traffic** (TCP for web, SSH, file transfer, etc.)
- **Blocks unwanted traffic** (ICMP, UDP, and other non-TCP protocols)
- **Optimizes network performance** by installing persistent flow rules

## Technical Implementation

### Firewall Logic (`do_firewall()` method)

The firewall implements a three-tier packet filtering system:

#### 1. ARP Packet Handling
```python
if packet.find('arp'):
    # Action: FLOOD packets that are ARP
    # Establishes new flow entry rule for future ARP packets
```
- **Purpose**: Allows ARP (Address Resolution Protocol) traffic
- **Behavior**: Floods ARP packets to all ports
- **Flow Rule**: Creates persistent rules for ARP packet forwarding

#### 2. TCP Packet Handling  
```python
elif packet.find('ipv4') and packet.find('tcp'):
    # Action: FLOOD packets that are TCP
    # Establishes new flow entry rule for future TCP packets
```
- **Purpose**: Allows TCP traffic (HTTP, HTTPS, SSH, etc.)
- **Behavior**: Floods TCP packets to enable communication
- **Flow Rule**: Creates persistent rules for TCP packet forwarding

#### 3. Non-TCP IPv4 Packet Handling
```python
elif packet.find('ipv4'):
    # Action: DROP packets that are IPv4 but not TCP
    # Establishes new flow entry rule for future IPv4 packets that are not TCP
```
- **Purpose**: Blocks non-TCP IPv4 traffic (UDP, ICMP, etc.)
- **Behavior**: Drops packets and installs blocking rules
- **Flow Rule**: Creates persistent drop rules for non-TCP IPv4 traffic

## Expected Behavior and Validation

### Connectivity Test (`pingall`)
- **Expected Result**: Fail
- **Reason**: ICMP packets (used by ping) are IPv4 but not TCP, so they are dropped by the firewall
- **Validates**: Non-TCP blocking functionality

### Flow Table Inspection (`dpctl dump-flows`)
- **Expected Result**: Display two types of flow entries:
  1. **ARP Flow Entry**: Configured to flood ARP packets
  2. **ICMP Flow Entry**: Configured to drop ICMP (IPv4 non-TCP) packets
- **Validates**: Proper flow rule installation

### TCP Performance Test (`iperf`)
- **Expected Result**: Succeed
- **Reason**: TCP traffic is allowed through the firewall, enabling successful data transfer
- **Validates**: TCP traffic allowance functionality

## Security Policy Summary

| Traffic Type | Action | Reason |
|-------------|---------|---------|
| ARP | ALLOW (Flood) | Essential for network discovery |
| TCP | ALLOW (Flood) | Application traffic (HTTP, SSH, etc.) |
| UDP | BLOCK (Drop) | Potentially unwanted traffic |
| ICMP | BLOCK (Drop) | Diagnostic traffic (ping, traceroute) |

## Key Features

- **Flow-based Security**: Uses OpenFlow to install persistent rules
- **Selective Filtering**: Distinguishes between different protocols
- **Performance Optimization**: Avoids controller involvement after initial rule installation
- **Network Discovery Support**: Maintains ARP functionality for proper network operation

## Requirements

- SDN Controller (POX/Ryu/ONOS)
- OpenFlow-compatible switches
- Mininet (for testing/simulation)
- Python environment

## Usage

1. **Start the Controller**:
   ```bash
   python controller.py
   ```

2. **Connect OpenFlow Switches**: Ensure switches connect to the controller

3. **Test Connectivity**:
   ```bash
   # Test ping (should fail)
   pingall
   
   # Check flow rules
   dpctl dump-flows
   
   # Test TCP traffic (should succeed)
   iperf
   ```
   
## Future Enhancements

- Add support for UDP whitelisting
- Implement port-based filtering
- Add logging and monitoring capabilities
- Create dynamic rule management interface
- Implement more granular security policies

## Author

**Violeta Solorio**  


---
