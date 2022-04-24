# IPK Project 2 - packet sniffer
Author: Matej Matuška (xmatus36)

Simple packet sniffer written in C. Supports filtering by multiple protocols
and port number. Based on pcap library.

## Project files
- ipk-sniffer.cpp - source code
- Makefile - build file
- README.md
- manual.pdf

## Building
The program can be compiled using the bundled Makefile.\
To compile the program run `make` command in directory containing Makefile and
ipk-sniffer.cpp files.

## Usage
Syntax:
```
./ipk-sniffer -i
./ipk-sniffer -i <interface> [-t|--tcp] [-u|--udp] [--arp] [--icmp] [-n <number>]
```

Program accepts multiple arguments:

|Argument          |Description                          |
|:-----------------|:------------------------------------|
|-i \<interace>    |Listen on interface                  |
|-p \<port-number> |Filter by port number                |
|-t --tcp          |Show only TCP packets                |
|-u --udp          |Show only UDP packets                |
|--arp             |Show only ARP packets                |
|--icmp            |Show only ICMP packets               |
|-n \<number>      |Number of packets to print, default 1|

#### Notes:
If no interface is specified program prints available interfaces.\
If no protocol filter is specified packets are not filtered by interface.\
If no port is specified all port numbers are considered.

To stop the program, press `ctrl + c`.

### Example usage:
List available interfaces:\
`./ipk-sniffer -i`

Sniff 5 TCP packets on interface "eth0" on port 22 (SSH):\
`./ipk-sniffer -i eth0 --tcp -p 22 -n 5`

Sniff 1 one ARP or UDP packet on interface wlan0:\
`./ipk-sniffer -i wlan0 -u --arp`
