import nmap

# nmap_path = r""
scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("<------------------------------------------------------>")

ip_addr = input("Please enter the IP address you want to scan: ")

print("The IP you entered is: ", ip_addr)
type(ip_addr)

resp = input("\nPlease enter the type of scan you want to run\n1) SYN ACK Scan\n2) UDP Scan\n3) Comprehensive scan\n")
print("You hace selected option: ", resp)

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())
elif resp == '3':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sU -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())
else:
    print("Please enter a valid option")