import nmap

# nmap_path = r""
scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("<------------------------------------------------------>")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)

resp = input("\nPlease enter the type of scan you want to run\n1) SYN ACK Scan\n2) UDP Scan\n3) Comprehensive scan")
print("You hace selected option: ", resp)

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan()