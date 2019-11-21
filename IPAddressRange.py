import ipaddress

class IPAddressRange:
    def __init__(self, lower_ip: str, upper_ip: str):
        """
        Args:
            lower_ip: the lower bound of IPv4 address in dotted 
                    decimal notation in string format
            upper_ip: the upper bound of IPv4 address in dotted
                    decimal notation in string format
        """
        self.lower = int(ipaddress.IPv4Address(lower_ip))
        self.upper = int(ipaddress.IPv4Address(upper_ip))
        

    def within_range(self, ip_addr: str) -> bool:
        """
        This method determines if an arbitrary IPv4 address is within the range.
        """
        ip_addr = int(ipaddress.IPv4Address(ip_addr))

        return ip_addr >= self.lower and ip_addr <= self.upper