from collections import defaultdict
from IPAddressRange import IPAddressRange

class Firewall:
    def __init__(self, rule_path):
        """
        The constructor of the Firewall class
        Args:
            rule_path: the path of a csv file which describes the rule of the firewall.
        """
        self.path = rule_path
        self.inbound_protocols = defaultdict(dict)
        self.outbound_protocals = defaultdict(dict)
        self._parse_rules()

    
    @staticmethod
    def _split_port_range(port_range):
        port_range = port_range.split('-')

        if len(port_range) > 1:
            min_port = int(port_range[0])
            max_port = int(port_range[1])
        else:
            min_port = int(port_range[0])
            max_port = int(port_range[0])

        return min_port, max_port


    @staticmethod
    def _split_ip_addr_range(ip_addr_range):
        """
        This helper method splits the IPv4 address range into
        the lower bound and upper bound, and then returns the
        corresponding IPAddressRange object.
        """
        ip_addr_range = ip_addr_range.split('-')

        if len(ip_addr_range) > 1:
            low_ip = ip_addr_range[0]
            high_ip = ip_addr_range[1]
        else:
            low_ip = ip_addr_range[0]
            high_ip = ip_addr_range[0]

        return IPAddressRange(low_ip, high_ip)


    def _parse_rules(self):
        try:
            with open(self.path, 'r') as f:
                for line in f:
                    line = line.strip()

                    if line == '':
                        continue

                    rule = line.split(',')
                    direction, protocol, port_range, ip_addr = tuple(rule)

                    min_port, max_port = Firewall._split_port_range(port_range)
                    ip_range = Firewall._split_ip_addr_range(ip_addr)

                    if direction == 'inbound':
                        for port in range(min_port, max_port + 1):
                            if port in self.inbound_protocols[protocol]:
                                self.inbound_protocols[protocol][port].append(ip_range)
                            else:
                                self.inbound_protocols[protocol][port] = [ip_range]
                            
                    else:
                        for port in range(min_port, max_port + 1):
                            if port in self.outbound_protocals[protocol]:
                                self.outbound_protocals[protocol][port].append(ip_range)
                            else:
                                self.outbound_protocals[protocol][port] = [ip_range]
        except FileNotFoundError as e:
            print(e)
            quit()


    def accept_packet(self, direction: str, protocol: str, port: int, ip_address: str) -> bool:
        """
        This method determines whether a packet complies with the rules or not.
        If at least one rule allows the packet, accept_packet method is going to return
        True. Otherwise, returns False.

        Args:
            direction: "inbound" or "outbound"
            protocol: "tcp" or "udp"
            port: an integer in the range of [1 - 65535]
            ip_address: a single IPv4 address
        """
        if direction == 'inbound':
            if port in self.inbound_protocols[protocol]:
                for ip_range in self.inbound_protocols[protocol][port]:
                    if ip_range.within_range(ip_address):
                        return True

                return False
            else:
                return False
        else:
            if port in self.outbound_protocals[protocol]:
                for ip_range in self.outbound_protocals[protocol][port]:
                    if ip_range.within_range(ip_address):
                        return True

                return False
            else:
                return False
        


if __name__ == "__main__":
    # examples
    fw = Firewall("example_rules.csv")
    print(fw.accept_packet("inbound","tcp",42995,"74.109.133.46"))
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(fw.accept_packet("outbound", "tcp", 65000, "52.13.48.93"))
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
