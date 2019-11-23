# Firewall-Object-Oriented-Design
The object oriented design of a simplified firewall.

## How to run the code
```
python3 Firewall.py
```
Code examples are included in the Firewall module.

```
python3 -m unittest test/test_Firewall.py
python3 -m unittest test/test_IPAddressRange.py
```
Run the unit tests.

## The design of Firewall class
```python
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
```
Each Firewall object has two instance variables - (inbound_protocols, outbound_protocols). The key of those dictionaries are protocols supported by the firewall. In this implementaion, only UDP and TCP are supported, but other protocols could be added in the future. "tcp" and "udp" are mapped to another dictionary, which stores all of allowed ports as the key, and a list of IPv4 ranges as the value. Each protocol at most has 65535 entries, because the port is in the range of \[1 - 65535\]. Each packet could be mapped to the corresponding IPv4 ranges in O(1) time.  

```python
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
```
Another point of the design is that, inevitably, the IP addresses of the packets are going to be compared very frequently. So, I create the IPAddressRange class, which has a lower bound IP address and a higher bound IP address. The lower bound and the higher bound are saved in the integer format. Thus, validating a given IP address is nothing different from comparing if a given integer stays in the range of \[lower_bound, upper_bound\].

## Things could be improved
If I have more time to finish this design of the firewall, I might store the IP address ranges in a sorted order in the list.
In this way, it's possible to use binary search to verify if a certain IP address is allowed. Using binary search could improve the time comlexity to O(log n), from O(n) in current implementation. However, we still need to decide sorting the IP ranges by the lower bound, upper bound or the median value.

## Team perferance
Data team - the most interested in
Platform team - also very interested in
