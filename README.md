
# DNS works!

This repository will help you understand how DNS works. It contains a technical walkthrough of the DNS resolution process.

Before you dive into the contents of this repository, I highly recommend that you read my blogpost, **Understanding DNS**: https://nkdesai409.blogspot.com/2022/03/understanding-dns.html

The Domain Name System (DNS) is the hierarchical and decentralized naming system used to identify computers, services, and other resources reachable through the Internet or other Internet Protocol (IP) networks. 

And the process of translating user-friendly computer names to IP addresses is called a *DNS Resolution*.

In every Operating System, there will be some kind of a *DNS Resolver* service. It's job is to query the *DNS server* to resolve the host names to IP addresses.

For example, Ubuntu uses `systemd-resolved` DNS resolver. Other popular DNS resolver applications for Linux include `Dnsmasq`.

Windows has it's own built-in Resolver service running.

## DNS Resolution

When a local application wants to resolve a network host name, it's first step will be to make a request to the OS's default DNS Resolver service. 

Let's take Ubuntu 20.04.3 LTS to demonstrate how this works. As mentioned earlier, newer Ubuntu versions use `systemd-resolved` DNS resolver. It's a system service included in the OS and the local applications (running on the system) can either use the glibc function `getaddrinfo()` or the API function (directly provided by `systemd-resolved`) to get the names resolved through `systemd-resolved`.

If any local application doesn't want to use any of the API functions provided by `systemd-resolved` and just want to make their own DNS query requests to a DNS server, then they can get the DNS server IP address in `/etc/resolv.conf` file. 

Whenever I issue a `dig databurn.in` command on my Ubuntu VM, I'll get the following output:

```bash
nandan@nandan:~/Desktop$ dig databurn.in
; <<>> DiG 9.16.1-Ubuntu <<>> databurn.in
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53053
;; flags: qr rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;databurn.in.			IN	A

;; ANSWER SECTION:
databurn.in.		3600	IN	A	185.199.108.153
databurn.in.		3600	IN	A	185.199.109.153
databurn.in.		3600	IN	A	185.199.110.153
databurn.in.		3600	IN	A	185.199.111.153

;; Query time: 228 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Thu Feb 24 17:46:42 IST 2022
;; MSG SIZE  rcvd: 104
```

Observe that the default DNS server being used in the above query output is 127.0.0.53. Where did `dig` get this IP address from? Is it mentioned in the `/etc/resolv.conf` file?

Let's check it out:

```bash
nandan@nandan:~/Desktop$ ls -l /etc/resolv.conf
lrwxrwxrwx 1 root root 39 Nov 11 21:48 /etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf
```

Observe that the  `/etc/resolv.conf` file is a *symbolic link* to another file  `/run/systemd/resolve/stub-resolv.conf`. And this symbolic link was set up by default when I installed Ubuntu.

And `/run/systemd/resolve/stub-resolv.conf` file belongs to `systemd-resolved`! `systemd-resolved` has a local DNS server running on IP address 127.0.0.53. This information is usually mentioned in the file `/run/systemd/resolve/stub-resolv.conf`. Also, the IPv4 network standards reserve the entire address block: 127.0.0.0/8 (more than 16 million addresses) for loopback purposes. 127.0.0.1 is just the translation for 'localhost' name. But the other 16 million addresses in 127.0.0.0/8 block can also be used by the local services running on your system. Any IP address in the 127.0.0.0/8 block won't be routable on the internet and is strictly reserved for local service running on a host. [More on here](https://en.wikipedia.org/wiki/Localhost).

If I don't want to use the `systemd-resolved` service for my DNS queries, I can remove the symbolic link on the `/etc/resolv.conf` file, and make it a regular file and put in whichever DNS server IP address I want there. 

But how does the `systemd-resolved` service (or it's equivalent service on Windows) respond with the correct IP address of the domain name that we requested? 

**Step 1:** 
`systemd-resolved` first checks the `/etc/hosts` file to see if the queried name is present in that file. The DNS query answer for "localhost" is usually found in this file (which, by default, is 127.0.0.1).

On Windows, this hosts file can be found at `c:\Windows\System32\Drivers\etc\hosts`.

**Step 2:** 
If the name is not found in the hosts file, then `systemd-resolved` checks it's local cache.  

Here is how to view this DNS cache information on Windows and Ubuntu!

To get the local DNS cache on Windows: 

    ifconfig /displaydns

To flush the local DNS cache on Windows:

    ifconfig /flushdns

And on Ubuntu, there is no direct way to view the DNS cache data, but the following command gives the DNS cache size, cache hits and cache misses:

    systemd-resolve --statistics

To flush the local DNS cache on Ubuntu:

    systemd-resolve --flush-caches


**Step 3:**

If the name is not found in local cache, then the `systemd-resolved` begins it's hunt for finding the IP address for the given domain name. For this, it first goes to the DNS server in the local network. The DNS server IP address for the local network is usually configured through DHCP protocol when we're initially connecting to that network.

To know which DNS server `systemd-resolved` is talking to, we can issue the following command:

    systemd-resolve --status

The output will be something like this: 
```bash
Link 2 (enp0s3)
      Current Scopes: DNS           
DefaultRoute setting: yes           
       LLMNR setting: yes           
MulticastDNS setting: no            
  DNSOverTLS setting: no            
      DNSSEC setting: no            
    DNSSEC supported: no            
  Current DNS Server: 192.168.43.112
         DNS Servers: 192.168.43.112
          DNS Domain: ~.       
```

On Windows, we can issue the following command to get the DNS server IP address for the local network:

    ipconfig /all

The output will be as follows (the text has been truncated):
```
....
....
....
IPv4 Address. . . . . . . . . . . : 192.168.43.192(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : 24 February 2022 11:13:18
   Lease Expires . . . . . . . . . . : 24 February 2022 19:13:03
   Default Gateway . . . . . . . . . : 192.168.43.112
   DHCP Server . . . . . . . . . . . : 192.168.43.112
   DNS Servers . . . . . . . . . . . : 192.168.43.112
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

As evident from the above output, my local network DNS server IP is 192.168.43.112. Let's try to make a DNS query directly to 192.168.43.112 server.  

```python
# simple_dns_query.py
import socket

# importing 'dnspython' module: https://www.dnspython.org/
import dns.rdataclass
import dns.message
import dns.rdatatype

dst = '192.168.43.22'
#dst = '127.0.0.53'
#dst = '1.1.1.1'
dport = 53  # Port that we want to probe

domain_name = 'cred.club'
dns_query = dns.message.make_query(domain_name,
                                   dns.rdatatype.from_text('A'),
                                   dns.rdataclass.from_text('IN'))  # 'IN' refers to Internet
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Send the DNS message request through the UDP socket
udp_socket.sendto(dns_query.to_wire(), (dst, dport))

# Listen for any UDP packets
packet = udp_socket.recvfrom(4096)[0]
dns_query_res = dns.message.from_wire(packet)
print(dns_query_res)

```

The output of the above Python script is: 
```
id 61729
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
cred.club. IN A
;ANSWER
cred.club. 17 IN A 13.32.33.111
cred.club. 17 IN A 13.32.33.210
cred.club. 17 IN A 13.32.33.92
cred.club. 17 IN A 13.32.33.46
;AUTHORITY
cred.club. 52236 IN NS ns-1447.awsdns-52.org.
cred.club. 52236 IN NS ns-1813.awsdns-34.co.uk.
cred.club. 52236 IN NS ns-467.awsdns-58.com.
cred.club. 52236 IN NS ns-960.awsdns-56.net.
;ADDITIONAL
```

In the following line: `cred.club. 17 IN A 13.32.33.210` the '*17*' says that this DNS response can be cached for 17 seconds. So if we make consecutive requests to 192.168.43.22 server within those 17 seconds, we'll get the cached response. So, the cached response will be as follows:

```
id 29164
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
cred.club. IN A
;ANSWER
cred.club. 14 IN A 13.32.33.111
cred.club. 14 IN A 13.32.33.92
cred.club. 14 IN A 13.32.33.46
cred.club. 14 IN A 13.32.33.210
;AUTHORITY
;ADDITIONAL
```

Notice that `AUTHORITY` section is empty in the cached output. This caching is done on 192.168.43.22 local DNS server.

Just as `systemd-reserved` caches the DNS responses, the *recursive* DNS servers cache the DNS query responses as well.

**Step 4:**

So, what happens when our DNS query reaches the local network DNS server? In my example, 192.168.43.112 server? How does it resolve the domain name? And what was that `AUTHORITY` section in the DNS query response in the previous example?

To understand how the local network DNS server resolves a domain name, go through the explanation given in [dns_resolution.py](/dns_resolution.py)

**Tip**:

To trace the route of a DNS query:

    dig +trace databurn.in

Related to DNS trace, check this out: https://superuser.com/questions/694127/how-to-trace-the-route-of-a-dns-query


## License

MIT License

Copyright 2022 Nandan Desai

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
