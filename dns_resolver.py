import socket

# importing 'dnspython' module: https://www.dnspython.org/
import dns.rdataclass
import dns.message
import dns.rdatatype


def make_dns_request(dns_server, dns_port, domain_name):
    dns_query = dns.message.make_query(domain_name,
                                       dns.rdatatype.from_text('A'),
                                       dns.rdataclass.from_text('IN'))  # 'IN' refers to Internet
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Send the DNS message request through the UDP socket
    udp_socket.sendto(dns_query.to_wire(), (dns_server, dns_port))
    # Listen for any UDP packets
    packet = udp_socket.recvfrom(4096)[0]
    dns_query_res: dns.message = dns.message.from_wire(packet)
    udp_socket.close()
    return dns_query_res


# START HERE
################################### STEP-1
'''
Every DNS client needs to know a list of root servers and their IP addresses.
Root servers show the clients the next path to take.
There are a bunch of root servers. 
Find out more about the root servers here: https://en.wikipedia.org/wiki/Root_name_server#Root_server_addresses
I'm choosing a root server being run by the University of Maryland.
It's "d.root-servers.net" with an IPv4 address of '199.7.91.13'
'''
root_server = '199.7.91.13'
dport = 53 # Default DNS port
cred_club_domain_name = 'cred.club'
print('\nMaking request to the root server::: ' + root_server)
dns_query_response = make_dns_request(root_server, dport, cred_club_domain_name)
print(dns_query_response)
# Output of the above query is as follows:
'''
id 23518
opcode QUERY
rcode NOERROR
flags QR RD
;QUESTION
cred.club. IN A
;ANSWER
;AUTHORITY
club. 172800 IN NS a.nic.club.
club. 172800 IN NS b.nic.club.
club. 172800 IN NS c.nic.club.
club. 172800 IN NS ns1.dns.nic.club.
club. 172800 IN NS ns2.dns.nic.club.
club. 172800 IN NS ns3.dns.nic.club.
;ADDITIONAL
a.nic.club. 172800 IN A 37.209.192.10
b.nic.club. 172800 IN A 37.209.194.10
c.nic.club. 172800 IN A 37.209.196.10
ns1.dns.nic.club. 172800 IN A 156.154.144.215
ns2.dns.nic.club. 172800 IN A 156.154.145.215
ns3.dns.nic.club. 172800 IN A 156.154.159.215
a.nic.club. 172800 IN AAAA 2001:dcd:1::10
b.nic.club. 172800 IN AAAA 2001:dcd:2::10
c.nic.club. 172800 IN AAAA 2001:dcd:3::10
ns1.dns.nic.club. 172800 IN AAAA 2610:a1:1071::d7
ns2.dns.nic.club. 172800 IN AAAA 2610:a1:1072::d7
ns3.dns.nic.club. 172800 IN AAAA 2610:a1:1073::d7
'''
################################### end of STEP-1



################################### STEP-2
'''
The above output says that the root server "d.root-servers.net" doesn't know about "cred.club" (the 'ANSWER' section is empty), but
it says that it knows who has the authority over ".club" domains. And it has responded with a bunch of ".club" authoritative servers
and their IP addresses in the 'ADDITIONAL' section.
From the above output, we know that "a.nic.club." is one of the authoritative servers for the ".club" domains. 
You can view the other authoritative servers in 'AUTHORITY' section of the above output.
And we have the IP address of "a.nic.club." in the 'ADDITIONAL' section, which is "37.209.192.10".
Let's try to make a DNS query for "cred.club" on this "37.209.192.10" IP address and let's see if it knows the IP address for "cred.club".
'''
club_authority = dns_query_response.additional[0]  # Get the first entry in the 'Additional' section: a.nic.club. 172800 IN A 37.209.192.10
club_auth_ip = club_authority[0]  # Get the IP address of the .club authoritative server: 37.209.192.10
print('\nMaking request to::: ' + str(club_authority))
dns_query_response = make_dns_request(str(club_auth_ip), dport, cred_club_domain_name)
print(dns_query_response)
# Output of the above query is as follows:
'''
id 27771
opcode QUERY
rcode NOERROR
flags QR RD
;QUESTION
cred.club. IN A
;ANSWER
;AUTHORITY
cred.club. 3600 IN NS ns-467.awsdns-58.com.
cred.club. 3600 IN NS ns-1813.awsdns-34.co.uk.
cred.club. 3600 IN NS ns-1447.awsdns-52.org.
cred.club. 3600 IN NS ns-960.awsdns-56.net.
;ADDITIONAL
'''
################################### end of STEP-2



################################### STEP-3
'''
From the above output, "a.nic.club." says that it doesn't know about "cred.club" but says that "ns-467.awsdns-58.com." is 
one of the 4 servers that know about "cred.club".
But the problem here is, the response doesn't contain the IP address of  "ns-467.awsdns-58.com."
You can see that the 'ADDITIONAL' field is empty.
So, our next step will be to try to figure out the IP address of "ns-467.awsdns-58.com." server
so that we can make a request to it for "cred.club." domain name.
To find the IP of "ns-467.awsdns-58.com.", we need to go back to the root servers again because,
as of now, we don't know who has the authority over ".com" domains. So, let's ask the root server.
'''
cred_club_authority = dns_query_response.authority[0]  # cred.club. 3600 IN NS ns-467.awsdns-58.com.
cred_club_authority_name = cred_club_authority[0]  # ns-467.awsdns-58.com.
print('\nMaking request to::: ' + root_server)
print('cred.club Authority name: ' + str(cred_club_authority_name))  # ns-467.awsdns-58.com.
dns_query_response = make_dns_request(root_server, dport, cred_club_authority_name)
print(dns_query_response)
# Output of the above query is as follows:
'''
id 31411
opcode QUERY
rcode NOERROR
flags QR RD
;QUESTION
ns-467.awsdns-58.com. IN A
;ANSWER
;AUTHORITY
com. 172800 IN NS a.gtld-servers.net.
com. 172800 IN NS b.gtld-servers.net.
com. 172800 IN NS c.gtld-servers.net.
com. 172800 IN NS d.gtld-servers.net.
com. 172800 IN NS e.gtld-servers.net.
com. 172800 IN NS f.gtld-servers.net.
com. 172800 IN NS g.gtld-servers.net.
com. 172800 IN NS h.gtld-servers.net.
com. 172800 IN NS i.gtld-servers.net.
com. 172800 IN NS j.gtld-servers.net.
com. 172800 IN NS k.gtld-servers.net.
com. 172800 IN NS l.gtld-servers.net.
com. 172800 IN NS m.gtld-servers.net.
;ADDITIONAL
a.gtld-servers.net. 172800 IN A 192.5.6.30
b.gtld-servers.net. 172800 IN A 192.33.14.30
c.gtld-servers.net. 172800 IN A 192.26.92.30
d.gtld-servers.net. 172800 IN A 192.31.80.30
e.gtld-servers.net. 172800 IN A 192.12.94.30
f.gtld-servers.net. 172800 IN A 192.35.51.30
g.gtld-servers.net. 172800 IN A 192.42.93.30
h.gtld-servers.net. 172800 IN A 192.54.112.30
i.gtld-servers.net. 172800 IN A 192.43.172.30
j.gtld-servers.net. 172800 IN A 192.48.79.30
k.gtld-servers.net. 172800 IN A 192.52.178.30
l.gtld-servers.net. 172800 IN A 192.41.162.30
m.gtld-servers.net. 172800 IN A 192.55.83.30
a.gtld-servers.net. 172800 IN AAAA 2001:503:a83e::2:30
'''
################################# end of STEP-3



################################# STEP-4
'''
The root server says it doesn't know about "ns-467.awsdns-58.com." domain but 
it says that it knows a bunch of Authoritative servers for the ".com" domains in the above output.
So, let's just pick the first one from that list: "a.gtld-servers.net." 
And, we also know it's IP address from the 'ADDITIONAL' section above, which is "192.5.6.30"
Remember, we're here trying to find out the IP address of "ns-467.awsdns-58.com." nameserver 
because that nameserver knows the IP address for "cred.club", which is our final goal.
So, Let's ask "a.gtld-servers.net." if it knows about "ns-467.awsdns-58.com."
'''
com_authority = dns_query_response.additional[0] # a.gtld-servers.net. 172800 IN A 192.5.6.30
com_authority_ip = com_authority[0]  # 192.5.6.30
print('\nMaking request to::: ' + str(com_authority))
dns_query_response = make_dns_request(str(com_authority_ip), dport, cred_club_authority_name) # cred_club_authority_name = "ns-467.awsdns-58.com."
print(dns_query_response)
'''
id 43546
opcode QUERY
rcode NOERROR
flags QR RD
;QUESTION
ns-467.awsdns-58.com. IN A
;ANSWER
;AUTHORITY
awsdns-58.com. 172800 IN NS g-ns-59.awsdns-58.com.
awsdns-58.com. 172800 IN NS g-ns-634.awsdns-58.com.
awsdns-58.com. 172800 IN NS g-ns-1210.awsdns-58.com.
awsdns-58.com. 172800 IN NS g-ns-1786.awsdns-58.com.
;ADDITIONAL
g-ns-59.awsdns-58.com. 172800 IN A 205.251.192.59
g-ns-59.awsdns-58.com. 172800 IN AAAA 2600:9000:5300:3b00::1
g-ns-634.awsdns-58.com. 172800 IN A 205.251.194.122
g-ns-634.awsdns-58.com. 172800 IN AAAA 2600:9000:5302:7a00::1
g-ns-1210.awsdns-58.com. 172800 IN A 205.251.196.186
g-ns-1210.awsdns-58.com. 172800 IN AAAA 2600:9000:5304:ba00::1
g-ns-1786.awsdns-58.com. 172800 IN A 205.251.198.250
g-ns-1786.awsdns-58.com. 172800 IN AAAA 2600:9000:5306:fa00::1
'''
################################# end of STEP-4



################################# STEP-5
'''
"a.gtld-servers.net." says that it doesn't know about "ns-467.awsdns-58.com." but it has
given us a list of authorities who know about "awsdns-58.com." domain.
Let's pick the first authoritative server from that list: "g-ns-59.awsdns-58.com."
We know it's IP address from 'ADDITIONAL' section: "205.251.192.59"
So, Let's make the request to find out the IP for the nameserver "ns-467.awsdns-58.com."
'''
awsdns_58_authority = dns_query_response.additional[0] # g-ns-59.awsdns-58.com. 172800 IN A 205.251.192.59
awsdns_58_authority_ip = awsdns_58_authority[0] # 205.251.192.59
print('\nMaking request to::: ' + str(awsdns_58_authority))
dns_query_response = make_dns_request(str(awsdns_58_authority_ip), dport, cred_club_authority_name) # cred_club_authority_name = "ns-467.awsdns-58.com."
print(dns_query_response)
'''
id 40993
opcode QUERY
rcode NOERROR
flags QR AA RD
;QUESTION
ns-467.awsdns-58.com. IN A
;ANSWER
ns-467.awsdns-58.com. 172800 IN A 205.251.193.211
;AUTHORITY
awsdns-58.com. 172800 IN NS g-ns-1210.awsdns-58.com.
awsdns-58.com. 172800 IN NS g-ns-1786.awsdns-58.com.
awsdns-58.com. 172800 IN NS g-ns-59.awsdns-58.com.
awsdns-58.com. 172800 IN NS g-ns-634.awsdns-58.com.
;ADDITIONAL
g-ns-1210.awsdns-58.com. 172800 IN A 205.251.196.186
g-ns-1210.awsdns-58.com. 172800 IN AAAA 2600:9000:5304:ba00::1
g-ns-1786.awsdns-58.com. 172800 IN A 205.251.198.250
g-ns-1786.awsdns-58.com. 172800 IN AAAA 2600:9000:5306:fa00::1
g-ns-59.awsdns-58.com. 172800 IN A 205.251.192.59
g-ns-59.awsdns-58.com. 172800 IN AAAA 2600:9000:5300:3b00::1
g-ns-634.awsdns-58.com. 172800 IN A 205.251.194.122
g-ns-634.awsdns-58.com. 172800 IN AAAA 2600:9000:5302:7a00::1
'''
################################# end of STEP-5



################################# STEP-6
'''
Yay! "g-ns-59.awsdns-58.com." knew about "ns-467.awsdns-58.com." domain!!!
In the above output, we have an entry in the 'ANSWER' section! 
'ns-467.awsdns-58.com. 172800 IN A 205.251.193.211'
There we have the IP address of the authoritative name server "ns-467.awsdns-58.com." for the "cred.club" domain.
So, now we can make a last DNS request to find out the IP address of "cred.club"
'''
cred_club_authority = dns_query_response.answer[0] # ns-467.awsdns-58.com. 172800 IN A 205.251.193.211
cred_club_authority_ip = cred_club_authority[0]  # 205.251.193.211
print('\nMaking request to::: ' + str(cred_club_authority_ip))
dns_query_response = make_dns_request(str(cred_club_authority_ip), dport, cred_club_domain_name) # domain name = "cred.club"
print(dns_query_response)
'''
id 21845
opcode QUERY
rcode NOERROR
flags QR AA RD
;QUESTION
cred.club. IN A
;ANSWER
cred.club. 60 IN A 52.84.11.80
cred.club. 60 IN A 52.84.11.50
cred.club. 60 IN A 52.84.11.122
cred.club. 60 IN A 52.84.11.73
;AUTHORITY
cred.club. 172800 IN NS ns-1447.awsdns-52.org.
cred.club. 172800 IN NS ns-1813.awsdns-34.co.uk.
cred.club. 172800 IN NS ns-467.awsdns-58.com.
cred.club. 172800 IN NS ns-960.awsdns-56.net.
;ADDITIONAL
'''
# And, there we have it! The IP address of "cred.club." is "52.84.11.80". Well, we have 3 more IPs in the
# Answer section. We can use any of those 4 IP addresses to communicate with "cred.club."!!!
################################# end of STEP-6
