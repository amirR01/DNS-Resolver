import socket
from concurrent.futures import ThreadPoolExecutor

def create_domain_table():
    domain_table = {}
    with open("/etc/myhosts", 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 2:
                ip_address, *domains = parts
                for domain in domains:
                    domain_table[domain] = ip_address
    return domain_table


def parse_dns_query(query):
    # The DNS header is the first 12 bytes
    header = query[:12]  

    # Extract header fields manually
    id = (header[0] << 8) | header[1]
    flags = (header[2] << 8) | header[3]
    qdcount = (header[4] << 8) | header[5]

    # Parse flags
    qr = (flags >> 15) & 0b1
    opcode = (flags >> 11) & 0b1111
    aa = (flags >> 10) & 0b1
    tc = (flags >> 9) & 0b1
    rd = (flags >> 8) & 0b1

    # QNAME starts at byte 12
    qname_start = 12  
    # Parse QNAME
    qname ,length = parse_qname(query, qname_start)

    qname_end = qname_start + length 

    # Extract QTYPE and QCLASS
    qtype = (query[qname_end] << 8) | query[qname_end + 1]
    qclass = (query[qname_end + 2] << 8) | query[qname_end + 3]

    return {
        #16 bits, a unique identifier for the query.
        'id': id,
        #1 bit, query (0) or response (1).
        'qr': qr,
        #4 bits, operation code (0 for standard query).
        'opcode': opcode,
        'aa': aa,
        'tc': tc,
        'rd': rd,
        #16 bits, number of entries in the question section.
        'qdcount': qdcount,
        #the domain name being queried.
        'qname': qname,
        #16 bits, specifies the type of the query (e.g., A for IPv4 address).
        'qtype': qtype,
        #16 bits, specifies the class of the query (e.g., IN for Internet).
        'qclass': qclass
    }

def parse_qname(query, start):
    # structure of qname is : length1 + part1 + length2 + part2 .............
    qname = ''
    pointer = start
    length = query[pointer]

    # if value == 0 : the qname has ended
    while length != 0:
        #In DNS messages, if the two most significant bits of the length byte are 11,it indicates that the label is a compression pointer.
        #  In other words, the label doesn't represent the actual characters of a domain name but is instead a reference to another location in the DNS message where the actual domain name can be found.
        if length & 0b11000000 == 0b11000000:
            # This is a pointer
            offset = ((length & 0b00111111) << 8) | query[pointer + 1]
            qname += parse_qname(query, offset)[0]
            break
        else:
            # This is a label
            qname += query[pointer + 1:pointer + 1 + length].decode('utf-8') + '.'
            pointer += length + 1

        length = query[pointer]
    


    return qname[0:-1], pointer - start + 1

def resolve_query(query, domain_table):
    parsed_dns_query = parse_dns_query(query)
    print(parsed_dns_query)
    RCODE = 0b00000000 # No error condition
    # check for valid query
    if parsed_dns_query['qr'] != 0 : 
        print("the client sent a response not a query. id: " + str(parsed_dns_query['id']))
        RCODE = 0b00000001 # Format error - The name server was unable to interpret the query.
    if parsed_dns_query['qtype'] != 1:
        print("the client sent a not A type query. id: " + str(parsed_dns_query['id']))
        RCODE = 0b00000100 # Not Implemented - The name server does not support the requested kind of query.
    
    # get ip address 
    ip_address = None
    if parsed_dns_query['qname'] in domain_table.keys():
        ip_address = domain_table[parsed_dns_query['qname']]
    if ip_address == None :
        print("no record for this query found. id: " + str(parsed_dns_query['id']))
        RCODE = 0b00000011 # Name Error - this code signifies that the domain name referenced in the query does not exist.

    # DNS response header
    header = bytearray(12)
    header[0:2] = parsed_dns_query['id'].to_bytes(2, 'big')
    header[2] = 0b10000000  # QR bit (1 for response)
    header[3] = RCODE  # Response code
    header[4:6] = (1).to_bytes(2,'big') # Qcount
    header[6:8] = (1).to_bytes(2,'big') # Acount
    # The rest of the header fields are set to 0

    # DNS response body
    qname_parts = parsed_dns_query['qname'].split('.')
    labels = bytearray()
    for part in qname_parts:
        labels.append(len(part))
        labels.extend(part.encode('utf-8'))
    labels.append(0)  # Null terminator for QNAME

    qtype = parsed_dns_query['qtype'].to_bytes(2, 'big')
    qclass = parsed_dns_query['qclass'].to_bytes(2, 'big')

    record = bytearray()
    record.extend(labels)
    record.extend((1).to_bytes(2, 'big'))  # TYPE (A record)
    record.extend((1).to_bytes(2, 'big'))  # CLASS (IN class)
    record.extend((350).to_bytes(4, 'big'))  # ttl
    record.extend((4).to_bytes(2, 'big'))  # RDLENGTH (length of RDATA)
    if ip_address != None :
        record.extend(socket.inet_aton(ip_address))  # RDATA (IPv4 address)

    # Construct the full DNS response
    dns_response = bytes(header + labels + qtype + qclass + record)
    return dns_response

def handle_dns_query(server_socket, query, addr, domain_table):
    response = resolve_query(query, domain_table)
    server_socket.sendto(response, addr)

def main():
    # create domain table
    domain_table = create_domain_table()
    
    # Create a socket to listen on localhost:5353
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('localhost', 5353))

    print("DNS server listening on localhost:5353")

    # Use a thread pool for handling DNS queries
    with ThreadPoolExecutor(max_workers=10) as executor:
        try:
            while True:
                # Accept incoming connections and submit them to the thread pool
                query, addr = server_socket.recvfrom(1024)
                executor.submit(handle_dns_query,server_socket, query,addr, domain_table)
        except KeyboardInterrupt:
            print("DNS resolver shutting down.")
        finally:
            server_socket.close()

if __name__ == "__main__":
    main()
