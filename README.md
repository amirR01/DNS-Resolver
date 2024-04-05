# DNS-Resolver
A simple DNS resolver that works over UDP. It resolves standard DNS queries and returns the IP address of the requested domain which is stored in `/etc/myhosts` file in the format of `etc/hosts` file.

## How to run
1. Create and populate the `/etc/myhosts` file with the domain names and their corresponding IP addresses.
2. Run the resolver using the following command:
```bash
python3 main.py
```
3. dig the domain name to get the IP address:
```bash
dig  @localhost -p 5353 <domain_name> A
```
4. The resolver will return the IP address of the requested domain name.

## Example
you can see the example in screenshots folder.

## Note 
- The resolver only works with A type queries.