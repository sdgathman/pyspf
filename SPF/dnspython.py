import dns.resolver  # http://www.dnspython.org
import dns.exception
import spf

if not hasattr(dns.rdatatype,'SPF'):
  # patch in type99 support
  dns.rdatatype.SPF = 99
  dns.rdatatype._by_text['SPF'] = dns.rdatatype.SPF

def DNSLookup(name,qtype):
  retVal = []
  try:
    answers = dns.resolver.query(name, qtype)
    for rdata in answers:
      if qtype == 'A' or qtype == 'AAAA':
        retVal.append(((name, qtype), rdata.address))
      elif qtype == 'MX':
        retVal.append(((name, qtype), (rdata.preference, rdata.exchange)))
      elif qtype == 'PTR':
        retVal.append(((name, qtype), rdata.target.to_text(True)))
      elif qtype == 'TXT' or qtype == 'SPF':
        retVal.append(((name, qtype), rdata.strings))
  except dns.resolver.NoAnswer:
    pass
  except dns.resolver.NXDOMAIN:
    pass
  except dns.exception.DNSException,x:
    raise spf.TempError,'DNS ' + str(x)
  return retVal

spf.DNSLookup = DNSLookup
