import DNS    # http://pydns.sourceforge.net
import spf

if not hasattr(DNS.Type, 'SPF'):
    # patch in type99 support
    DNS.Type.SPF = 99
    DNS.Type.typemap[99] = 'SPF'
    DNS.Lib.RRunpacker.getSPFdata = DNS.Lib.RRunpacker.getTXTdata

def DNSLookup(name, qtype, strict=True):
    try:
        req = DNS.DnsRequest(name, qtype=qtype)
        resp = req.req()
	#resp.show()
        # key k: ('wayforward.net', 'A'), value v
	# FIXME: pydns returns AAAA RR as 16 byte binary string, but
	# A RR as dotted quad.  For consistency, this driver should
	# return both as binary string.
        return [((a['name'], a['typename']), a['data']) for a in resp.answers]
    except IOError, x:
        raise spf.TempError, 'DNS ' + str(x)
    except DNS.DNSError, x:
        raise spf.TempError, 'DNS ' + str(x)

DNS.DiscoverNameServers() # Fails on Mac OS X? Add domain to /etc/resolv.conf

spf.DNSLookup = DNSLookup
