#!/usr/bin/env python
"""SPF (Sender Policy Framework) implementation.

Copyright (c) 2003, Terence Way
Portions Copyright (c) 2004,2005,2006 Stuart Gathman <stuart@bmsi.com>
Portions Copyright (c) 2005,2006 Scott Kitterman <scott@kitterman.com>
This module is free software, and you may redistribute it and/or modify
it under the same terms as Python itself, so long as this copyright message
and disclaimer are retained in their original form.

IN NO EVENT SHALL THE AUTHOR BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF
THIS CODE, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.

THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE.  THE CODE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS,
AND THERE IS NO OBLIGATION WHATSOEVER TO PROVIDE MAINTENANCE,
SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.

For more information about SPF, a tool against email forgery, see
    http://www.openspf.org/

For news, bugfixes, etc. visit the home page for this implementation at
    http://www.wayforward.net/spf/
    http://sourceforge.net/projects/pymilter/
"""

# Changes:
#    9-dec-2003, v1.1, Meng Weng Wong added PTR code, THANK YOU
#   11-dec-2003, v1.2, ttw added macro expansion, exp=, and redirect=
#   13-dec-2003, v1.3, ttw added %{o} original domain macro,
#                      print spf result on command line, support default=,
#                      support localhost, follow DNS CNAMEs, cache DNS results
#                      during query, support Python 2.2 for Mac OS X
#   16-dec-2003, v1.4, ttw fixed include handling (include is a mechanism,
#                      complete with status results, so -include: should work.
#                      Expand macros AFTER looking for status characters ?-+
#                      so altavista.com SPF records work.
#   17-dec-2003, v1.5, ttw use socket.inet_aton() instead of DNS.addr2bin, so
#                      n, n.n, and n.n.n forms for IPv4 addresses work, and to
#                      ditch the annoying Python 2.4 FutureWarning
#   18-dec-2003, v1.6, Failures on Intel hardware: endianness.  Use ! on
#                      struct.pack(), struct.unpack().
#
# Development taken over by Stuart Gathman <stuart@bmsi.com>.
#
# $Log$
# Revision 1.108.2.3  2006/12/23 04:44:05  customdesigned
# Fix key-value quoting in get_header.
#
# Revision 1.108.2.2  2006/12/22 20:27:24  customdesigned
# Index error reporting non-mech permerror.
#
# Revision 1.108.2.1  2006/12/22 04:59:40  customdesigned
# Merge comma heuristic.
#
# Revision 1.108  2006/11/08 01:27:00  customdesigned
# Return all key-value-pairs in Received-SPF header for all results.
#
# Revision 1.107  2006/11/04 21:58:12  customdesigned
# Prevent cache poisoning by bogus additional RRs in PTR DNS response.
#
# Revision 1.106  2006/10/16 20:48:24  customdesigned
# More DOS limit tests.
#
# Revision 1.105  2006/10/07 22:06:28  kitterma
# Pass strict status to DNSLookup - will be needed for TCP failover.
#
# Revision 1.104  2006/10/07 21:59:37  customdesigned
# long/empty label tests and fix.
#
# Revision 1.103  2006/10/07 18:16:20  customdesigned
# Add tests for and fix RE_TOPLAB.
#
# Revision 1.102  2006/10/05 13:57:15  customdesigned
# Remove isSPF and make missing space after version tag a warning.
#
# Revision 1.101  2006/10/05 13:39:11  customdesigned
# SPF version tag is case insensitive.
#
# Revision 1.100  2006/10/04 02:14:04  customdesigned
# Remove incomplete saving of result.  Was messing up bmsmilter.  Would
# be useful if done consistently - and disabled when passing spf= to check().
#
# Revision 1.99  2006/10/03 21:00:26  customdesigned
# Correct fat fingered merge error.
#
# Revision 1.98  2006/10/03 17:35:45  customdesigned
# Provide python inet_ntop and inet_pton when not socket.has_ipv6
#
# Revision 1.97  2006/10/02 17:10:13  customdesigned
# Test and fix for uppercase macros.
#
# Revision 1.96  2006/10/01 01:27:54  customdesigned
# Switch to pymilter lax processing convention:
# Always return strict result, extended result in q.perm_error.ext
#
# Revision 1.95  2006/09/30 22:53:44  customdesigned
# Fix getp to obey SHOULDs in RFC.
#
# Revision 1.94  2006/09/30 22:23:25  customdesigned
# p macro tests and fixes
#
# Revision 1.93  2006/09/30 20:57:06  customdesigned
# Remove generator expression for compatibility with python2.3.
#
# Revision 1.92  2006/09/30 19:52:52  customdesigned
# Removed redundant flag and unneeded global.
#
# Revision 1.91  2006/09/30 19:37:49  customdesigned
# Missing L
#
# Revision 1.90  2006/09/30 19:29:58  customdesigned
# pydns returns AAAA RR as binary string
#
# Revision 1.89  2006/09/29 20:23:11  customdesigned
# Optimize cidrmatch
#
# Revision 1.88  2006/09/29 19:44:10  customdesigned
# Fix ptr with ip6 for harsh mode.
#
# Revision 1.87  2006/09/29 19:26:53  customdesigned
# Add PTR tests and fix ip6 ptr
#
# Revision 1.86  2006/09/29 17:55:22  customdesigned
# Pass ip6 tests
#
# Revision 1.85  2006/09/29 15:58:02  customdesigned
# Pass self test on non IP6 python.
# PTR accepts no cidr.
#
# Revision 1.83  2006/09/27 18:09:40  kitterma
# Converted spf.check to return pre-MARID result codes for drop in
# compatibility with pySPF 1.6/1.7.  Added new procedure, spf.check2 to
# return RFC4408 results in a two part answer (result, explanation).
# This is the external API for pySPF 2.0.  No longer any need to branch
# for 'classic' and RFC compliant pySPF libraries.
#
# Revision 1.82  2006/09/27 18:02:21  kitterma
# Converted max MX limit to ambiguity warning for validator.
#
# Revision 1.81  2006/09/27 17:38:14  kitterma
# Updated initial comments and moved pre-1.7 changes to spf_changelog.
#
# Revision 1.80  2006/09/27 17:33:53  kitterma
# Fixed indentation error in check0.
#
# Revision 1.79  2006/09/26 18:05:44  kitterma
# Removed unused receiver policy definitions.
#
# Revision 1.78  2006/09/26 16:15:50  kitterma
# added additional IP4 and CIDR validation tests - no code changes.
#
# Revision 1.77  2006/09/25 19:42:32  customdesigned
# Fix unknown macro sentinel
#
# Revision 1.76  2006/09/25 19:10:40  customdesigned
# Fix exp= error and add another failing test.
#
# Revision 1.75  2006/09/25 02:02:30  kitterma
# Fixed redirect-cancels-exp test suite failure.
#
# Revision 1.74  2006/09/24 04:04:08  kitterma
# Implemented check for macro 'c' - Macro unimplimented.
#
# Revision 1.73  2006/09/24 02:08:35  kitterma
# Fixed invalid-macro-char test failure.
#
# Revision 1.72  2006/09/23 05:45:52  kitterma
# Fixed domain-name-truncation test failure
#
# Revision 1.71  2006/09/22 01:02:54  kitterma
# pySPF correction for nolocalpart in rfc4408-tests.yml failed, 4.3/2.
# Added comments to testspf.py on where to get YAML.
#
# Revision 1.70  2006/09/18 02:13:27  kitterma
# Worked through a large number of pylint issues - all 4 spaces, not a mix
# of 4 spaces, 2 spaces, and tabs. Caught a few minor errors in the process.
# All built in tests still pass.
#
# Revision 1.69  2006/09/17 18:44:25  kitterma
# Fixed validation mode only crash bug when rDNS check had no PTR record
#
#
# See spf_changelog.txt for earlier changes.

__author__ = "Terence Way"
__email__ = "terry@wayforward.net"
__version__ = "1.7: July 22, 2005"
MODULE = 'spf'

USAGE = """To check an incoming mail request:
    % python spf.py {ip} {sender} {helo}
    % python spf.py 69.55.226.139 tway@optsw.com mx1.wayforward.net

To test an SPF record:
    % python spf.py "v=spf1..." {ip} {sender} {helo}
    % python spf.py "v=spf1 +mx +ip4:10.0.0.1 -all" 10.0.0.1 tway@foo.com a    

To fetch an SPF record:
    % python spf.py {domain}
    % python spf.py wayforward.net

To test this script (and to output this usage message):
    % python spf.py
"""

import re
import socket  # for inet_ntoa() and inet_aton()
import struct  # for pack() and unpack()
import time    # for time()
import urllib  # for quote()

import DNS    # http://pydns.sourceforge.net
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
        raise TempError, 'DNS ' + str(x)
    except DNS.DNSError, x:
        raise TempError, 'DNS ' + str(x)

RE_SPF = re.compile(r'^v=spf1$|^v=spf1 ',re.IGNORECASE)

# Regular expression to look for modifiers
RE_MODIFIER = re.compile(r'^([a-z][a-z0-9_\-\.]*)=', re.IGNORECASE)

# Regular expression to find macro expansions
PAT_CHAR = r'%(%|_|-|(\{[^\}]*\}))'
RE_CHAR = re.compile(PAT_CHAR)

# Regular expression to break up a macro expansion
RE_ARGS = re.compile(r'([0-9]*)(r?)([^0-9a-zA-Z]*)')

RE_DUAL_CIDR = re.compile(r'//(0|[1-9]\d*)$')
RE_CIDR = re.compile(r'/(0|[1-9]\d*)$')

PAT_IP4 = r'\.'.join([r'(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])']*4)
RE_IP4 = re.compile(PAT_IP4+'$')

RE_TOPLAB = re.compile(
    r'\.(?:[0-9a-z]*[a-z][0-9a-z]*|[0-9a-z]+-[0-9a-z-]*[0-9a-z])\.?$|%s'
    	% PAT_CHAR, re.IGNORECASE)

RE_DOT_ATOM = re.compile(r'%(atext)s+([.]%(atext)s+)*$' % {
    'atext': r"[0-9a-z!#$%&'*+/=?^_`{}|~-]" }, re.IGNORECASE)

RE_IP6 = re.compile(                 '(?:%(hex4)s:){6}%(ls32)s$'
                   '|::(?:%(hex4)s:){5}%(ls32)s$'
                  '|(?:%(hex4)s)?::(?:%(hex4)s:){4}%(ls32)s$'
    '|(?:(?:%(hex4)s:){0,1}%(hex4)s)?::(?:%(hex4)s:){3}%(ls32)s$'
    '|(?:(?:%(hex4)s:){0,2}%(hex4)s)?::(?:%(hex4)s:){2}%(ls32)s$'
    '|(?:(?:%(hex4)s:){0,3}%(hex4)s)?::%(hex4)s:%(ls32)s$'
    '|(?:(?:%(hex4)s:){0,4}%(hex4)s)?::%(ls32)s$'
    '|(?:(?:%(hex4)s:){0,5}%(hex4)s)?::%(hex4)s$'
    '|(?:(?:%(hex4)s:){0,6}%(hex4)s)?::$'
  % {
    'ls32': r'(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|%s)'%PAT_IP4,
    'hex4': r'[0-9a-f]{1,4}'
    }, re.IGNORECASE)

# Local parts and senders have their delimiters replaced with '.' during
# macro expansion
#
JOINERS = {'l': '.', 's': '.'}

RESULTS = {'+': 'pass', '-': 'fail', '?': 'neutral', '~': 'softfail',
           'pass': 'pass', 'fail': 'fail', 'permerror': 'permerror',
       'error': 'error', 'neutral': 'neutral', 'softfail': 'softfail',
       'none': 'none', 'local': 'local', 'trusted': 'trusted',
           'ambiguous': 'ambiguous'}

EXPLANATIONS = {'pass': 'sender SPF authorized',
                'fail': 'SPF fail - not authorized',
                'permerror': 'permanent error in processing',
                'temperror': 'temporary DNS error in processing',
        'softfail': 'domain owner discourages use of this host',
        'neutral': 'access neither permitted nor denied',
        'none': '',
                #Note: The following are not formally SPF results
                'local': 'No SPF result due to local policy',
                'trusted': 'No SPF check - trusted-forwarder.org',
                #Ambiguous only used in harsh mode for SPF validation
                'ambiguous': 'No error, but results may vary'
        }

# support pre 2.2.1....
try:
    bool, True, False = bool, True, False
except NameError:
    False, True = 0, 1
    def bool(x): return not not x
# ...pre 2.2.1

DELEGATE = None

# standard default SPF record for best_guess
DEFAULT_SPF = 'v=spf1 a/24 mx/24 ptr'

#Whitelisted forwarders here.  Additional locally trusted forwarders can be
#added to this record.
TRUSTED_FORWARDERS = 'v=spf1 ?include:spf.trusted-forwarder.org -all'

# maximum DNS lookups allowed
MAX_LOOKUP = 10 #RFC 4408 Para 10.1
MAX_MX = 10 #RFC 4408 Para 10.1
MAX_PTR = 10 #RFC 4408 Para 10.1
MAX_CNAME = 10 # analogous interpretation to MAX_PTR
MAX_RECURSION = 20

ALL_MECHANISMS = ('a', 'mx', 'ptr', 'exists', 'include', 'ip4', 'ip6', 'all')
COMMON_MISTAKES = {
  'prt': 'ptr', 'ip': 'ip4', 'ipv4': 'ip4', 'ipv6': 'ip6', 'all.': 'all'
}

#If harsh processing, for the validator, is invoked, warn if results
#likely deviate from the publishers intention.
class AmbiguityWarning(Exception):
    "SPF Warning - ambiguous results"
    def __init__(self, msg, mech=None, ext=None):
        Exception.__init__(self, msg, mech)
        self.msg = msg
        self.mech = mech
        self.ext = ext
    def __str__(self):
        if self.mech:
            return '%s: %s' %(self.msg, self.mech)
        return self.msg

class TempError(Exception):
    "Temporary SPF error"
    def __init__(self, msg, mech=None, ext=None):
        Exception.__init__(self, msg, mech)
        self.msg = msg
        self.mech = mech
        self.ext = ext
    def __str__(self):
        if self.mech:
            return '%s: %s '%(self.msg, self.mech)
        return self.msg

class PermError(Exception):
    "Permanent SPF error"
    def __init__(self, msg, mech=None, ext=None):
        Exception.__init__(self, msg, mech)
        self.msg = msg
        self.mech = mech
        self.ext = ext
    def __str__(self):
        if self.mech:
            return '%s: %s'%(self.msg, self.mech)
        return self.msg

def check2(i, s, h, local=None, receiver=None):
    """Test an incoming MAIL FROM:<s>, from a client with ip address i.
    h is the HELO/EHLO domain name.  This is the RFC4408 compliant pySPF2.0
    interface.  The interface returns an SPF result and explanation only.
    SMTP response codes are not returned since RFC 4408 does not specify
    receiver policy.  Applications updated for RFC 4408 should use this
    interface.

    Returns (result, explanation) where result in
    ['pass', 'permerror', 'fail', 'temperror', 'softfail', 'none', 'neutral' ].

    Example:
    #>>> check2(i='61.51.192.42', s='liukebing@bcc.com', h='bmsi.com')

    """
    res,_,exp = query(i=i, s=s, h=h, local=local, receiver=receiver).check()
    return res,exp

def check(i, s, h, local=None, receiver=None):
    """Test an incoming MAIL FROM:<s>, from a client with ip address i.
    h is the HELO/EHLO domain name.  This is the pre-RFC SPF Classic interface.
    Applications written for pySPF 1.6/1.7 can use this interface to allow
    pySPF2 to be a drop in replacement for older versions.  With the exception
    of result codes, performance in RFC 4408 compliant.

    Returns (result, code, explanation) where result in
    ['pass', 'unknown', 'fail', 'error', 'softfail', 'none', 'neutral' ].

    Example:
    #>>> check(i='61.51.192.42', s='liukebing@bcc.com', h='bmsi.com')

    """
    res,code,exp = query(i=i, s=s, h=h, local=local, receiver=receiver).check()
    if res == 'permerror':
        res = 'unknown'
    elif res == 'tempfail':
        res =='error'
    return res, code, exp

class query(object):
    """A query object keeps the relevant information about a single SPF
    query:

    i: ip address of SMTP client in dotted notation
    s: sender declared in MAIL FROM:<>
    l: local part of sender s
    d: current domain, initially domain part of sender s
    h: EHLO/HELO domain
    v: 'in-addr' for IPv4 clients and 'ip6' for IPv6 clients
    t: current timestamp
    p: SMTP client domain name
    o: domain part of sender s
    r: receiver
    c: pretty ip address (different from i for IPv6)

    This is also, by design, the same variables used in SPF macro
    expansion.

    Also keeps cache: DNS cache.  
    """
    def __init__(self, i, s, h, local=None, receiver=None, strict=True):
        self.s, self.h = s, h
        if not s and h:
            self.s = 'postmaster@' + h
	    self.ident = 'helo'
	else:
	    self.ident = 'mailfrom'
        self.l, self.o = split_email(s, h)
        self.t = str(int(time.time()))
        self.d = self.o
        self.p = None	# lazy evaluation
        if receiver:
            self.r = receiver
        else:
            self.r = 'unknown'
        # Since the cache does not track Time To Live, it is created
        # fresh for each query.  It is important for efficiently using
        # multiple results provided in DNS answers.
        self.cache = {}
        self.defexps = dict(EXPLANATIONS)
        self.exps = dict(EXPLANATIONS)
        self.libspf_local = local    # local policy
        self.lookups = 0
        # strict can be False, True, or 2 (numeric) for harsh
        self.strict = strict
	if i:
	    self.set_ip(i)

    def set_ip(self, i):
        "Set connect ip, and ip6 or ip4 mode."
	if RE_IP4.match(i):
	    self.ip = addr2bin(i)
	    ip6 = False
	else:
	    self.ip = bin2long6(inet_pton(i))
	    if (self.ip >> 32) == 0xFFFF:	# IP4 mapped address
		self.ip = self.ip & 0xFFFFFFFFL
		ip6 = False
	    else:
		ip6 = True
	# NOTE: self.A is not lowercase, so isn't a macro.  See query.expand()
	if ip6:
	    self.c = inet_ntop(
	    	struct.pack("!QQ", self.ip>>64, self.ip&0xFFFFFFFFFFFFFFFFL))
	    self.i = '.'.join(list('%032X'%self.ip))
	    self.A = 'AAAA'
	    self.v = 'ip6'
	    self.cidrmax = 128
	else:
	    self.c = socket.inet_ntoa(struct.pack("!L", self.ip))
	    self.i = self.c
	    self.A = 'A'
	    self.v = 'in-addr'
	    self.cidrmax = 32

    def set_default_explanation(self, exp):
        exps = self.exps
        defexps = self.defexps
        for i in 'softfail', 'fail', 'permerror':
            exps[i] = exp
            defexps[i] = exp

    def set_explanation(self, exp):
        exps = self.exps
        for i in 'softfail', 'fail', 'permerror':
            exps[i] = exp

    # Compute p macro only if needed
    def getp(self):
        if not self.p:
            p = self.validated_ptrs()
            if not p:
                self.p = "unknown"
	    elif self.d in p:
	        self.p = self.d
	    else:
	        sfx = '.' + self.d
	        for d in p:
		    if d.endswith(sfx):
		        self.p = d
			break
		else:
		    self.p = p[0]
        return self.p

    def best_guess(self, spf=DEFAULT_SPF):
        """Return a best guess based on a default SPF record"""
        return self.check(spf)


    def check(self, spf=None):
        """
    Returns (result, mta-status-code, explanation) where result
    in ['fail', 'softfail', 'neutral' 'permerror', 'pass', 'temperror', 'none']

    Examples:
    >>> q = query(s='strong-bad@email.example.com',
    ...           h='mx.example.org', i='192.0.2.3')
    >>> q.check(spf='v=spf1 ?all')
    ('neutral', 250, 'access neither permitted nor denied')

    >>> q.check(spf='v=spf1 redirect=controlledmail.com exp=_exp.controlledmail.com')
    ('fail', 550, 'SPF fail - not authorized')
    
    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 ?all moo')
    ('permerror', 550, 'SPF Permanent Error: Unknown mechanism found: moo')

    >>> q.check(spf='v=spf1 =a ?all moo')
    ('permerror', 550, 'SPF Permanent Error: Unknown qualifier, RFC 4408 para 4.6.1, found in: =a')

    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 ~all')
    ('pass', 250, 'sender SPF authorized')

    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 -all moo=')
    ('pass', 250, 'sender SPF authorized')

    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 -all match.sub-domains_9=yes')
    ('pass', 250, 'sender SPF authorized')

    >>> q.strict = False
    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 -all moo')
    ('permerror', 550, 'SPF Permanent Error: Unknown mechanism found: moo')
    >>> q.perm_error.ext
    ('pass', 250, 'sender SPF authorized')

    >>> q.strict = True
    >>> q.check(spf='v=spf1 ip4:192.1.0.0/16 moo -all')
    ('permerror', 550, 'SPF Permanent Error: Unknown mechanism found: moo')

    >>> q.check(spf='v=spf1 ip4:192.1.0.0/16 ~all')
    ('softfail', 250, 'domain owner discourages use of this host')

    >>> q.check(spf='v=spf1 -ip4:192.1.0.0/6 ~all')
    ('fail', 550, 'SPF fail - not authorized')

    # Assumes DNS available
    >>> q.check()
    ('none', 250, '')

    >>> q.check(spf='v=spf1 ip4:1.2.3.4 -a:example.net -all')
    ('fail', 550, 'SPF fail - not authorized')
    >>> q.libspf_local='ip4:192.0.2.3 a:example.org'
    >>> q.check(spf='v=spf1 ip4:1.2.3.4 -a:example.net -all')
    ('pass', 250, 'sender SPF authorized')

    >>> q.check(spf='v=spf1 ip4:1.2.3.4 -all exp=_exp.controlledmail.com')
    ('fail', 550, 'Controlledmail.com does not send mail from itself.')
    
    >>> q.check(spf='v=spf1 ip4:1.2.3.4 ?all exp=_exp.controlledmail.com')
    ('neutral', 250, 'access neither permitted nor denied')
        """
        self.mech = []        # unknown mechanisms
        # If not strict, certain PermErrors (mispelled
        # mechanisms, strict processing limits exceeded)
        # will continue processing.  However, the exception
        # that strict processing would raise is saved here
        self.perm_error = None

        try:
            self.lookups = 0
            if not spf:
                spf = self.dns_spf(self.d)
            if self.libspf_local and spf: 
                spf = insert_libspf_local_policy(
                    spf, self.libspf_local)
            rc = self.check1(spf, self.d, 0)
	    if self.perm_error:
		# lax processing encountered a permerror, but continued
		self.perm_error.ext = rc
		raise self.perm_error
	    return rc
	        
        except TempError, x:
            self.prob = x.msg
            if x.mech:
                self.mech.append(x.mech)
            return ('temperror', 451, 'SPF Temporary Error: ' + str(x))
        except PermError, x:
            if not self.perm_error:
                self.perm_error = x
            self.prob = x.msg
            if x.mech:
                self.mech.append(x.mech)
            # Pre-Lentczner draft treats this as an unknown result
            # and equivalent to no SPF record.
            return ('permerror', 550, 'SPF Permanent Error: ' + str(x))

    def check1(self, spf, domain, recursion):
        # spf rfc: 3.7 Processing Limits
        #
        if recursion > MAX_RECURSION:
            # This should never happen in strict mode
            # because of the other limits we check,
            # so if it does, there is something wrong with
            # our code.  It is not a PermError because there is not
            # necessarily anything wrong with the SPF record.
            if self.strict:
                raise AssertionError('Too many levels of recursion')
            # As an extended result, however, it should be
            # a PermError.
            raise PermError('Too many levels of recursion')
        try:
            try:
                tmp, self.d = self.d, domain
                return self.check0(spf, recursion)
            finally:
                self.d = tmp
        except AmbiguityWarning,x:
            self.prob = x.msg
            if x.mech:
                self.mech.append(x.mech)
            return ('ambiguous', 000, 'SPF Ambiguity Warning: %s' % x)

    def note_error(self, *msg):
        if self.strict:
            raise PermError(*msg)
        # if lax mode, note error and continue
        if not self.perm_error:
            try:
                raise PermError(*msg)
            except PermError, x:
                # FIXME: keep a list of errors for even friendlier diagnostics.
                self.perm_error = x
        return self.perm_error

    def validate_mechanism(self, mech):
        """Parse and validate a mechanism.
    Returns mech,m,arg,cidrlength,result

    Examples:
    >>> q = query(s='strong-bad@email.example.com.',
    ...           h='mx.example.org', i='192.0.2.3')
    >>> q.validate_mechanism('A')
    ('A', 'a', 'email.example.com', 32, 'pass')
    
    >>> q = query(s='strong-bad@email.example.com',
    ...           h='mx.example.org', i='192.0.2.3')    
    >>> q.validate_mechanism('A')
    ('A', 'a', 'email.example.com', 32, 'pass')

    >>> q.validate_mechanism('?mx:%{d}/27')
    ('?mx:%{d}/27', 'mx', 'email.example.com', 27, 'neutral')

    >>> try: q.validate_mechanism('ip4:1.2.3.4/247')
    ... except PermError,x: print x
    Invalid IP4 CIDR length: ip4:1.2.3.4/247
    
    >>> try: q.validate_mechanism('ip4:1.2.3.4/33')
    ... except PermError,x: print x
    Invalid IP4 CIDR length: ip4:1.2.3.4/33

    >>> try: q.validate_mechanism('a:example.com:8080')
    ... except PermError,x: print x
    Invalid domain found (use FQDN): example.com:8080
    
    >>> try: q.validate_mechanism('ip4:1.2.3.444/24')
    ... except PermError,x: print x
    Invalid IP4 address: ip4:1.2.3.444/24
    
    >>> try: q.validate_mechanism('ip4:1.2.03.4/24')
    ... except PermError,x: print x
    Invalid IP4 address: ip4:1.2.03.4/24
    
    >>> try: q.validate_mechanism('-all:3030')
    ... except PermError,x: print x
    Invalid all mechanism format - only qualifier allowed with all: -all:3030

    >>> q.validate_mechanism('-mx:%%%_/.Clara.de/27')
    ('-mx:%%%_/.Clara.de/27', 'mx', '% /.Clara.de', 27, 'fail')

    >>> q.validate_mechanism('~exists:%{i}.%{s1}.100/86400.rate.%{d}')
    ('~exists:%{i}.%{s1}.100/86400.rate.%{d}', 'exists', '192.0.2.3.com.100/86400.rate.email.example.com', 32, 'softfail')

    >>> q.validate_mechanism('a:mail.example.com.')
    ('a:mail.example.com.', 'a', 'mail.example.com', 32, 'pass')

    >>> try: q.validate_mechanism('a:mail.example.com,')
    ... except PermError,x: print x
    Do not separate mechnisms with commas: a:mail.example.com,
    """
        if mech.endswith( "," ):
            self.note_error('Do not separate mechnisms with commas', mech)
	    mech = mech[:-1]
        # a mechanism
        m, arg, cidrlength, cidr6length = parse_mechanism(mech, self.d)
        # map '?' '+' or '-' to 'neutral' 'pass' or 'fail'
        if m:
            result = RESULTS.get(m[0])
            if result:
                # eat '?' '+' or '-'
                m = m[1:]
            else:
                # default pass
                result = 'pass'
        if m in COMMON_MISTAKES:
            self.note_error('Unknown mechanism found', mech)
            m = COMMON_MISTAKES[m]

        if m == 'a' and RE_IP4.match(arg):
            x = self.note_error(
              'Use the ip4 mechanism for ip4 addresses', mech)
            m = 'ip4'


        # validate cidr and dual-cidr
        if m in ('a', 'mx'):
            if cidrlength is None:
                cidrlength = 32;
            elif cidrlength > 32:
                raise PermError('Invalid IP4 CIDR length', mech)
            if cidr6length is None:
                cidr6length = 128
            elif cidr6length > 128:
                raise PermError('Invalid IP6 CIDR length', mech)
	    if self.v == 'ip6':
	    	cidrlength = cidr6length
        elif m == 'ip4':
            if cidr6length is not None:
                raise PermError('Dual CIDR not allowed', mech)
            if cidrlength is None:
                cidrlength = 32;
            elif cidrlength > 32:
                raise PermError('Invalid IP4 CIDR length', mech)
            if not RE_IP4.match(arg):
                raise PermError('Invalid IP4 address', mech)
        elif m == 'ip6':
            if cidr6length is not None:
                raise PermError('Dual CIDR not allowed', mech)
            if cidrlength is None:
                cidrlength = 128
            elif cidrlength > 128:
                raise PermError('Invalid IP6 CIDR length', mech)
            if not RE_IP6.match(arg):
                raise PermError('Invalid IP6 address', mech)
        else:
            if cidrlength is not None or cidr6length is not None:
                raise PermError('CIDR not allowed', mech)
	    cidrlength = self.cidrmax

        # validate domain-spec
        if m in ('a', 'mx', 'ptr', 'exists', 'include'):
            # any trailing dot was removed by expand()
            if RE_TOPLAB.split(arg)[-1]:
                raise PermError('Invalid domain found (use FQDN)', arg)
            arg = self.expand(arg)
            if m == 'include':
                if arg == self.d:
                    if mech != 'include':
                        raise PermError('include has trivial recursion', mech)
                    raise PermError('include mechanism missing domain', mech)
            return mech, m, arg, cidrlength, result

        # validate 'all' mechanism per RFC 4408 ABNF
        if m == 'all' and mech.count(':'):
            # print '|'+ arg + '|', mech, self.d,
            self.note_error(
            'Invalid all mechanism format - only qualifier allowed with all'
              , mech)
        if m in ALL_MECHANISMS:
            return mech, m, arg, cidrlength, result
        if m[1:] in ALL_MECHANISMS:
            x = self.note_error(
                'Unknown qualifier, RFC 4408 para 4.6.1, found in', mech)
        else:
            x = self.note_error('Unknown mechanism found', mech)
        return mech, m, arg, cidrlength, x

    def check0(self, spf, recursion):
        """Test this query information against SPF text.

        Returns (result, mta-status-code, explanation) where
        result in ['fail', 'unknown', 'pass', 'none']
        """

        if not spf:
            return ('none', 250, EXPLANATIONS['none'])

        # split string by whitespace, drop the 'v=spf1'
        spf = spf.split()
        # Catch case where SPF record has no spaces.
        # Can never happen with conforming dns_spf(), however
        # in the future we might want to give warnings
        # for common mistakes like IN TXT "v=spf1" "mx" "-all"
        # in relaxed mode.
        if spf[0].lower() != 'v=spf1':
	    assert strict > 1
	    raise AmbiguityWarning('Invalid SPF record in', self.d)
        spf = spf[1:]

        # copy of explanations to be modified by exp=
        exps = self.exps
        redirect = None

        # no mechanisms at all cause unknown result, unless
        # overridden with 'default=' modifier
        #
        default = 'neutral'
        mechs = []

        # Look for modifiers
        #
        for mech in spf:
            m = RE_MODIFIER.split(mech)[1:]
            if len(m) != 2:
                mechs.append(self.validate_mechanism(mech))
                continue

            if m[0] == 'exp':
	        # always fetch explanation to check permerrors
	        exp = self.get_explanation(m[1])
	        if not recursion:
		    # only set explanation in base recursion level
		    self.set_explanation(exp)
            elif m[0] == 'redirect':
                self.check_lookups()
                redirect = self.expand(m[1])
            elif m[0] == 'default':
		arg = self.expand(m[1])
                # default=- is the same as default=fail
                default = RESULTS.get(arg, default)
	    else:
		# spf rfc: 3.6 Unrecognized Mechanisms and Modifiers
		self.expand(m[1])	# syntax error on invalid macro


        # Evaluate mechanisms
        #
        for mech, m, arg, cidrlength, result in mechs:

            if m == 'include':
                self.check_lookups()
                res, code, txt = self.check1(self.dns_spf(arg),
                      arg, recursion + 1)
                if res == 'pass':
                    break
                if res == 'none':
                    self.note_error(
                        'No valid SPF record for included domain: %s' %arg,
                      mech)
                res = 'neutral'
                continue
            elif m == 'all':
                break

            elif m == 'exists':
                self.check_lookups()
                try:
                    if len(self.dns_a(arg,'A')) > 0:
                        break
                except AmbiguityWarning:
                    # Exists wants no response sometimes so don't raise
                    # the warning.
                    pass

            elif m == 'a':
                self.check_lookups()
		if self.cidrmatch(self.dns_a(arg,self.A), cidrlength):
		    break

            elif m == 'mx':
                self.check_lookups()
                if self.cidrmatch(self.dns_mx(arg), cidrlength):
                    break

            elif m == 'ip4':
	        if self.v == 'in-addr': # match own connection type only
		    try:
			if self.cidrmatch([arg], cidrlength): break
		    except socket.error:
			raise PermError('syntax error', mech)

            elif m == 'ip6':
	        if self.v == 'ip6': # match own connection type only
		    try:
			arg = inet_pton(arg)
			if self.cidrmatch([arg], cidrlength): break
		    except socket.error:
			raise PermError('syntax error', mech)

            elif m == 'ptr':
                self.check_lookups()
                if domainmatch(self.validated_ptrs(), arg):
                    break

        else:
            # no matches
            if redirect:
                #Catch redirect to a non-existant SPF record.
                redirect_record = self.dns_spf(redirect)
                if not redirect_record:
                    raise PermError('redirect domain has no SPF record',
                        redirect)
                self.exps = dict(self.defexps)
                return self.check1(redirect_record, redirect, recursion)
            else:
                result = default

        if result == 'fail':
            return (result, 550, exps[result])
        else:
            return (result, 250, exps[result])

    def check_lookups(self):
        self.lookups = self.lookups + 1
        if self.lookups > MAX_LOOKUP*4:
            raise PermError('More than %d DNS lookups'%MAX_LOOKUP*4)
        if self.lookups > MAX_LOOKUP:
            self.note_error('Too many DNS lookups')

    def get_explanation(self, spec):
        """Expand an explanation."""
        if spec:
            txt = ''.join(self.dns_txt(self.expand(spec)))
            return self.expand(txt, stripdot=False)
        else:
            return 'explanation : Required option is missing'

    def expand(self, str, stripdot=True): # macros='slodipvh'
        """Do SPF RFC macro expansion.

        Examples:
        >>> q = query(s='strong-bad@email.example.com',
        ...           h='mx.example.org', i='192.0.2.3')
        >>> q.p = 'mx.example.org'
        >>> q.r = 'example.net'

        >>> q.expand('%{d}')
        'email.example.com'

        >>> q.expand('%{d4}')
        'email.example.com'

        >>> q.expand('%{d3}')
        'email.example.com'

        >>> q.expand('%{d2}')
        'example.com'

        >>> q.expand('%{d1}')
        'com'

        >>> q.expand('%{p}')
        'mx.example.org'

        >>> q.expand('%{p2}')
        'example.org'

        >>> q.expand('%{dr}')
        'com.example.email'
    
        >>> q.expand('%{d2r}')
        'example.email'

        >>> q.expand('%{l}')
        'strong-bad'

        >>> q.expand('%{l-}')
        'strong.bad'

        >>> q.expand('%{lr}')
        'strong-bad'

        >>> q.expand('%{lr-}')
        'bad.strong'

        >>> q.expand('%{l1r-}')
        'strong'

        >>> q.expand('%{c}',stripdot=False)
        '192.0.2.3'

        >>> q.expand('%{r}',stripdot=False)
        'example.net'

        >>> q.expand('%{ir}.%{v}._spf.%{d2}')
        '3.2.0.192.in-addr._spf.example.com'

        >>> q.expand('%{lr-}.lp._spf.%{d2}')
        'bad.strong.lp._spf.example.com'

        >>> q.expand('%{lr-}.lp.%{ir}.%{v}._spf.%{d2}')
        'bad.strong.lp.3.2.0.192.in-addr._spf.example.com'

        >>> q.expand('%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}')
        '3.2.0.192.in-addr.strong.lp._spf.example.com'

        >>> try: q.expand('%(ir).%{v}.%{l1r-}.lp._spf.%{d2}')
        ... except PermError,x: print x
        invalid-macro-char : %(ir)

        >>> q.expand('%{p2}.trusted-domains.example.net')
        'example.org.trusted-domains.example.net'

        >>> q.expand('%{p2}.trusted-domains.example.net.')
        'example.org.trusted-domains.example.net'

        >>> q = query(s='@email.example.com',
        ...           h='mx.example.org', i='192.0.2.3')
        >>> q.p = 'mx.example.org'
        >>> q.expand('%{l}')
        'postmaster'

        """
        macro_delimiters = ['{', '%', '-', '_']
        end = 0
        result = ''
        macro_count = str.count('%')
        if macro_count != 0:
            labels = str.split('.')
            for label in labels:
                is_macro = False
                if len(label) > 1:
                    if label[0] == '%':
                        for delimit in macro_delimiters:
                            if label[1] == delimit:
                                is_macro = True
                        if not is_macro:
                            raise PermError ('invalid-macro-char ', label)
                            break
        for i in RE_CHAR.finditer(str):
            result += str[end:i.start()]
            macro = str[i.start():i.end()]
            if macro == '%%':
                result += '%'
            elif macro == '%_':
                result += ' '
            elif macro == '%-':
                result += '%20'
            else:
                letter = macro[2].lower()
#                print letter
                if letter == 'p':
                    self.getp()
		elif letter in 'crt' and stripdot:
		    raise PermError(
		        'c,r,t macros allowed in exp= text only', macro)
                expansion = getattr(self, letter, self)
                if expansion:
                    if expansion == self:
                        raise PermError('Unknown Macro Encountered', macro) 
		    e = expand_one(expansion, macro[3:-1], JOINERS.get(letter))
		    if letter != macro[2]:
		        e = urllib.quote(e)
                    result += e

            end = i.end()
        result += str[end:]
        if stripdot and result.endswith('.'):
            result =  result[:-1]
        if result.count('.') != 0:
            if len(result) > 253:
                result = result[(result.index('.')+1):]
        return result

    def dns_spf(self, domain):
        """Get the SPF record recorded in DNS for a specific domain
        name.  Returns None if not found, or if more than one record
        is found.
        """
	# Per RFC 4.3/1, check for malformed domain.  This produces
	# no results as a special case.
	for label in domain.split('.'):
	  if not label or len(label) > 63:
	    return None
        # for performance, check for most common case of TXT first
        a = [t for t in self.dns_txt(domain) if RE_SPF.match(t)]
        if len(a) > 1:
            raise PermError('Two or more type TXT spf records found.')
        if len(a) == 1 and self.strict < 2:
            return a[0]               
        # check official SPF type first when it becomes more popular
        try:
            b = [t for t in self.dns_99(domain) if RE_SPF.match(t)]
        except TempError,x:
            # some braindead DNS servers hang on type 99 query
            if self.strict > 1: raise TempError(x)
            b = []

        if len(b) > 1:
            raise PermError('Two or more type SPF spf records found.')
        if len(b) == 1:
            if self.strict > 1 and len(a) == 1 and a[0] != b[0]:
            #Changed from permerror to warning based on RFC 4408 Auth 48 change
                raise AmbiguityWarning(
'v=spf1 records of both type TXT and SPF (type 99) present, but not identical')
            return b[0]
        if len(a) == 1:
            return a[0]    # return TXT if SPF wasn't found
        if DELEGATE:    # use local record if neither found
            a = [t
              for t in self.dns_txt(domain+'._spf.'+DELEGATE)
            if RE_SPF.match(t)
            ]
            if len(a) == 1: return a[0]
        return None

    def dns_txt(self, domainname):
        "Get a list of TXT records for a domain name."
        if domainname:
            return [''.join(a) for a in self.dns(domainname, 'TXT')]
        return []
    def dns_99(self, domainname):
        "Get a list of type SPF=99 records for a domain name."
        if domainname:
            return [''.join(a) for a in self.dns(domainname, 'SPF')]
        return []

    def dns_mx(self, domainname):
        """Get a list of IP addresses for all MX exchanges for a
        domain name.
        """
        # RFC 4408 section 5.4 "mx"
        # To prevent DoS attacks, more than 10 MX names MUST NOT be looked up
        mxnames = self.dns(domainname, 'MX')
        if self.strict:
            max = MAX_MX
            if self.strict > 1:
                if len(mxnames) > MAX_MX:
                    raise AmbiguityWarning(
                        'More than %d MX records returned'%MAX_MX)
                if len(mxnames) == 0:
                    raise AmbiguityWarning(
                        'No MX records found for mx mechanism', domainname)
        else:
            max = MAX_MX * 4
        return [a for mx in mxnames[:max] for a in self.dns_a(mx[1],self.A)]

    def dns_a(self, domainname, A='A'):
        """Get a list of IP addresses for a domainname.
	"""
        if not domainname: return []
        if self.strict > 1:
            alist = self.dns(domainname, A)
            if len(alist) == 0:
                raise AmbiguityWarning(
			'No %s records found for'%A, domainname)
            else:
                return alist
        return self.dns(domainname, A)

    def validated_ptrs(self):
        """Figure out the validated PTR domain names for the connect IP."""
# To prevent DoS attacks, more than 10 PTR names MUST NOT be looked up
        if self.strict:
            max = MAX_PTR
            if self.strict > 1:
                #Break out the number of PTR records returned for testing
                try:
                    ptrnames = self.dns_ptr(self.i)
                    if len(ptrnames) > max:
                        warning = 'More than %d PTR records returned' % max
                        raise AmbiguityWarning(warning, i)
                    else:
                        if len(ptrnames) == 0:
                            raise AmbiguityWarning(
                                'No PTR records found for ptr mechanism', self.c)
                except:
                    raise AmbiguityWarning(
                      'No PTR records found for ptr mechanism', i)
        else:
            max = MAX_PTR * 4
	cidrlength = self.cidrmax
        return [p for p in self.dns_ptr(self.i)[:max]
	    if self.cidrmatch(self.dns_a(p,self.A),cidrlength)]

    def dns_ptr(self, i):
        """Get a list of domain names for an IP address."""
        return self.dns('%s.%s.arpa'%(reverse_dots(i),self.v), 'PTR')

    # We have to be careful which additional DNS RRs we cache.  For
    # instance, PTR records are controlled by the connecting IP, and they
    # could poison our local cache with bogus A and MX records.  

    SAFE2CACHE = {
      ('MX','A'): None,
      ('MX','MX'): None,
      ('CNAME','A'): None,
      ('CNAME','CNAME'): None,
      ('A','A'): None,
      ('AAAA','AAAA'): None,
      ('PTR','PTR'): None,
      ('TXT','TXT'): None,
      ('SPF','SPF'): None
    }

    def dns(self, name, qtype, cnames=None):
        """DNS query.

        If the result is in cache, return that.  Otherwise pull the
        result from DNS, and cache ALL answers, so additional info
        is available for further queries later.

        CNAMEs are followed.

        If there is no data, [] is returned.

        pre: qtype in ['A', 'AAAA', 'MX', 'PTR', 'TXT', 'SPF']
        post: isinstance(__return__, types.ListType)
        """
        result = self.cache.get( (name, qtype) )
        cname = None

        if not result:
	    safe2cache = query.SAFE2CACHE
            for k, v in DNSLookup(name, qtype, self.strict):
                if k == (name, 'CNAME'):
                    cname = v
		if (qtype,k[1]) in safe2cache:
		    self.cache.setdefault(k, []).append(v)
            result = self.cache.get( (name, qtype), [])
        if not result and cname:
            if not cnames:
                cnames = {}
            elif len(cnames) >= MAX_CNAME:
                #return result    # if too many == NX_DOMAIN
                raise PermError('Length of CNAME chain exceeds %d' % MAX_CNAME)
            cnames[name] = cname
            if cname in cnames:
                raise PermError, 'CNAME loop'
            result = self.dns(cname, qtype, cnames=cnames)
        return result

    def cidrmatch(self, ipaddrs, n):
	"""Match connect IP against a list of other IP addresses."""
	try:
	    if self.v == 'ip6':
	        MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL
		bin = bin2long6
	    else:
	        MASK = 0xFFFFFFFFL
		bin = addr2bin
	    c = ~(MASK >> n) & MASK & self.ip
	    for ip in [bin(ip) for ip in ipaddrs]:
		if c == ~(MASK >> n) & MASK & ip: return True
	except socket.error: pass
	return False

    def get_header(self, res, receiver=None):
        if not receiver:
            receiver = self.r
        if res == 'permerror' and self.mech:
            tag = ' '.join([res] + self.mech)
	    return '%s (%s: %s) client-ip=%s; envelope-from=%s; helo=%s; ' \
	    	   'receiver=%s; identity=%s; problem=%s;' % (
		tag, receiver, self.get_header_comment(res), self.c,
		quote_value(self.s), quote_value(self.h), receiver, self.ident,
		quote_value(' '.join(self.mech)))
	return '%s (%s: %s) client-ip=%s; envelope-from=%s; helo=%s; ' \
		'receiver=%s; identity=%s;' % (
	    res, receiver, self.get_header_comment(res), self.c,
	    quote_value(self.s), quote_value(self.h), receiver, self.ident)

    def get_header_comment(self, res):
        """Return comment for Received-SPF header.
        """
        sender = self.o
        if res == 'pass':
            return \
                "domain of %s designates %s as permitted sender" \
                % (sender, self.c)
        elif res == 'softfail': return \
      "transitioning domain of %s does not designate %s as permitted sender" \
            % (sender, self.c)
        elif res == 'neutral': return \
            "%s is neither permitted nor denied by domain of %s" \
                % (self.c, sender)
        elif res == 'none': return \
            "%s is neither permitted nor denied by domain of %s" \
                  % (self.c, sender)
            #"%s does not designate permitted sender hosts" % sender
        elif res == 'permerror': return \
            "permanent error in processing domain of %s: %s" \
                  % (sender, self.prob)
        elif res == 'error': return \
              "temporary error in processing during lookup of %s" % sender
        elif res == 'fail': return \
              "domain of %s does not designate %s as permitted sender" \
              % (sender, self.c)
        raise ValueError("invalid SPF result for header comment: "+res)

def split_email(s, h):
    """Given a sender email s and a HELO domain h, create a valid tuple
    (l, d) local-part and domain-part.

    Examples:
    >>> split_email('', 'wayforward.net')
    ('postmaster', 'wayforward.net')

    >>> split_email('foo.com', 'wayforward.net')
    ('postmaster', 'foo.com')

    >>> split_email('terry@wayforward.net', 'optsw.com')
    ('terry', 'wayforward.net')
    """
    if not s:
        return 'postmaster', h
    else:
        parts = s.split('@', 1)
        if parts[0] == '':
            parts[0] = 'postmaster'
        if len(parts) == 2:
            return tuple(parts)
        else:
            return 'postmaster', s

def quote_value(s):
    """Quote the value for a key-value pair in Received-SPF header field
    if needed.  No quoting needed for a dot-atom value.

    Examples:
    >>> quote_value('foo@bar.com')
    '"foo@bar.com"'
    
    >>> quote_value('mail.example.com')
    'mail.example.com'

    >>> quote_value('A:1.2.3.4')
    '"A:1.2.3.4"'

    >>> quote_value('abc"def')
    '"abc\\\\"def"'

    >>> quote_value(r'abc\def')
    '"abc\\\\\\\\def"'

    >>> quote_value('abc..def')
    '"abc..def"'
    """
    if RE_DOT_ATOM.match(s):
      return s
    return '"' + s.replace('\\',r'\\').replace('"',r'\"') + '"'

def parse_mechanism(str, d):
    """Breaks A, MX, IP4, and PTR mechanisms into a (name, domain,
    cidr,cidr6) tuple.  The domain portion defaults to d if not present,
    the cidr defaults to 32 if not present.

    Examples:
    >>> parse_mechanism('a', 'foo.com')
    ('a', 'foo.com', None, None)

    >>> parse_mechanism('a:bar.com', 'foo.com')
    ('a', 'bar.com', None, None)

    >>> parse_mechanism('a/24', 'foo.com')
    ('a', 'foo.com', 24, None)

    >>> parse_mechanism('A:foo:bar.com/16//48', 'foo.com')
    ('a', 'foo:bar.com', 16, 48)

    >>> parse_mechanism('-exists:%{i}.%{s1}.100/86400.rate.%{d}','foo.com')
    ('-exists', '%{i}.%{s1}.100/86400.rate.%{d}', None, None)

    >>> parse_mechanism('mx:%%%_/.Claranet.de/27','foo.com')
    ('mx', '%%%_/.Claranet.de', 27, None)

    >>> parse_mechanism('mx:%{d}//97','foo.com')
    ('mx', '%{d}', None, 97)

    >>> parse_mechanism('iP4:192.0.0.0/8','foo.com')
    ('ip4', '192.0.0.0', 8, None)
    """

    a = RE_DUAL_CIDR.split(str)
    if len(a) == 3:
        str, cidr6 = a[0], int(a[1])
    else:
        cidr6 = None
    a = RE_CIDR.split(str)
    if len(a) == 3:
        str, cidr = a[0], int(a[1])
    else:
        cidr = None

    a = str.split(':', 1)
    if len(a) < 2:
        return str.lower(), d, cidr, cidr6
    return a[0].lower(), a[1], cidr, cidr6

def reverse_dots(name):
    """Reverse dotted IP addresses or domain names.

    Example:
    >>> reverse_dots('192.168.0.145')
    '145.0.168.192'

    >>> reverse_dots('email.example.com')
    'com.example.email'
    """
    a = name.split('.')
    a.reverse()
    return '.'.join(a)

def domainmatch(ptrs, domainsuffix):
    """grep for a given domain suffix against a list of validated PTR
    domain names.

    Examples:
    >>> domainmatch(['FOO.COM'], 'foo.com')
    1

    >>> domainmatch(['moo.foo.com'], 'FOO.COM')
    1

    >>> domainmatch(['moo.bar.com'], 'foo.com')
    0

    """
    domainsuffix = domainsuffix.lower()
    for ptr in ptrs:
        ptr = ptr.lower()

        if ptr == domainsuffix or ptr.endswith('.' + domainsuffix):
            return True

    return False

def addr2bin(str):
    """Convert a string IPv4 address into an unsigned integer.

    Examples::
    >>> addr2bin('127.0.0.1')
    2130706433L

    >>> addr2bin('127.0.0.1') == socket.INADDR_LOOPBACK
    1

    >>> addr2bin('255.255.255.254')
    4294967294L

    >>> addr2bin('192.168.0.1')
    3232235521L

    Unlike DNS.addr2bin, the n, n.n, and n.n.n forms for IP addresses
    are handled as well::
    >>> addr2bin('10.65536')
    167837696L
    >>> 10 * (2 ** 24) + 65536
    167837696

    >>> addr2bin('10.93.512')
    173867520L
    >>> 10 * (2 ** 24) + 93 * (2 ** 16) + 512
    173867520
    """
    return struct.unpack("!L", socket.inet_aton(str))[0]

def bin2long6(str):
    h, l = struct.unpack("!QQ", str)
    return h << 64 | l

if socket.has_ipv6:
    def inet_ntop(s):
        return socket.inet_ntop(socket.AF_INET6,s)
    def inet_pton(s):
        return socket.inet_pton(socket.AF_INET6,s)
else:
    def inet_ntop(s):
      """Convert ip6 address to standard hex notation.
      Examples:
      >>> inet_ntop(struct.pack("!HHHHHHHH",0,0,0,0,0,0xFFFF,0x0102,0x0304))
      '::FFFF:1.2.3.4'
      >>> inet_ntop(struct.pack("!HHHHHHHH",0x1234,0x5678,0,0,0,0,0x0102,0x0304))
      '1234:5678::102:304'
      >>> inet_ntop(struct.pack("!HHHHHHHH",0,0,0,0x1234,0x5678,0,0x0102,0x0304))
      '::1234:5678:0:102:304'
      >>> inet_ntop(struct.pack("!HHHHHHHH",0x1234,0x5678,0,0x0102,0x0304,0,0,0))
      '1234:5678:0:102:304::'
      >>> inet_ntop(struct.pack("!HHHHHHHH",0,0,0,0,0,0,0,0))
      '::'
      """
      # convert to 8 words
      a = struct.unpack("!HHHHHHHH",s)
      n = (0,0,0,0,0,0,0,0)	# null ip6
      if a == n: return '::'
      # check for ip4 mapped
      if a[:5] == (0,0,0,0,0) and a[5] in (0,0xFFFF):
	ip4 = '.'.join([str(i) for i in struct.unpack("!HHHHHHBBBB",s)[6:]])
	if a[5]:
	  return "::FFFF:" + ip4
	return "::" + ip4
      # find index of longest sequence of 0
      for l in (7,6,5,4,3,2,1):
	e = n[:l]
	for i in range(9-l):
	  if a[i:i+l] == e:
	    if i == 0:
	      return ':'+':%x'*(8-l) % a[l:]
	    if i == 8 - l:
	      return '%x:'*(8-l) % a[:-l] + ':'
	    return '%x:'*i % a[:i] + ':%x'*(8-l-i) % a[i+l:]
      return "%x:%x:%x:%x:%x:%x:%x:%x" % a

    def inet_pton(p):
      """Convert ip6 standard hex notation to ip6 address.
      Examples:
      >>> struct.unpack('!HHHHHHHH',inet_pton('::'))
      (0, 0, 0, 0, 0, 0, 0, 0)
      >>> struct.unpack('!HHHHHHHH',inet_pton('::1234'))
      (0, 0, 0, 0, 0, 0, 0, 4660)
      >>> struct.unpack('!HHHHHHHH',inet_pton('1234::'))
      (4660, 0, 0, 0, 0, 0, 0, 0)
      >>> struct.unpack('!HHHHHHHH',inet_pton('1234::5678'))
      (4660, 0, 0, 0, 0, 0, 0, 22136)
      >>> struct.unpack('!HHHHHHHH',inet_pton('::FFFF:1.2.3.4'))
      (0, 0, 0, 0, 0, 65535, 258, 772)
      >>> struct.unpack('!HHHHHHHH',inet_pton('1.2.3.4'))
      (0, 0, 0, 0, 0, 65535, 258, 772)
      >>> try: inet_pton('::1.2.3.4.5')
      ... except ValueError,x: print x
      ::1.2.3.4.5
      """
      if p == '::':
	return '\0'*16
      s = p
      m = RE_IP4.search(s)
      try:
	  if m:
	      pos = m.start()
	      ip4 = [int(i) for i in s[pos:].split('.')]
	      if not pos:
	          return struct.pack('!QLBBBB',0,65535,*ip4)
	      s = s[:pos]+'%x%02x:%x%02x'%tuple(ip4)
	  a = s.split('::')
	  if len(a) == 2:
	    l,r = a
	    if not l:
	      r = r.split(':')
	      return struct.pack('!HHHHHHHH',
		*[0]*(8-len(r)) + [int(s,16) for s in r])
	    if not r:
	      l = l.split(':')
	      return struct.pack('!HHHHHHHH',
		*[int(s,16) for s in l] + [0]*(8-len(l)))
	    l = l.split(':')
	    r = r.split(':')
	    return struct.pack('!HHHHHHHH',
		*[int(s,16) for s in l] + [0]*(8-len(l)-len(r))
		+ [int(s,16) for s in r])
	  if len(a) == 1:
	    return struct.pack('!HHHHHHHH',
		*[int(s,16) for s in a[0].split(':')])
      except ValueError: pass
      raise ValueError,p

def expand_one(expansion, str, joiner):
    if not str:
        return expansion
    ln, reverse, delimiters = RE_ARGS.split(str)[1:4]
    if not delimiters:
        delimiters = '.'
    expansion = split(expansion, delimiters, joiner)
    if reverse: expansion.reverse()
    if ln: expansion = expansion[-int(ln)*2+1:]
    return ''.join(expansion)

def split(str, delimiters, joiner=None):
    """Split a string into pieces by a set of delimiter characters.  The
    resulting list is delimited by joiner, or the original delimiter if
    joiner is not specified.

    Examples:
    >>> split('192.168.0.45', '.')
    ['192', '.', '168', '.', '0', '.', '45']

    >>> split('terry@wayforward.net', '@.')
    ['terry', '@', 'wayforward', '.', 'net']

    >>> split('terry@wayforward.net', '@.', '.')
    ['terry', '.', 'wayforward', '.', 'net']
    """
    result, element = [], ''
    for c in str:
        if c in delimiters:
            result.append(element)
            element = ''
            if joiner:
                result.append(joiner)
            else:
                result.append(c)
        else:
            element += c
    result.append(element)
    return result

def insert_libspf_local_policy(spftxt, local=None):
    """Returns spftxt with local inserted just before last non-fail
    mechanism.  This is how the libspf{2} libraries handle "local-policy".
    
    Examples:
    >>> insert_libspf_local_policy('v=spf1 -all')
    'v=spf1 -all'
    >>> insert_libspf_local_policy('v=spf1 -all','mx')
    'v=spf1 -all'
    >>> insert_libspf_local_policy('v=spf1','a mx ptr')
    'v=spf1 a mx ptr'
    >>> insert_libspf_local_policy('v=spf1 mx -all','a ptr')
    'v=spf1 mx a ptr -all'
    >>> insert_libspf_local_policy('v=spf1 mx -include:foo.co +all','a ptr')
    'v=spf1 mx a ptr -include:foo.co +all'

    # FIXME: is this right?  If so, "last non-fail" is a bogus description.
    >>> insert_libspf_local_policy('v=spf1 mx ?include:foo.co +all','a ptr')
    'v=spf1 mx a ptr ?include:foo.co +all'
    >>> spf='v=spf1 ip4:1.2.3.4 -a:example.net -all'
    >>> local='ip4:192.0.2.3 a:example.org'
    >>> insert_libspf_local_policy(spf,local)
    'v=spf1 ip4:1.2.3.4 ip4:192.0.2.3 a:example.org -a:example.net -all'
    """
    # look to find the all (if any) and then put local
    # just after last non-fail mechanism.  This is how
    # libspf2 handles "local policy", and some people
    # apparently find it useful (don't ask me why).
    if not local: return spftxt
    spf = spftxt.split()[1:]
    if spf:
        # local policy is SPF mechanisms/modifiers with no
        # 'v=spf1' at the start
        spf.reverse() #find the last non-fail mechanism
        for mech in spf:
        # map '?' '+' or '-' to 'neutral' 'pass'
        # or 'fail'
            if not RESULTS.get(mech[0]):
                # actually finds last mech with default result
                where = spf.index(mech)
                spf[where:where] = [local]
                spf.reverse()
                local = ' '.join(spf)
                break
        else:
            return spftxt # No local policy adds for v=spf1 -all
    # Processing limits not applied to local policy.  Suggest
    # inserting 'local' mechanism to handle this properly
    #MAX_LOOKUP = 100 
    return 'v=spf1 '+local

def _test():
    import doctest, spf
    return doctest.testmod(spf)

DNS.DiscoverNameServers() # Fails on Mac OS X? Add domain to /etc/resolv.conf

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 1:
        print USAGE
        _test()
    elif len(sys.argv) == 2:
        q = query(i='127.0.0.1', s='localhost', h='unknown',
            receiver=socket.gethostname())
        print q.dns_spf(sys.argv[1])
    elif len(sys.argv) == 4:
        print check(i=sys.argv[1], s=sys.argv[2], h=sys.argv[3],
            receiver=socket.gethostname())
    elif len(sys.argv) == 5:
        i, s, h = sys.argv[2:]
        q = query(i=i, s=s, h=h, receiver=socket.gethostname(),
            strict=False)
        print q.check(sys.argv[1])
        if q.perm_error and q.perm_error.ext:
            print q.perm_error.ext
    else:
        print USAGE
