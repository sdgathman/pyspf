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
#   31-jul-2006, v1.7, Backward compatible (with pyspf-1.6) version with old 
#                      result names, but most of the new RFC fixes.  Will 
#                      release a version with configurable result names and
#                      local policy later.
#
# Development taken over by Stuart Gathman <stuart@bmsi.com>.
#
# $Log$
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
__version__ = "1.7: July 31, 2006"
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

import DNS    # http://pydns.sourceforge.net
if not hasattr(DNS.Type, 'SPF'):
    # patch in type99 support
    DNS.Type.SPF = 99
    DNS.Type.typemap[99] = 'SPF'
    DNS.Lib.RRunpacker.getSPFdata = DNS.Lib.RRunpacker.getTXTdata

def DNSLookup(name, qtype):
    try:
        req = DNS.DnsRequest(name, qtype=qtype)
        resp = req.req()
        #resp.show()
        # key k: ('wayforward.net', 'A'), value v
        return [((a['name'], a['typename']), a['data']) for a in resp.answers]
    except IOError, x:
        raise error, 'DNS ' + str(x)
    except DNS.DNSError, x:
        raise error, 'DNS ' + str(x)

def isSPF(txt):
    "Return True if txt has SPF record signature."
    return txt.startswith('v=spf1 ') or txt == 'v=spf1'

# 32-bit IPv4 address mask
MASK = 0xFFFFFFFFL

# Regular expression to look for modifiers
RE_MODIFIER = re.compile(r'^([a-z][a-z0-9_\-\.]*)=', re.IGNORECASE)

# Regular expression to find macro expansions
RE_CHAR = re.compile(r'%(%|_|-|(\{[a-zA-Z][0-9]*r?[^\}]*\}))')

# Regular expression to break up a macro expansion
RE_ARGS = re.compile(r'([0-9]*)(r?)([^0-9a-zA-Z]*)')

RE_DUAL_CIDR = re.compile(r'//(0|[1-9]\d*)$')
RE_CIDR = re.compile(r'/(0|[1-9]\d*)$')

PAT_IP4 = r'\.'.join([r'(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])']*4)
RE_IP4 = re.compile(PAT_IP4+'$')

RE_TOPLAB = re.compile(
    r'\.[0-9a-z]*[a-z][0-9a-z]*|[0-9a-z]+-[0-9a-z-]*[0-9a-z]$', re.IGNORECASE)

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
           'pass': 'pass', 'fail': 'fail', 'unknown': 'unknown',
       'error': 'error', 'neutral': 'neutral', 'softfail': 'softfail',
       'none': 'none', 'local': 'local', 'trusted': 'trusted',
           'ambiguous': 'ambiguous'}

EXPLANATIONS = {'pass': 'sender SPF authorized',
                'fail': 'SPF fail - not authorized',
                'unknown': 'permanent error in processing',
                'error': 'temporary DNS error in processing',
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
COMMON_MISTAKES = { 'prt': 'ptr', 'ip': 'ip4', 'ipv4': 'ip4', 'ipv6': 'ip6' }


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

class error(Exception):
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

class unknown(Exception):
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

def check(i, s, h, local=None, receiver=None):
    """Test an incoming MAIL FROM:<s>, from a client with ip address i.
    h is the HELO/EHLO domain name.

    Returns (result,  code, explanation) where result in
    ['pass', 'unknown', 'fail', 'error', 'softfail', 'none', 'neutral' ].
    
    Example:
        >>> check(i='127.0.0.1', s='terry@wayforward.net', h='localhost')
        ('pass', 250, 'local connections always pass')

    Example:
    #>>> check(i='61.51.192.42', s='liukebing@bcc.com', h='bmsi.com')

    """
    return query(i=i, s=s, h=h, local=local, receiver=receiver).check()

class query(object):
    """A query object keeps the relevant information about a single SPF
    query:

    i: ip address of SMTP client
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
        self.i, self.s, self.h = i, s, h
        if not s and h:
            self.s = 'postmaster@' + h
        self.l, self.o = split_email(s, h)
        self.t = str(int(time.time()))
        self.v = 'in-addr'
        self.d = self.o
        self.p = None
        if receiver:
            self.r = receiver
        else:
            self.r = 'unknown'
	self.c = self.i
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

    def set_default_explanation(self, exp):
        exps = self.exps
        defexps = self.defexps
        for i in 'softfail', 'fail', 'unknown':
            exps[i] = exp
            defexps[i] = exp

    def set_explanation(self, exp):
        exps = self.exps
        for i in 'softfail', 'fail', 'unknown':
            exps[i] = exp

    def getp(self):
        if not self.p:
            p = self.dns_ptr(self.i)
            if len(p) > 0:
                self.p = p[0]
            else:
                self.p = self.i
        return self.p

    def best_guess(self, spf=DEFAULT_SPF):
        """Return a best guess based on a default SPF record"""
        return self.check(spf)


    def check(self, spf=None):
        """
    Returns (result, mta-status-code, explanation) where result
    in ['fail', 'softfail', 'neutral' 'unknown', 'pass', 'error', 'none']

    Examples:
    >>> q = query(s='strong-bad@email.example.com',
    ...           h='mx.example.org', i='192.0.2.3')
    >>> q.check(spf='v=spf1 ?all')
    ('neutral', 250, 'access neither permitted nor denied')

    >>> q.check(spf='v=spf1 redirect=controlledmail.com exp=_exp.controlledmail.com')
    ('fail', 550, 'SPF fail - not authorized')
    
    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 ?all moo')
    ('unknown', 550, 'SPF Permanent Error: Unknown mechanism found: moo')

    >>> q.check(spf='v=spf1 =a ?all moo')
    ('unknown', 550, 'SPF Permanent Error: Unknown qualifier, RFC 4408 para 4.6.1, found in: =a')

    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 ~all')
    ('pass', 250, 'sender SPF authorized')

    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 -all moo=')
    ('pass', 250, 'sender SPF authorized')

    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 -all match.sub-domains_9=yes')
    ('pass', 250, 'sender SPF authorized')

    >>> q.strict = False
    >>> q.check(spf='v=spf1 ip4:192.0.0.0/8 -all moo')
    ('pass', 250, 'sender SPF authorized')

    >>> q.strict = True
    >>> q.check(spf='v=spf1 ip4:192.1.0.0/16 moo -all')
    ('unknown', 550, 'SPF Permanent Error: Unknown mechanism found: moo')

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
        if self.i.startswith('127.'):
            return ('pass', 250, 'local connections always pass')
        # If not strict, certain unknowns (mispelled
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
            return self.check1(spf, self.d, 0)
        except error, x:
            self.prob = x.msg
            if x.mech:
                self.mech.append(x.mech)
            return ('error', 451, 'SPF Temporary Error: ' + str(x))
        except unknown, x:
            if not self.perm_error:
                self.perm_error = x
            self.prob = x.msg
            if x.mech:
                self.mech.append(x.mech)
            # Pre-Lentczner draft treats this as an unknown result
            # and equivalent to no SPF record.
            return ('unknown', 550, 'SPF Permanent Error: ' + str(x))

    def check1(self, spf, domain, recursion):
        # spf rfc: 3.7 Processing Limits
        #
        if recursion > MAX_RECURSION:
            # This should never happen in strict mode
            # because of the other limits we check,
            # so if it does, there is something wrong with
            # our code.  It is not a unknown because there is not
            # necessarily anything wrong with the SPF record.
            if self.strict:
                raise AssertionError('Too many levels of recursion')
            # As an extended result, however, it should be
            # a unknown.
            raise unknown('Too many levels of recursion')
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
            raise unknown(*msg)
        # if lax mode, note error and continue
        if not self.perm_error:
            try:
                raise unknown(*msg)
            except unknown, x:
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
    ... except unknown,x: print x
    Invalid IP4 CIDR length: ip4:1.2.3.4/247
    
    >>> try: q.validate_mechanism('ip4:1.2.3.4/33')
    ... except unknown,x: print x
    Invalid IP4 CIDR length: ip4:1.2.3.4/33

    >>> try: q.validate_mechanism('a:example.com:8080')
    ... except unknown,x: print x
    Invalid domain found (use FQDN): example.com:8080
    
    >>> try: q.validate_mechanism('ip4:1.2.3.444/24')
    ... except unknown,x: print x
    Invalid IP4 address: ip4:1.2.3.444/24
    
    >>> try: q.validate_mechanism('ip4:1.2.03.4/24')
    ... except unknown,x: print x
    Invalid IP4 address: ip4:1.2.03.4/24
    
    >>> try: q.validate_mechanism('-all:3030')
    ... except unknown,x: print x
    Invalid all mechanism format - only qualifier allowed with all: -all:3030

    >>> q.validate_mechanism('-mx:%%%_/.Clara.de/27')
    ('-mx:%%%_/.Clara.de/27', 'mx', '% /.Clara.de', 27, 'fail')

    >>> q.validate_mechanism('~exists:%{i}.%{s1}.100/86400.rate.%{d}')
    ('~exists:%{i}.%{s1}.100/86400.rate.%{d}', 'exists', '192.0.2.3.com.100/86400.rate.email.example.com', 32, 'softfail')

    >>> q.validate_mechanism('a:mail.example.com.')
    ('a:mail.example.com.', 'a', 'mail.example.com', 32, 'pass')
        """
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
        if m in ('a', 'mx', 'ptr'):
            if cidrlength is None:
                cidrlength = 32;
            elif cidrlength > 32:
                raise unknown('Invalid IP4 CIDR length', mech)
            if cidr6length is None:
                cidr6length = 128
            elif cidr6length > 128:
                raise unknown('Invalid IP6 CIDR length', mech)
        elif m == 'ip4':
            if cidr6length is not None:
                raise unknown('Dual CIDR not allowed', mech)
            if cidrlength is None:
                cidrlength = 32;
            elif cidrlength > 32:
                raise unknown('Invalid IP4 CIDR length', mech)
            if not RE_IP4.match(arg):
                raise unknown('Invalid IP4 address', mech)
        elif m == 'ip6':
            if cidr6length is not None:
                raise unknown('Dual CIDR not allowed', mech)
            if cidrlength is None:
                cidrlength = 128
            elif cidrlength > 128:
                raise unknown('Invalid IP6 CIDR length', mech)
            if not RE_IP6.match(arg):
                raise unknown('Invalid IP6 address', mech)
        else:
            if cidrlength is not None or cidr6length is not None:
                raise unknown('Dual CIDR not allowed', mech)
            cidrlength = 32

        # validate domain-spec
        if m in ('a', 'mx', 'ptr', 'exists', 'include'):
            arg = self.expand(arg)
            # any trailing dot was removed by expand()
            if RE_TOPLAB.split(arg)[-1]:
                raise unknown('Invalid domain found (use FQDN)', arg)
            if m == 'include':
                if arg == self.d:
                    if mech != 'include':
                        raise unknown('include has trivial recursion', mech)
                    raise unknown('include mechanism missing domain', mech)
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
        # in the future we might want to give unknown
        # for common mistakes like IN TXT "v=spf1" "mx" "-all"
        # in relaxed mode.
        if spf[0] != 'v=spf1':
            raise unknown('Invalid SPF record in', self.d)
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
	        # always fetch explanation to check unknowns
	        exp = self.get_explanation(m[1])
	        if not recursion:
		    # only set explanation in base recursion level
		    self.set_explanation(exp)
            elif m[0] == 'redirect':
                self.check_lookups()
                redirect = self.expand(m[1])
            elif m[0] == 'default':
                # default=- is the same as default=fail
                default = RESULTS.get(m[1], default)

            # spf rfc: 3.6 Unrecognized Mechanisms and Modifiers

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
                    if len(self.dns_a(arg)) > 0:
                        break
                except AmbiguityWarning:
                    # Exists wants no response sometimes so don't raise
                    # the warning.
                    pass

            elif m == 'a':
                self.check_lookups()
                if cidrmatch(self.i, self.dns_a(arg), cidrlength):
                    break

            elif m == 'mx':
                self.check_lookups()
                if cidrmatch(self.i, self.dns_mx(arg), cidrlength):
                    break

            elif m == 'ip4':
                if arg == self.d:
                    raise unknown('Missing IP4 arg', mech)
                try:
                    if cidrmatch(self.i, [arg], cidrlength):
                        break
                except socket.error:
                    raise unknown('syntax error', mech)

            elif m == 'ip6':
                if arg == self.d:
                    raise unknown('Missing IP6 arg', mech)
            # Until we support IPV6, we should never
            # get an IPv6 connection.  So this mech
            # will never match.
                pass

            elif m == 'ptr':
                self.check_lookups()
                if domainmatch(self.validated_ptrs(self.i), arg):
                    break

        else:
            # no matches
            if redirect:
                #Catch redirect to a non-existant SPF record.
                redirect_record = self.dns_spf(redirect)
                if not redirect_record:
                    raise unknown('redirect domain has no SPF record',
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
            raise unknown('More than %d DNS lookups'%MAX_LOOKUP*4)
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
        ... except unknown,x: print x
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
                            raise unknown ('invalid-macro-char ', label)
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
		    raise unknown(
		        'c,r,t macros allowed in exp= text only', macro)
                expansion = getattr(self, letter, self)
                if expansion:
                    if expansion == self:
                        raise unknown('Unknown Macro Encountered', macro) 
                    result += expand_one(expansion, macro[3:-1], 
                        JOINERS.get(letter))

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
        # for performance, check for most common case of TXT first
        a = [t for t in self.dns_txt(domain) if isSPF(t)]
        if len(a) > 1:
            raise unknown('Two or more type TXT spf records found.')
        if len(a) == 1 and self.strict < 2:
            return a[0]               
        # check official SPF type first when it becomes more popular
        try:
            b = [t for t in self.dns_99(domain) if isSPF(t)]
        except error,x:
            # some braindead DNS servers hang on type 99 query
            if self.strict > 1: raise error(x)
            b = []

        if len(b) > 1:
            raise unknown('Two or more type SPF spf records found.')
        if len(b) == 1:
            if self.strict > 1 and len(a) == 1 and a[0] != b[0]:
            #Changed from unknown to warning based on RFC 4408 Auth 48 change
                raise AmbiguityWarning(
'v=spf1 records of both type TXT and SPF (type 99) present, but not identical')
            return b[0]
        if len(a) == 1:
            return a[0]    # return TXT if SPF wasn't found
        if DELEGATE:    # use local record if neither found
            a = [t
              for t in self.dns_txt(domain+'._spf.'+DELEGATE)
            if isSPF(t)
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
        return [a for mx in mxnames[:max] for a in self.dns_a(mx[1])]

    def dns_a(self, domainname):
        """Get a list of IP addresses for a domainname."""
        if not domainname: return []
        if self.strict > 1:
            alist = self.dns(domainname, 'A')
            if len(alist) == 0:
                raise AmbiguityWarning('No A records found for', domainname)
            else:
                return alist
        return self.dns(domainname, 'A')

    def dns_aaaa(self, domainname):
        """Get a list of IPv6 addresses for a domainname."""
        return self.dns(domainname, 'AAAA')

    def validated_ptrs(self, i):
        """Figure out the validated PTR domain names for a given IP
        address.
        """
# To prevent DoS attacks, more than 10 PTR names MUST NOT be looked up
        if self.strict:
            max = MAX_PTR
            if self.strict > 1:
                #Break out the number of PTR records returned for testing
                try:
                    ptrnames = self.dns_ptr(i)
                    ptrip = [p for p in ptrnames if i in self.dns_a(p)]
                    if len(ptrnames) > max:
                        warning = 'More orgthan ' + str(max)\
                             + ' PTR records returned'
                        raise AmbiguityWarning(warning, i)
                    else:
                        if len(ptrnames) == 0:
                            raise AmbiguityWarning(
                                'No PTR records found for ptr mechanism', i)
                    return ptrip
                except:
                    raise AmbiguityWarning(
                      'No PTR records found for ptr mechanism', i)
        else:
            max = MAX_PTR * 4
        return [p for p in self.dns_ptr(i)[:max] if i in self.dns_a(p)]

    def dns_ptr(self, i):
        """Get a list of domain names for an IP address."""
        return self.dns(reverse_dots(i) + ".in-addr.arpa", 'PTR')

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
            for k, v in DNSLookup(name, qtype):
                if k == (name, 'CNAME'):
                    cname = v
                self.cache.setdefault(k, []).append(v)
            result = self.cache.get( (name, qtype), [])
        if not result and cname:
            if not cnames:
                cnames = {}
            elif len(cnames) >= MAX_CNAME:
                #return result    # if too many == NX_DOMAIN
                raise unknown('Length of CNAME chain exceeds %d' % MAX_CNAME)
            cnames[name] = cname
            if cname in cnames:
                raise unknown, 'CNAME loop'
            result = self.dns(cname, qtype, cnames=cnames)
        return result

    def get_header(self, res, receiver=None):
        if not receiver:
            receiver = self.r
        if res in ('pass', 'fail',' softfail'):
            return '%s (%s: %s) client-ip=%s; envelope-from=%s; helo=%s;' % (
                res, receiver, self.get_header_comment(res), self.i,
                self.l + '@' + self.o, self.h)
        if res == 'unknown':
            return '%s (%s: %s)' % (' '.join([res] + self.mech),
            receiver,self.get_header_comment(res))
        return '%s (%s: %s)' % (res, receiver, self.get_header_comment(res))

    def get_header_comment(self, res):
        """Return comment for Received-SPF header.
        """
        sender = self.o
        if res == 'pass':
            return \
                "domain of %s designates %s as permitted sender" \
                % (sender, self.i)
        elif res == 'softfail': return \
      "transitioning domain of %s does not designate %s as permitted sender" \
            % (sender, self.i)
        elif res == 'neutral': return \
            "%s is neither permitted nor denied by domain of %s" \
                % (self.i, sender)
        elif res == 'none': return \
            "%s is neither permitted nor denied by domain of %s" \
                  % (self.i, sender)
            #"%s does not designate permitted sender hosts" % sender
        elif res == 'unknown': return \
            "permanent error in processing domain of %s: %s" \
                  % (sender, self.prob)
        elif res == 'error': return \
              "temporary error in processing during lookup of %s" % sender
        elif res == 'fail': return \
              "domain of %s does not designate %s as permitted sender" \
              % (sender, self.i)
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

    >>> parse_mechanism('A:foo:bar.com/16', 'foo.com')
    ('a', 'foo:bar.com', 16, None)

    >>> parse_mechanism('-exists:%{i}.%{s1}.100/86400.rate.%{d}','foo.com')
    ('-exists', '%{i}.%{s1}.100/86400.rate.%{d}', None, None)

    >>> parse_mechanism('mx:%%%_/.Claranet.de/27','foo.com')
    ('mx', '%%%_/.Claranet.de', 27, None)

    >>> parse_mechanism('mx:%{d}/27','foo.com')
    ('mx', '%{d}', 27, None)

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

def cidrmatch(i, ipaddrs, cidr_length = 32):
    """Match an IP address against a list of other IP addresses.

    Examples:
    >>> cidrmatch('192.168.0.45', ['192.168.0.44', '192.168.0.45'])
    1

    >>> cidrmatch('192.168.0.43', ['192.168.0.44', '192.168.0.45'])
    0

    >>> cidrmatch('192.168.0.43', ['192.168.0.44', '192.168.0.45'], 24)
    1
    """
    try:
        c = cidr(i, cidr_length)
        for ip in ipaddrs:
            if cidr(ip, cidr_length) == c:
                return True
    except socket.error: pass
    return False

def cidr(i, n):
    """Convert an IP address string with a CIDR mask into a 32-bit
    or 128-bit integer.

    i must be a string of numbers 0..255 separated by dots '.'::
    pre: forall([0 <= int(p) < 256 for p in i.split('.')])

    n is a number of bits to mask::
    pre: 0 <= n <= 32

    Examples:
    >>> bin2addr(cidr('192.168.5.45', 32))
    '192.168.5.45'
    >>> bin2addr(cidr('192.168.5.45', 24))
    '192.168.5.0'
    >>> bin2addr(cidr('192.168.0.45', 8))
    '192.0.0.0'
    """
    return ~(MASK >> n) & MASK & addr2bin(i)

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
    try:
        return struct.unpack("!L", socket.inet_aton(str))[0]
    except socket.error:
        if not socket.has_ipv6: raise
    h, l = struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, str))
    return h << 64 | l;

def bin2addr(addr):
    """Convert a numeric IPv4 address into string n.n.n.n form.

    Examples::
    >>> bin2addr(socket.INADDR_LOOPBACK)
    '127.0.0.1'

    >>> bin2addr(socket.INADDR_ANY)
    '0.0.0.0'

    >>> bin2addr(socket.INADDR_NONE)
    '255.255.255.255'
    """
    return socket.inet_ntoa(struct.pack("!L", addr))

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
