#!/usr/bin/env python
"""SPF (Sender Policy Framework) implementation.

Copyright (c) 2003, Terence Way
Portions Copyright (c) 2004,2005 Stuart Gathman <stuart@bmsi.com>
Portions Copyright (c) 2005 Scott Kitterman <scott@kitterman.com>
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
# Development taken over by Stuart Gathman <stuart@bmsi.com> since
# Terrence is not responding to email.
#
# $Log$
# Revision 1.70  2006/09/18 02:13:27  kitterma
# Worked through a large number of pylint issues - all 4 spaces, not a mix
# of 4 spaces, 2 spaces, and tabs. Caught a few minor errors in the process.
# All built in tests still pass.
#
# Revision 1.69  2006/09/17 18:44:25  kitterma
# Fixed validation mode only crash bug when rDNS check had no PTR record
#
# Revision 1.68  2006/09/01 23:56:43  customdesigned
# Fix improved RE_IP6
#
# Revision 1.67  2006/09/01 23:27:56  customdesigned
# Improved RE_IP6
#
# Revision 1.66  2006/09/01 22:16:41  customdesigned
# Parse IP6 for RFC conformance.
#
# Revision 1.65  2006/08/31 18:00:18  customdesigned
# Fix dual-cidr-length parsing.
#
# Revision 1.64  2006/08/30 17:54:23  customdesigned
# Fix dual-cidr.
#
# Revision 1.63  2006/07/28 01:53:03  customdesigned
# Localhost shouldn't get automatic pass
#
# Revision 1.62  2006/07/27 03:56:45  customdesigned
# Removed redundant trailing dot check.
#
# Revision 1.61  2006/07/26 21:40:19  customdesigned
# YAML test format.  Accept trailing dot on domains.
#
# Revision 1.60  2006/06/28 04:25:38  customdesigned
# Catch unexpected IO errors from pydns.
#
# Revision 1.59  2006/05/19 13:18:23  kitterma
# Fix to disallow ':' except between the mechanism and domain-spec.
#
# Revision 1.58  2006/05/19 02:04:58  kitterma
# Corrected validation bug where 'all' mechanism was not correctly checked,
# updated for RFC 4408 Auth 48 changes - trailing dot now allowed in domain
# name and Type TXT and Type SPF DNS records not identical raises a warning
# instead of a permanent error, and changed internet draft references to refer
# to RFC 4408.
#
# Revision 1.57  2006/05/12 16:38:12  customdesigned
# a:1.2.3.4 -> ip4:1.2.3.4 heuristic.
#
# Revision 1.56  2005/12/29 19:14:11  customdesigned
# Handle NULL MX and other A lookups of DNS root.
#
# Revision 1.55  2005/10/30 00:41:48  customdesigned
# Ignore SPF records missing space after version as required by RFC.
# FIXME: in "relaxed" mode, give permerror when there is exactly one
# such malformed record.
#
# Revision 1.54  2005/08/23 21:50:10  customdesigned
# Missing separator line in insert_libspf_local_policy self test.
#
# Revision 1.53  2005/08/23 20:37:19  customdesigned
# Simplify libspf_local further.  FIXME for possible specification error.
#
# Revision 1.52  2005/08/23 20:23:31  customdesigned
# Clean up libspf_local and add inline test cases.
# Repair try..finally in check1() broken when Ambiguity warning added.
#
# Revision 1.51  2005/08/19 19:06:49  customdesigned
# use note_error method for consistent extended processing.
# Return extended result, strict result in self.perm_error
#
# Revision 1.50  2005/08/19 18:13:31  customdesigned
# Still want to do strict tests in even stricter modes.
#
# Revision 1.49  2005/08/12 18:54:34  kitterma
# Consistently treat strict as a numeric for hard processing.
#
# Revision 1.48  2005/08/11 14:30:44  kitterma
# Restore all numeric TLD test from 1.44 that was inadvertently deleted.  Ugh.
#
# Revision 1.47  2005/08/10 13:31:34  kitterma
# Completed first part of local policy implementation.  Local policy will now be
# added before the last non-fail mechanism as in Libspf2 and Mail::SPF::Query.
# Still ToDo for local policy is: don't do local policy until after redirect=,
# modify explanation to indicate result is based on local policy, and an option
# for RFE [ 1224459 ] local policy API to execute local policy before public
# policy.  Will do the RFE after basic compatibility with the reference
# implementations.  Restored Unix line endings.  Changed Harsh mode check for
# ambiguity to exclude exists: mechanisms.
#
# Revision 1.46  2005/08/08 15:03:28  kitterma
# Added PermError for redirect= to a domain without an SPF record.
#
# Revision 1.45  2005/08/08 03:04:44  kitterma
# Added PermError for multiple SPF records per para 4.5 of schlitt-02
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
        raise TempError, 'DNS ' + str(x)
    except DNS.DNSError, x:
        raise TempError, 'DNS ' + str(x)

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

#Default receiver policies - can be overridden.
POLICY = {'tfwl': False, #Check trusted-forwarder.org
          'skip_localhost': True, #Don't check SPF on local connections
          'always_helo': False, #Only works if helo_first is also True.
          'spf_helo_mustpass': True, #Treat HELO test returning softfail or
          #neutral as Fail - HELO should be a single IP per name.  No reason to
          #accept SPF relaxed provisions for HELO.  No affect if None.
          'reject_helo_fail': False, 
          'spf_reject_fail': True,
          'spf_reject_neutral': False,
          'spf_accept_softfail': True,
          'spf_best_guess': True,
          'spf_strict': True,
        }
# Recommended SMTP codes for certain SPF results.  For results not in
# this table the recommendation is to accept the message as authorized.
# An SPF result is never enough to recommend that a message be accepted for
# delivery.  Additional checks are generally required.
# The softfail result requires special processing.

SMTP_CODES = {
  'fail': [550,'5.7.1'],
  'temperror': [451,'4.4.3'],
  'permerror': [550,'5.5.2'],
  'softfail': [451,'4.3.0']
        }
if not POLICY['spf_accept_softfail']:
    SMTP_CODES['softfail'] = (550,'5.7.1')
if POLICY['spf_reject_neutral']:
    SMTP_CODES['neutral'] = (550,'5.7.1')
# if set to a domain name, search _spf.domain namespace if no SPF record
# found in source domain.

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

def check(i, s, h, local=None, receiver=None):
    """Test an incoming MAIL FROM:<s>, from a client with ip address i.
    h is the HELO/EHLO domain name.

    Returns (result,  code, explanation) where result in
    ['pass', 'permerror', 'fail', 'temperror', 'softfail', 'none', 'neutral' ].

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
        for i in 'softfail', 'fail', 'permerror':
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
    in ['fail', 'softfail', 'neutral' 'permerror', 'pass', 'temperror', 'none']

    Examples:
    >>> q = query(s='strong-bad@email.example.com',
    ...           h='mx.example.org', i='192.0.2.3')
    >>> q.check(spf='v=spf1 ?all')
    ('neutral', 250, 'access neither permitted nor denied')

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
            return self.check1(spf, self.d, 0)
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

    >>> try: q.validate_mechanism('a:example.com:8080')
    ... except PermError,x: print x
    Invalid domain found (use FQDN): example.com:8080
    
    >>> try: q.validate_mechanism('ip4:1.2.3.444/24')
    ... except PermError,x: print x
    Invalid IP4 address: ip4:1.2.3.444/24
    
    >>> try: q.validate_mechanism('-all:3030')
    ... except PermError,x: print x
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
                raise PermError('Invalid IP4 CIDR length', mech)
            if cidr6length is None:
                cidr6length = 128
            elif cidr6length > 128:
                raise PermError('Invalid IP6 CIDR length', mech)
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
                raise PermError('Dual CIDR not allowed', mech)
            cidrlength = 32

        # validate domain-spec
        if m in ('a', 'mx', 'ptr', 'exists', 'include'):
            arg = self.expand(arg)
            # any trailing dot was removed by expand()
            if RE_TOPLAB.split(arg)[-1]:
                raise PermError('Invalid domain found (use FQDN)', arg)
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
        # in the future we might want to give permerror
        # for common mistakes like IN TXT "v=spf1" "mx" "-all"
        # in relaxed mode.
        if spf[0] != 'v=spf1':
            raise PermError('Invalid SPF record in', self.d)
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
                try:
                    self.set_default_explanation(self.get_explanation(m[1]))
                except PermError:
                    pass
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
                    raise PermError('Missing IP4 arg', mech)
                try:
                    if cidrmatch(self.i, [arg], cidrlength):
                        break
                except socket.error:
                    raise PermError('syntax error', mech)

            elif m == 'ip6':
                if arg == self.d:
                    raise PermError('Missing IP6 arg', mech)
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
                    raise PermError('redirect domain has no SPF record',
                        redirect)
                return self.check1(redirect_record, redirect, recursion + 1)
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

        >>> q.expand('%{ir}.%{v}._spf.%{d2}')
        '3.2.0.192.in-addr._spf.example.com'

        >>> q.expand('%{lr-}.lp._spf.%{d2}')
        'bad.strong.lp._spf.example.com'

        >>> q.expand('%{lr-}.lp.%{ir}.%{v}._spf.%{d2}')
        'bad.strong.lp.3.2.0.192.in-addr._spf.example.com'

        >>> q.expand('%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}')
        '3.2.0.192.in-addr.strong.lp._spf.example.com'

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
        end = 0
        result = ''
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
                if letter == 'p':
                    self.getp()
                expansion = getattr(self, letter, 'Macro Error')
                if expansion:
                    if expansion == 'Macro Error':
                        raise PermError('Unknown Macro Encountered') 
                    result += expand_one(expansion, macro[3:-1], 
                        JOINERS.get(letter))

            end = i.end()
        result += str[end:]
        if stripdot and result.endswith('.'):
            return result[:-1]
        return result

    def dns_spf(self, domain):
        """Get the SPF record recorded in DNS for a specific domain
        name.  Returns None if not found, or if more than one record
        is found.
        """
        # for performance, check for most common case of TXT first
        a = [t for t in self.dns_txt(domain) if isSPF(t)]
        if len(a) > 1:
            raise PermError('Two or more type TXT spf records found.')
        if len(a) == 1 and self.strict < 2:
            return a[0]               
        # check official SPF type first when it becomes more popular
        try:
            b = [t for t in self.dns_99(domain) if isSPF(t)]
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
        if len(mxnames) > MAX_MX:
            self.note_error('More than %d MX records returned'%MAX_MX)
        if self.strict:
            max = MAX_MX
            if self.strict > 1 and len(mxnames) == 0:
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
                raise PermError('Length of CNAME chain exceeds %d' % MAX_CNAME)
            cnames[name] = cname
            if cname in cnames:
                raise PermError, 'CNAME loop'
            result = self.dns(cname, qtype, cnames=cnames)
        return result

    def get_header(self, res, receiver=None):
        if not receiver:
            receiver = self.r
        if res in ('pass', 'fail',' softfail'):
            return '%s (%s: %s) client-ip=%s; envelope-from=%s; helo=%s;' % (
                res, receiver, self.get_header_comment(res), self.i,
                self.l + '@' + self.o, self.h)
        if res == 'permerror':
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
        elif res == 'permerror': return \
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
