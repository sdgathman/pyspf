SPF
===

Sender-Policy-Framework queries in Python
-----------------------------------------

Quick Start
===========

Installation
------------
This package requires either the dns (dnspython) or DNS (PyDNS/Py3DNS modules
and either the ipaddress module or python3.3 and later.  For dnspython, at
least version 1.16.0 is required.  The authres module is required to process
and generate RFC 8601 Authentication Results headers.  These can all be
installed from pypi via pip.  Additionally, they are also available via many
distribution packaging systems.

The minimum Python version required is python2.6.  The spf module in this
version has been tested with python3 versions through python3.8.

Testing
-------
After this package is installed, cd into the test directory and
execute testspf.py::

    % cd test
    % python testspf.py
    WARN: invalid-domain-long in rfc4408-tests.yml, 8.1/2, 5/10: fail preferred to temperror
    WARN: txttimeout in rfc4408-tests.yml, 4.4/1: fail preferred to temperror
    WARN: spfoverride in rfc4408-tests.yml, 4.5/5: pass preferred to fail
    WARN: multitxt1 in rfc4408-tests.yml, 4.5/5: pass preferred to permerror
    WARN: multispf2 in rfc4408-tests.yml, 4.5/6: permerror preferred to pass
    ..
    ----------------------------------------------------------------------
    Ran 2 tests in 3.036s

    OK

This runs the SPF council test-suite as of when this package was built.
It does not test the pyDNS installation, but uses an internal driver.
This avoids changing results due to DNS timeouts.

In addition, spf.py runs an internal self-test every time it is used from the
command line.

If you're running on Mac OS X, and it looks like DNS.DiscoverNameServers()
is failing, you'll need to edit your /etc/resolv.conf and specify a
domain name.  For some reason, OS X writes out resolv.conf with a single
'domain' line, which isn't good at all.  Later versions of py3dns have been
updated to better support Max OS X.


Description
===========
SPF does email sender validation.  For more information about SPF,
please see http://www.open-spf.org/

One incompatible change was introduced in version 1.7.  Prior to version 1.7,
connections from a local IP address (127...) would always return a Pass 
result.  The special case was eliminated.  Programs calling pySPF should not
do SPF checks on locally submitted mail.

This SPF client is intended to be installed on the border MTA, checking
if incoming SMTP clients are permitted to forward mail.  The SPF check
should be done during the MAIL FROM:<...> command.

There are two ways to use this package.  The first is from the command
line::

	% python spf.py {ip-addr} {mail-from} {helo}

For instance, during an SMTP exchange from client 69.55.226.139::

	S: 220 mail.example.com ESMTP Postfix
	C: EHLO mx1.wayforward.net
	S: 250-mail.example.com
	S: ...
	S: 250 8BITMIME
	C: MAIL FROM:<terry@wayforward.net>

Then the following command line would check if this is a valid sender::

	% ./spf.py 69.55.226.139 terry@wayforward.net mx1.wayforward.net ('pass', 250, 'sender SPF authorized')

Command line calls return RFC 4408/7208 result codes, i.e. 'pass', 'fail',
'neutral', 'softfail, 'permerror', or 'temperror'.

The second way is via the module's APIs.

The legacy (pySPF 1.6) API:
	>>> import spf
	>>> spf.check(i='69.55.226.139',
	...           s='terry@wayforward.net',
	...           h='mx1.wayforward.net')
	('pass', 250, 'sender SPF authorized')

The first element in the tuple is one of 'pass', 'fail', 'netural', 'softfail',
'unknown', or 'error'.  The second is the SMTP response status code: 550 for 
'fail', 450 for 'error' and 250 for all else.  The third is an explanation.

Note: SPF results alone are never sufficient to decide that a message should be
accepted.  Accept, reject, or defer decisions are a function of local reciever
policy.

The RFC 4408/7208 compliant API::

        >>> import spf
        >>> spf.check2(i='69.55.226.139',
        ...           s='terry@wayforward.net',
        ...           h='mx1.wayforward.net')
        ('pass', 'sender SPF verified')

The first element in the tuple is one of 'pass', 'fail', 'neutral', 'softfail,
'permerror', or 'temperror'.  The second is an explanation.

This package also provides two additional helper scripts; type99.py and 
spfquery.py.  The type99.py script will convert DNS TXT strings to a binary 
equivalent suitable for use in a BIND zone file.  The spfquery.py script is a
Python reimplementination of Wayne Schlitt's spfquery command line tool.

The type99.py script is called from the command line as follows:

python type99.py "v=spf1 -all" {Note: Use your desired SPF record instead.}
\# 12 0b763d73706631202d616c6c {This is the correct result for "v=spf1 -all"}

or 

python type99 - {File name}

The input file format is a standard BIND Zone file.  The type99 script will add
a Type99 record for each TXT record found in the file.  Use of DNS type 99
(type SPF) was removed from SPF in RFC 7208, so this script should be of
historical interest only.

The spfquery.py script is called with a number of possible options.  Options can
either use standard '-' prefix or be PERL style long options, '--'.  Supported
options are:

"--file" or "-file" {filename}: Read the query (or queries) from the designated 
    file.  If {filename} is '0', then query inputs are read from STDIN.

 "--ip" or "-ip" {address}: Client IP address to use for SPF check.


"--sender" or "-sender" {Mail From address}: Envelope sender from which mail was
    received.

"--helo" or "-helo" {client hostname}: HELO/EHLO name used by SMTP client.

"--local" or "-local" {local policy SPF string}: Additional SPF mechanisms to be
    checked on the basis of local policy.  Note that local policy matches are 
    not strictly SPF results.  Local policy processing is not defined in RFC 
    4408 or RFC 7208.  Result may vary among SPF implementations.

"--rcpt-to" or "rcpt-to" {rcpt-to address - if available}: Receipt to address is
    not used for actual SPF processing, but if available it can be useful for 
    logging, spf-received header construction, and providing useful rejection
    messages when messages are rejected due to SPF.

"--default-explanation" or "-default-explanation" {explanation string}: Default
    Fail explanation string to be used.

"--sanitize" or "-sanitize" and "--debug" or "-debug": These options are no-op
    in the Python implementation, but are valid inputs to provide compatibliity
    with input files developed to work with the original PERL and C spfquery
    implementations.

Overall per SPF check time limits can be controlled by passing querytime
to the spf.check2 function or when initializing a spf.query object.
It is set to 20 seconds by default based on RFC 7208.  If querytime is set to
0, then the overall time limit is disabled and the per DNS lookup limit is used
instead.  This defaults to 20 seconds and can be controlled via
spf.MAX_PER_LOOKUP_TIME.  RFC 4408 says that the overall limit MAY be used and
recommends no less than 20 seconds if it is. RFC 7208 is stronger, so a
default limit aligned to the RFC requirements is now used.

License: Python Software Foundation License

Author:
Terence Way terry@wayforward.net
http://www.wayforward.net/spf/

Maintainers:
Stuart Gathman stuart@gathman.org
Scott Kitterman scott@kitterman.com
https://pypi.org/project/pyspf/

Code is currently hosted at https://github.com/sdgathman/pyspf/
