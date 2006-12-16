#!/usr/bin/python2.4
#
# Copy Bind zonefiles to stdout, removing TYPE99 RRs and
# adding a TYPE99 RR for each TXT RR encountered.
# This can be used to maintain SPF records as TXT RRs
# in a zonefile until Bind is patched/upgraded to recognize
# the SPF RR.  After adding/changing/deleting TXT RRs,
# filtering through this script will refresh the TYPE99 RRs.
#
# BUGS: multiline TXT RRs are not supported.
# 
# $Log$
# Revision 1.4  2005/08/26 20:53:38  kitterma
# Fixed typo in type99 script
#
# Revision 1.3  2005/08/19 19:06:49  customdesigned
# use note_error method for consistent extended processing.
# Return extended result, strict result in self.perm_error
#
# Revision 1.2  2005/07/17 02:46:03  customdesigned
# Use of expand not needed.
#
# Revision 1.1  2005/07/17 02:39:42  customdesigned
# Utility to maintain TYPE99 copies of SPF TXT RRs.
#

import sys
import fileinput
import re

def dnstxt(txt):
  "Convert data into DNS TXT format (sequence of pascal strings)."
  r = []
  while txt:
    s,txt = txt[:255],txt[255:]
    r.append(chr(len(s))+s)
  return ''.join(r)
    
USAGE="""Usage:\t%s phrase
	%s - <zoneinfo
"""

if len(sys.argv) < 2:
    sys.stderr.write(USAGE % (sys.argv[0],sys.argv[0]))
    sys.exit(1)

if sys.argv[1] == '-' or len(sys.argv) > 2:
  RE_TXT = re.compile(r'^(?P<rr>.*\s)TXT\s"(?P<str>v=spf1.*)"')
  RE_TYPE99 = re.compile(r'\sTYPE99\s')
  for line in fileinput.input():
    if not RE_TYPE99.search(line):
      sys.stdout.write(line)
    m = RE_TXT.match(line)
    if m:
      phrase = dnstxt(m.group('str'))
      s = m.group('rr') + 'TYPE99 \# %i'%len(phrase)
      print s,''.join(["%02x"%ord(c) for c in phrase])
else:
  phrase = dnstxt(sys.argv[1])
  print "\# %i"%len(phrase),''.join(["%02x"%ord(c) for c in phrase])
