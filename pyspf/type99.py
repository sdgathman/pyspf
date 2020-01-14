#!/usr/bin/python
"""Type 99 (SPF) DNS conversion script.

Copyright (c) 2005,2006 Stuart Gathman <stuart@bmsi.com>
Portions Copyright (c) 2007 Scott Kitterman <scott@kitterman.com>
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
    http://www.openspf.net/"""
    
# Copy Bind zonefiles to stdout, removing TYPE99 RRs and
# adding a TYPE99 RR for each TXT RR encountered.
# This can be used to maintain SPF records as TXT RRs
# in a zonefile until Bind is patched/upgraded to recognize
# the SPF RR.  After adding/changing/deleting TXT RRs,
# filtering through this script will refresh the TYPE99 RRs.
# 
# $Log$
# Revision 1.4.4.4  2011/10/27 04:44:58  kitterma
# Update type99.py to work with 2.6, 2.7, and 3.2:
#  - raise ... as ...
#  - Add filter to stdin processing
#  - Modernize output print to use format to get consistent python/python3 output
#
# Revision 1.4.4.3  2008/03/26 19:01:07  kitterma
# Capture Type99.py improvements from trunk.  SF #1257140
#
# Revision 1.9  2008/03/26 18:56:42  kitterma
# Update Type99 script to correctly parse multi-string single line TXT records.
# Multi-string/multi-line still fails.
#
# Revision 1.8  2007/01/26 05:06:41  customdesigned
# Tweaks for epydoc.
# Design for test in type99.py, test cases.
# Null byte test case for quote_value.
#
# Revision 1.7  2007/01/25 21:59:29  kitterma
# Update comments to match bug fix.  Include copyright statements.  Update sheband.
#
# Revision 1.6  2007/01/25 21:51:45  kitterma
# Fix type99 script for multi-line support (Fixes sourceforge #1257140)
#
# Revision 1.5  2006/12/16 20:45:23  customdesigned
# Move dns drivers to package directory.
#
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

RE_TXT = re.compile(r'^(?P<rr>.*\s)TXT\s"(?P<str>v=spf1.*)"(?P<eol>.*)',
	re.DOTALL)
RE_TYPE99 = re.compile(r'\sTYPE99\s')

def filter(fin):
  for line in fin:
    if not RE_TYPE99.search(line):
      yield line
    m = RE_TXT.match(line)
    if not m:
        left = line.split('(')
        try:
            right = left[1].split(')')
        except IndexError as errmsg:
            right = left[0].split(')')
            if len(left) == 2:
                right = left[1]
            else:
                left = line.split('(')
                right = left[0]
        middlelist = right[0].split('"')
        middle = ''
        for fragment in middlelist:
            if fragment != ' ':
                middle = middle + fragment
        line = left[0] + '"' + middle + '"'
        m = RE_TXT.match(line)
    if m:
      phrase = dnstxt(m.group('str'))
      dns_string = ''
      list = m.group('str')
      for st in list:
        dns_string += st
      phrase = dnstxt(dns_string)
      s = m.group('rr') + 'TYPE99 \# %i '%len(phrase)
      yield s+''.join(["%02x"%ord(c) for c in phrase])+m.group('eol')
    
USAGE="""Usage:\t%s phrase
	%s - <zoneinfo
"""

if __name__ == '__main__':
  if len(sys.argv) < 2:
      sys.stderr.write(USAGE % (sys.argv[0],sys.argv[0]))
      sys.exit(1)

  if sys.argv[1] == '-':
      sys.stdout.writelines(list(filter(fileinput.input())))
  else:
    dns_string = ''
    list = sys.argv[1:]
    for st in list:
      dns_string += st
    phrase = dnstxt(dns_string)
    print("\# {0} {1}".format(len(phrase), ''.join(["%02x"%ord(c) for c in phrase])))
