"""Pure Python IP6 parsing and formatting

Copyright (c) 2006 Stuart Gathman <stuart@bmsi.com>

This module is free software, and you may redistribute it and/or modify
it under the same terms as Python itself, so long as this copyright message
and disclaimer are retained in their original form.
"""
import struct
#from spf import RE_IP4 
import re
PAT_IP4 = r'\.'.join([r'(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])']*4)
RE_IP4 = re.compile(PAT_IP4+'$')

def inet_ntop(s):
  """
  Convert ip6 address to standard hex notation.

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
    ip4 = '.'.join([str(i) for i in struct.unpack("!BBBB",s[12:])])
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
  """
  Convert ip6 standard hex notation to ip6 address.

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
