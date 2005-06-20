#!/usr/bin/python2.3

# Convert a MS Caller-ID entry (XML) to a SPF entry
#
# (c) 2004 by Ernesto Baschny
# (c) 2004 Python version by Stuart Gathman
#
# Date: 2004-02-25
# Version: 1.0
#
# Usage:
#  ./cid2spf.pl "<ep xmlns='http://ms.net/1'>...</ep>"
#
# Note that the 'include' directives will also have to be checked and
# "translated". Future versions of this script might be able to get a
# domain name as an argument and "crawl" the DNS for the necessary
# information.
#
# A complete reverse translation (SPF -> CID) might be impossible, since
# there are no way to handle:
# - PTR and EXISTS mechanism 
# - MX mechanism with an different domain as argument
# - macros
# 
# References:
# http://www.microsoft.com/mscorp/twc/privacy/spam_callerid.mspx
# http://spf.pobox.com/
#
# Known bugs:
# - Currently it won't handle the exclusions provided in the A and R
#   tags (prefix '!'). They will show up "as-is" in the SPF record
# - I really haven't read the MS-CID specs in-depth, so there are probably
#   other bugs too :)
#
# Ernesto Baschny <ernst@baschny.de>
#

import xml.sax
import spf

# -------------------------------------------------------------------------
class CIDParser(xml.sax.ContentHandler):
  "Convert a MS Caller-ID entry (XML) to a SPF entry"

  def __init__(self,q=None):
    self.spf = []
    self.action = '-all'
    self.has_servers = None
    self.spf_entry = None
    if q:
      self.spf_query = q
    else:
      self.spf_query = spf.query(i='127.0.0.1', s='localhost', h='unknown')

  def startElement(self,tag,attr):
      if tag == 'm':
	if self.has_servers != None and not self.has_servers:
	  raise ValueError(
    "Declared <noMailServers\> and later <m>, this CID entry is not valid."
	  )
	self.has_servers = True
      elif tag == 'noMailServers':
	if self.has_servers:
	  raise ValueError(
    "Declared <m> and later <noMailServers\>, this CID entry is not valid."
	  )
	self.has_servers = False
      elif tag == 'ep':
	if attr.has_key('testing') and attr.getValue('testing') == 'true':
	  # A CID with 'testing' found:
	  # From the MS-specs:
	  #  "Documents in which such attribute is present with a true
	  #  value SHOULD be entirely ignored (one should act as if the
	  #  document were absent)"
	  # From the SPF-specs:
	  #  "Neutral (?): The SPF client MUST proceed as if a domain did
	  #  not publish SPF data."
	  # So we set SPF action to "neutral":
	  self.action = '?all'
      elif tag == 'mx':
	  # The empty MX-tag, same as SPF's MX-mechanism
	  self.spf.append('mx')
      self.tag = tag

  def characters(self,text):
	tag = self.tag
	# Remove starting and trailing spaces from text:
	text = text.strip()

	if tag == 'a' or tag == 'r':
	    # The A and R tags from MS-CID are both handled by the 
	    # ipv4/6-mechanisms from SPF:
	    if text.find(':') < 0:
	      mechanism = 'ip4'
	    else:
	      mechanism = 'ip6'
	    self.spf.append(mechanism + ':' + text)
	elif tag == 'indirect':
	    # MS-CID's indirect is "sort of" the include from SPF:
	    # Not really true, because the <indirect> tag from MS-CID also 
	    # provides a fallback in case the included domain doesn't provide
	    # _ep-records: The inbound MX-servers of the included domains
	    # are added to the list of allowed outgoing mailservers for the
	    # domain that declared the _ep-record with the <indirect> tag.
	    # In SPF you would use the 'mx:domain' to handle this, but this
	    # wouldn't depend on referred domain having or not SPF-records.
	    cid_xml = self.cid_txt(text)
	    if cid_xml:
	      p = CIDParser()
	      xml.sax.parseString(cid_xml,p)
	      if p.has_servers != False:
		self.spf += p.spf
	    else:
	      self.spf.append('mx:' + text)

  def cid_txt(self,domain):
    q = self.spf_query
    domain='_ep.' + domain
    a = q.dns_txt(domain)
    if not a: return None
    if a[0].lower().startswith('<ep ') and a[-1].lower().endswith('</ep>'):
      return ''.join(a)
    return None

  def endElement(self,tag):
      if tag == 'ep':
	# This is the end... assemble what we've got
	spf_entry = ['v=spf1']
	if self.has_servers != False:
	  spf_entry += self.spf
	spf_entry.append(self.action)
	self.spf_entry = ' '.join(spf_entry)

  def spf_txt(self,cid_xml):
    if not cid_xml.startswith('<'):
      cid_xml = self.cid_txt(cid_xml)
      if not cid_xml: return None
    # Parse the beast. Any XML-problem will be reported by xlm.sax
    self.spf_entry = None
    xml.sax.parseString(cid_xml,self)
    return self.spf_entry

if __name__ == '__main__':
  import sys
  if len(sys.argv) < 2:
    print >>sys.stderr, \
      """Usage: %s "<ep xmlns='http://ms.net/1'>...</ep>" """ % sys.argv[0]
    sys.exit(1)

  cid_xml = sys.argv[1]

  p = CIDParser()
  print p.spf_txt(cid_xml)
