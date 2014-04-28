# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2006 Business Management Systems, Inc.

# This module is free software, and you may redistribute it and/or modify
# it under the same terms as Python itself, so long as this copyright message
# and disclaimer are retained in their original form.

# Run SPF test cases in the YAML format specified by the SPF council.

import unittest
import socket
import sys
import spf
import re
try:
  import yaml
except:
  print("yaml can be found at http://pyyaml.org/")
  print("Tested with PYYAML 3.04")
  raise

zonedata = {}
RE_IP4 = re.compile(r'\.'.join(
    [r'(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])']*4)+'$')

def DNSLookup(name,qtype,strict=True,timeout=None):
  try:
    #print name,qtype
    timeout = True

    # emulate pydns-2.3.0 label processing
    a = []
    for label in name.split('.'):
      if label:
        if len(label) > 63:
          raise spf.TempError('DNS label too long')
        a.append(label)
    name = '.'.join(a)

    for i in zonedata[name.lower()]:
      if i == 'TIMEOUT':
        if timeout:
          raise spf.TempError('DNS timeout')
        return
      t,v = i
      if t == qtype:
        timeout = False
      if v == 'TIMEOUT':
        if t == qtype:
          raise spf.TempError('DNS timeout')
        continue
      # keep test zonedata human readable, but translate to simulate pydns
      if t == 'AAAA':
        v = bytes(socket.inet_pton(socket.AF_INET6,v))
      elif t in ('TXT','SPF'):
        v = tuple([s.encode('utf-8') for s in v])
      yield ((name,t),v)
  except KeyError:
    if name.startswith('error.'):
      raise spf.TempError('DNS timeout')

spf.DNSLookup = DNSLookup

class SPFTest(object):
  def __init__(self,testid,scenario,data={}):
    self.id = testid
    self.scenario = scenario
    self.explanation = None
    self.spec = None
    self.header = None
    self.strict = True
    self.receiver = None
    self.comment = []
    if 'result' not in data:
      print(testid,'missing result')
    for k,v in list(data.items()):
      setattr(self,k,v)
    if type(self.comment) is str:
      self.comment = self.comment.splitlines()

def getrdata(r):
  "Unpack rdata given as list of maps to list of tuples."
  txt = []        # generated TXT records
  gen = True
  for m in r:
    try:
      for i in list(m.items()):
        t,v = i
        if t == 'TXT':
          gen = False # no generated TXT records
        elif t == 'SPF' and gen:
          txt.append(('TXT',v))
        if v != 'NONE':
          if t in ('TXT','SPF') and type(v) == str:
            yield (t,(v,))
          else:
            yield i
    except:
      yield m
  if gen:
    for i in txt:
      yield i

def loadZone(data):
  return dict([
    (d.lower(), list(getrdata(r))) for d,r in list(data['zonedata'].items())
  ])

class SPFScenario(object):
  def __init__(self,filename=None,data={}):
    self.id = None
    self.filename = filename
    self.comment = []
    self.zonedata = {}
    self.tests = {}
    if data:
      self.zonedata= loadZone(data)
      #print self.zonedata
      for t,v in list(data['tests'].items()):
        self.tests[t] = SPFTest(t,self,v)
      if 'id' in data:
        self.id = data['id']
      if 'comment' in data:
        self.comment = data['comment'].splitlines()

  def addDNS(self,name,val):
    self.zonedata.setdefault(name,[]).append(val)

  def addTest(self,test):
    self.tests[test.id] = test

def loadYAML(fname):
  "Load testcases in YAML format.  Return map of SPFTests by name."
  fp = open(fname,'rb')
  try:
    tests = {}
    for s in yaml.safe_load_all(fp):
      scenario = SPFScenario(fname,data=s)
      for k,v in list(scenario.tests.items()):
        tests[k] = v
    return tests
  finally: fp.close()

oldresults = { 'unknown': 'permerror', 'error': 'temperror' }

verbose = 0
warnings = []

class SPFTestCase(unittest.TestCase):

  def __init__(self,t):
    unittest.TestCase.__init__(self)
    self._spftest = t
    self._testMethodName = 'runTest'
    self._testMethodDoc = t.spec

  def id(self):
    t = self._spftest
    return t.id + ' in ' + t.scenario.filename

  def setUp(self):
    global zonedata
    self.savezonedata = zonedata

  def tearDown(self):
    global zonedata
    zonedata = self.savezonedata

  def warn(self,msg):
    global warnings
    warnings.append(msg)

  def runTest(self):
    global zonedata
    t = self._spftest
    zonedata = t.scenario.zonedata
    q = spf.query(i=t.host, s=t.mailfrom, h=t.helo, strict=t.strict)
    q.set_default_explanation('DEFAULT')
    res,code,exp = q.check()
    if res in oldresults:
      res = oldresults[res]
    ok = True
    msg = ''
    if res != t.result and res not in t.result:
      if verbose: msg += ' '.join((t.result,'!=',res))+'\n'
      ok = False
    elif res != t.result and res != t.result[0]:
      self.warn("WARN: %s in %s, %s: %s preferred to %s" % (
	  t.id,t.scenario.filename,t.spec,t.result[0],res))
    if t.explanation is not None and t.explanation != exp:
      if verbose: msg += ' '.join((t.explanation,'!=',exp))+'\n'
      ok = False
    if t.header:
      self.assertEqual(t.header,q.get_header(res,receiver=t.receiver))
    if not ok:
      if verbose and not t.explanation: msg += exp+'\n'
      if verbose > 1: msg += t.scenario.zonedata
      self.fail(msg+"%s in %s failed, %s" % (t.id,t.scenario.filename,t.spec))

class SPFTestCases(unittest.TestCase):

  def testInvalidSPF(self):
    i, s, h = '1.2.3.4','sender@domain','helo'
    q = spf.query(i=i, s=s, h=h, receiver='localhost', strict=False)
    res,code,txt = q.check('v=spf1...')
    self.assertEquals('none',res)
    q = spf.query(i=i, s=s, h=h, receiver='localhost', strict=2)
    res,code,txt = q.check('v=spf1...')
    self.assertEquals('ambiguous',res)

def makeSuite(filename):
  suite = unittest.TestSuite()
  for t in loadYAML(filename).values():
    suite.addTest(SPFTestCase(t))
  return suite

def suite(): 
  suite = unittest.makeSuite(SPFTestCases,'test')
  suite.addTest(makeSuite('test.yml'))
  suite.addTest(makeSuite('rfc7208-tests.yml'))
  suite.addTest(makeSuite('rfc4408-tests.yml'))
  import doctest
  suite.addTest(doctest.DocTestSuite(spf))
  return suite

if __name__ == '__main__':
  tc = None
  for i in sys.argv[1:]:
    if i == '-v':
      verbose += 1
      continue
    # a specific test selected by id from YAML files
    if not tc:
      tc = unittest.TestSuite()
      t0 = loadYAML('rfc7208-tests.yml')
      t1 = loadYAML('rfc4408-tests.yml')
      t2 = loadYAML('test.yml')
    if i in t0:
      tc.addTest(SPFTestCase(t0[i]))
    if i in t1:
      tc.addTest(SPFTestCase(t1[i]))
    if i in t2:
      tc.addTest(SPFTestCase(t2[i]))
  if not tc:
    # load zonedata for doctests
    fp = open('doctest.yml','rb')
    try:
      zonedata = loadZone(next(yaml.safe_load_all(fp)))
    finally: fp.close()
    tc = suite()	# all tests, including doctests
  runner = unittest.TextTestRunner()
  res = runner.run(tc)
  for s in warnings:
    print(s)
  if not res.wasSuccessful():
    sys.exit(1)
