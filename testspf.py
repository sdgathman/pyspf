import unittest
import spf
import csv
import re
import yaml

zonedata = {}
RE_IP4 = re.compile(r'\.'.join(
	[r'(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])']*4)+'$')

def DNSLookup(name,qtype):
  try:
    #print name
    timeout = True
    for i in zonedata[name]:
      if i == 'TIMEOUT':
        if timeout:
	  raise spf.TempError,'DNS timeout'
	return
      t,v = i
      if t == qtype:
        timeout = False
      yield ((name,t),v)
  except KeyError:
    if name.startswith('error.'):
      raise spf.TempError,'DNS timeout'

spf.DNSLookup = DNSLookup

class SPFTest(object):
  def __init__(self,testid,scenario,data={}):
    self.id = testid
    self.scenario = scenario
    self.explanation = None
    self.comment = []
    for k,v in data.items():
      setattr(self,k,v)
    if type(self.comment) is str:
      self.comment = self.comment.splitlines()

def getrdata(r):
  "Unpack rdata given as list of maps to list of tuples."
  for m in r:
    try:
      for t in m.items():
        yield t
    except:
      yield m

class SPFScenario(object):
  def __init__(self,filename=None,data={}):
    self.id = None
    self.filename = filename
    self.comment = []
    self.zonedata = {}
    self.tests = {}
    if data:
      self.zonedata= dict([
        (d, list(getrdata(r))) for d,r in data['zonedata'].items()
      ])
      for t,v in data['tests'].items():
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
  "Load testcases in YAML format.  Return list of SPFTest"
  fp = open(fname,'rb')
  tests = {}
  for s in yaml.safe_load_all(fp):
    scenario = SPFScenario(fname,data=s)
    for k,v in scenario.tests.items():
      tests[k] = v
  return tests.values()

def loadBind(fname):
  "Load testcases in BIND format.  Return list of SPFTest"
  tests = {}
  scenario = SPFScenario(fname)
  comments = []
  lastdomain = None
  fp = open(fname,'rb')
  for a in csv.reader(fp,delimiter=' ',skipinitialspace=True):
    if not a:
      scenario = SPFScenario(fname)
      continue
    name = a[0].strip()
    if name.startswith('#') or name.startswith(';'):
      cmt = ' '.join(a)[1:].strip()
      comments.append(cmt)
      continue
    cmd = a[1].upper()
    if cmd == 'IN':
#example.com IN SPF "v=spf1 mx/26 exists:%{l}.%{d}.%{i}.spf.example.net -all"
      t = a[2].upper()
      if not name:
        name = lastdomain
      elif name.endswith('.'):
	name = name[:-1]
      lastdomain = name
      if t == 'MX':
	v = t,(int(a[3]),a[4].rstrip('.'))
      else:
	v = t,a[3]
      scenario.addDNS(name,v)
      if comments:
	scenario.comment += comments
	comments = []
    elif cmd == 'TEST':
      if not name:
        name = lastdomain
      else:
	lastdomain = name
      if name not in tests:
	tests[name] = test = SPFTest(name,scenario)
      else:
	test = tests[name]
      scenario.addTest(test)
      if comments:
	test.comment += comments
	comments = []
      t = a[2].lower()
      if RE_IP4.match(t):
        # fail TEST 1.2.3.4 lyme.eater@example.co.uk mail.example.net
	test.host,test.mailfrom,test.helo,test.result = a[2:6]
      elif t == 'mail-from':
        test.mailfrom = a[3]
      else:
        setattr(test,t,a[3])
  fp.close()
  return tests.values()

oldresults = { 'unknown': 'permerror', 'error': 'temperror' }

class SPFTestCase(unittest.TestCase):

  def runTests(self,tests):
    global zonedata
    passed,failed = 0,0
    for t in tests:
      zonedata = t.scenario.zonedata
      q = spf.query(i=t.host, s=t.mailfrom, h=t.helo)
      res,code,exp = q.check()
      if res in oldresults:
        res = oldresults[res]
      ok = res == t.result
      if t.explanation is not None and t.explanation != exp:
        print t.explanation,'!=',exp
        ok = False
      if ok:
	passed += 1
      else:
        print t.result,'!=',res
	failed += 1
	print "test %s in %s failed" % (t.id,t.scenario.filename)
    if failed:
      print "%d passed" % passed,"%d failed" % failed

  #def testMacro(self):
  #  self.runTests(loadBind('test/macro.dat'))

  #def testMailzone(self):
  #  self.runTests(loadBind('otest.dat'))

  def testYAML(self):
    self.runTests(loadYAML('test.yml'))

#  def testRFC(self):
#    self.runTests(loadYAML('rfc4408-tests.yml'))

def suite(): return unittest.makeSuite(SPFTestCase,'test')

if __name__ == '__main__':
  unittest.main()
