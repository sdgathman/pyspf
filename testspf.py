import unittest
import spf

zonedata = {
  'premierpc.co.uk':
  [('SPF','v=spf1 mx/26 exists:%{l}.%{d}.%{i}.spf.uksubnet.net -all')],
  'mailing.gdi.ws':
  [('CNAME','mailing.gdi.ws')]
}

def DNSLookup(name,qtype):
  try:
    return [((name,t),v) for t,v in zonedata[name]]
  except KeyError:
    return []

spf.DNSLookup = DNSLookup

class SPFTestCase(unittest.TestCase):

  # test mime parameter parsing
  def testMacro(self):
    i, s, h = ('1.2.3.4','lyndon.eaton@premierpc.co.uk','mail.uksubnet.net')
    q = spf.query(i=i, s=s, h=h)
    self.failUnless(q.check()[0] == 'fail')

  def testCnameLoop(self):
    i, s, h = '66.150.186.79','chuckvsr@mailing.gdi.ws','master.gdi.ws'
    q = spf.query(i=i, s=s, h=h)
    self.failUnless(q.check()[0] == 'none')
    self.failUnless(q.best_guess()[0] == 'neutral')

def suite(): return unittest.makeSuite(SPFTestCase,'test')

if __name__ == '__main__':
  unittest.main()
