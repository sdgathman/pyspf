import unittest
import spf

zonedata = {
  'premierpc.co.uk':
  [('SPF','v=spf1 mx/26 exists:%{l}.%{d}.%{i}.spf.uksubnet.net -all')],
  'mailing.gdi.ws':
  [('CNAME','mailing.gdi.ws')],
  'loop0.example.com':
  [('CNAME','loop1.example.com')],
  'loop1.example.com':
  [('CNAME','loop2.example.com')],
  'loop2.example.com':
  [('CNAME','loop3.example.com')],
  'loop3.example.com':
  [('CNAME','loop4.example.com')],
  'loop4.example.com':
  [('CNAME','loop5.example.com')],
  'loop5.example.com':
  [('CNAME','loop6.example.com')],
  'loop6.example.com':
  [('CNAME','loop7.example.com')],
  'loop7.example.com':
  [('CNAME','loop8.example.com')],
  'loop8.example.com':
  [('CNAME','loop9.example.com')],
  'loop9.example.com':
  [('CNAME','loop10.example.com')],
  'loop10.example.com':
  [('CNAME','loop0.example.com')],
  'a.com':
  [('SPF','v=spf1 a mx include:b.com')],
  'b.com':
  [('SPF','v=spf1 a mx include:a.com')],
}

def DNSLookup(name,qtype):
  try:
    return [((name,t),v) for t,v in zonedata[name]]
  except KeyError:
    if name.startswith('error.'):
      raise spf.TempError,'DNS timeout'
    return []

spf.DNSLookup = DNSLookup

class SPFTestCase(unittest.TestCase):

  # test mime parameter parsing
  def testMacro(self):
    i, s, h = ('1.2.3.4','lyndon.eaton@premierpc.co.uk','mail.uksubnet.net')
    q = spf.query(i=i, s=s, h=h)
    self.assertEqual(q.check()[0],'fail')

  def testCnameLoop(self):
    i, s, h = '66.150.186.79','chuckvsr@mailing.gdi.ws','master.gdi.ws'
    q = spf.query(i=i, s=s, h=h)
    self.assertEqual(q.check()[0],'permerror')
    i, s, h = '66.150.186.79','chuckvsr@loop0.example.com','master.gdi.ws'
    q = spf.query(i=i, s=s, h=h)
    self.assertEqual(q.check()[0],'permerror')	# if too many == PermErr
    #self.assertEqual(q.check()[0],'none')	# if too many == NX_DOMAIN

  def testIncludeLoop(self):
    i, s, h = '66.150.186.79','chuckvsr@a.com','mail.a.com'
    q = spf.query(i=i, s=s, h=h)
    self.assertEqual(q.check()[0],'permerror')

  def testDNSError(self):
    i, s, h = ('1.2.3.4','lyndon.eaton@error.co.uk','mail.uksubnet.net')
    q = spf.query(i=i, s=s, h=h)
    self.assertEqual(q.check()[0],'temperror')

def suite(): return unittest.makeSuite(SPFTestCase,'test')

if __name__ == '__main__':
  unittest.main()
