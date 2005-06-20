import unittest
import spf

class SPFTestCase(unittest.TestCase):

  # test mime parameter parsing
  def testMacro(self):
    spf_rec = 'v=spf1 mx/26 exists:%{l}.%{d}.%{i}.spf.uksubnet.net -all'
    i, s, h = ('1.2.3.4','lyndon.eaton@premierpc.co.uk','mail.uksubnet.net')
    q = spf.query(i=i, s=s, h=h)
    print q.check(spf_rec)

  def testCnameLoop(self):
    spf_rec = 'v=spf1 a/24 mx/24 ptr'
    i, s, h = '66.150.186.79','chuckvsr@mailing.gdi.ws','master.gdi.ws'
    q = spf.query(i=i, s=s, h=h)
    print q.check(spf_rec)

def suite(): return unittest.makeSuite(SPFTestCase,'test')

if __name__ == '__main__':
  unittest.main()
