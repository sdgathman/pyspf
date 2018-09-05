#!/usr/bin/python

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2004 Business Management Systems, Inc.

# This module is free software, and you may redistribute it and/or modify
# it under the same terms as Python itself, so long as this copyright message
# and disclaimer are retained in their original form.

# Emulate the spfquery command line tool used by Wayne Schlitt's SPF test suite

# $Log$
# Revision 1.4.2.3  2011/10/27 04:44:58  kitterma
# Update spfquery.py to work with 2.6, 2.7, and 3.2:
#  - raise ... as ...
#  - print()
#
# Revision 1.4.2.2  2008/03/26 14:34:35  kitterma
# Change shebangs to #!/usr/bin/python throughout.
#
# Revision 1.4.2.1  2006/12/23 05:31:22  kitterma
# Minor updates for packaging lessons learned from Ubuntu
#
# Revision 1.4  2006/11/20 18:39:41  customdesigned
# Change license on spfquery.py.  Update README.  Move tests to test directory.
#
# Revision 1.3  2005/07/22 02:11:57  customdesigned
# Use dictionary to check for CNAME loops.  Check limit independently for
# each top level name, just like for PTR.
#
# Revision 1.2  2005/07/14 04:18:01  customdesigned
# Bring explanations and Received-SPF header into line with
# the unknown=PermErr and error=TempErr convention.
# Hope my case-sensitive mech fix doesn't clash with Scotts.
#
# Revision 1.1.1.1  2005/06/20 19:57:32  customdesigned
# Move Python SPF to its own module.
#
# Revision 1.2  2005/06/02 04:18:55  customdesigned
# Update copyright notices after reading article on /.
#
# Revision 1.1.1.1  2005/05/31 18:07:19  customdesigned
# Release 0.6.9
#
# Revision 2.3  2004/04/19 22:12:11  stuart
# Release 0.6.9
#
# Revision 2.2  2004/04/18 03:29:35  stuart
# Pass most tests except -local and -rcpt-to
#
# Revision 2.1  2004/04/08 18:41:15  stuart
# Reject numeric hello names
#
# Driver for SPF test system

import spf
import sys

from optparse import OptionParser

class PerlOptionParser(OptionParser):
    def _process_args (self, largs, rargs, values):
        """_process_args(largs : [string],
                         rargs : [string],
                         values : Values)

        Process command-line arguments and populate 'values', consuming
        options and arguments from 'rargs'.  If 'allow_interspersed_args' is
        false, stop at the first non-option argument.  If true, accumulate any
        interspersed non-option arguments in 'largs'.
        """
        while rargs:
            arg = rargs[0]
            # We handle bare "--" explicitly, and bare "-" is handled by the
            # standard arg handler since the short arg case ensures that the
            # len of the opt string is greater than 1.
            if arg == "--":
                del rargs[0]
                return
            elif arg[0:2] == "--":
                # process a single long option (possibly with value(s))
                self._process_long_opt(rargs, values)
            elif arg[:1] == "-" and len(arg) > 1:
                # process a single perl style long option
                rargs[0] = '-' + arg
                self._process_long_opt(rargs, values)
            elif self.allow_interspersed_args:
                largs.append(arg)
                del rargs[0]
            else:
                return

def format(q):
  res,code,txt = q.check()
  print(res)
  if res in ('pass','neutral','unknown'): print()
  else: print(txt)
  print('spfquery:',q.get_header_comment(res))
  print('Received-SPF:',q.get_header(res,'spfquery'))

def main(argv):
  parser = PerlOptionParser()
  parser.add_option("--file",dest="file")
  parser.add_option("--ip",dest="ip")
  parser.add_option("--sender",dest="sender")
  parser.add_option("--helo",dest="hello_name")
  parser.add_option("--local",dest="local_policy")
  parser.add_option("--rcpt-to",dest="rcpt")
  parser.add_option("--default-explanation",dest="explanation")
  parser.add_option("--sanitize",type="int",dest="sanitize")
  parser.add_option("--debug",type="int",dest="debug")
  opts,args = parser.parse_args(argv)
  if opts.ip:
    q = spf.query(opts.ip,opts.sender,opts.hello_name,local=opts.local_policy)
    if opts.explanation:
      q.set_default_explanation(opts.explanation)
    format(q)
  if opts.file:
    if opts.file == '0':
      fp = sys.stdin
    else:
      fp = open(opts.file,'r')
    for ln in fp:
      ip,sender,helo,rcpt = ln.split(None,3)
      q = spf.query(ip,sender,helo,local=opts.local_policy)
      if opts.explanation:
        q.set_default_explanation(opts.explanation)
      format(q)
    fp.close()
    
if __name__ == "__main__":
  import sys
  main(sys.argv[1:])
