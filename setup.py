#!/usr/bin/env python

from distutils.core import setup

DESC = """SPF (Sender Policy Framework) implemented in Python."""

setup(name='pyspf',
      version='1.7',
      description=DESC,
      author='Terence Way',
      author_email='terry@wayforward.net',
      maintainer="Stuart D. Gathman",
      maintainer_email="stuart@bmsi.com",
      url='http://pymilter.sourceforge.net/',
      license='Python Software Foundation License',
      py_modules=['spf'])
