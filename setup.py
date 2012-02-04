#!/usr/bin/python

from distutils.core import setup
import sys

DESC = """SPF (Sender Policy Framework) implemented in Python."""

setup(name='pyspf',
      version='2.0.7',
      description=DESC,
      author='Terence Way',
      author_email='terry@wayforward.net',
      maintainer="Stuart D. Gathman",
      maintainer_email="stuart@bmsi.com",
      url='http://pymilter.sourceforge.net/',
      license='Python Software Foundation License',
      py_modules=['spf'],
      keywords = ['spf','email','forgery'],
      scripts = ['type99.py','spfquery.py'],
      classifiers = [
	'Development Status :: 5 - Production/Stable',
	'Environment :: No Input/Output (Daemon)',
	'Intended Audience :: Developers',
	'License :: OSI Approved :: Python Software Foundation License',
	'Natural Language :: English',
	'Operating System :: OS Independent',
	'Programming Language :: Python',
	'Topic :: Communications :: Email :: Mail Transport Agents',
	'Topic :: Communications :: Email :: Filters',
	'Topic :: Internet :: Name Service (DNS)',
	'Topic :: Software Development :: Libraries :: Python Modules'
      ]
)

if sys.version_info < (2, 6):
    raise Exception("pyspf 2.0.6 and later requires at least python2.6.")
