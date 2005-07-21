#!/usr/bin/env python

from distutils.core import setup

DESC = """SPF (Sender Permitted From) Spam block implemented in Python."""

setup(name='pyspf',
      version='1.6',
      description=DESC,
      author='Terence Way',
      author_email='terry@wayforward.net',
      url='http://www.wayforward.net/spf/',
      license='Python Software Foundation License',
      py_modules=['spf'])
