%define __python python2.6
%define pythonbase python26
%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           %{pythonbase}-pyspf
Version:        2.0.7
Release:        1
Summary:        Python module and programs for SPF (Sender Policy Framework).

Group:          Development/Languages
License:        Python Software Foundation License
URL:            http://sourceforge.net/forum/forum.php?forum_id=596908
Source0:        pyspf-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildArch:      noarch
#BuildRequires:  python-setuptools
Requires:       %{pythonbase}-pydns, %{pythonbase} >= 2.6

%description
SPF does email sender validation.  For more information about SPF,
please see http://openspf.net

This SPF client is intended to be installed on the border MTA, checking
if incoming SMTP clients are permitted to send mail.  The SPF check
should be done during the MAIL FROM:<...> command.

%define namewithoutpythonprefix %(echo %{name} | sed 's/^%{pythonbase}-//')
%prep
%setup -q -n %{namewithoutpythonprefix}-%{version}

%build
%{__python} setup.py build

%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT
mv $RPM_BUILD_ROOT/usr/bin/type99.py $RPM_BUILD_ROOT/usr/bin/type99
mv $RPM_BUILD_ROOT/usr/bin/spfquery.py $RPM_BUILD_ROOT/usr/bin/spfquery
rm -f $RPM_BUILD_ROOT/usr/bin/*.py{o,c}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc CHANGELOG PKG-INFO README test
%{python_sitelib}/spf.py*
/usr/bin/type99
/usr/bin/spfquery
/usr/lib/python2.6/site-packages/pyspf-2.0.6-py2.6.egg-info

%changelog
* Fri Feb 03 2012 Stuart Gathman <stuart@bmsi.com> 2.0.7-1
- fix CNAME chain duplicating TXT records
- local test cases for CNAME chains
- python3 compatibility changes e.g. print a -> print(a)
- check for 7-bit ascii on TXT and SPF records
- Use openspf.net for SPF web site instead of openspf.org
- Support Authentication-Results header field
- Support overall DNS timeout

* Thu Oct 27 2011 Stuart Gathman <stuart@bmsi.com> 2.0.6-2
- Python3 port (still requires 2to3 on spf.py)
- Ensure Temperror for all DNS rcodes other than 0 and 3 per RFC 4408
- Parse Received-SPF header
- Report CIDR error only for valid mechanism
- Handle invalid SPF record on command line
- Add timeout to check2
- Check for non-ascii policy

* Wed Mar 03 2011 Stuart Gathman <stuart@bmsi.com> 2.0.6-1
- Python-2.6
- parse_header method

* Wed Apr 02 2008 Stuart Gathman <stuart@bmsi.com> 2.0.5-1
- Add timeout parameter to query ctor and DNSLookup
- Patch from Scott Kitterman to retry truncated results with TCP unless harsh
- Validate DNS labels
- Reflect decision on empty-exp errata

* Wed Jul 25 2007 Stuart Gathman <stuart@bmsi.com> 2.0.4-1
- Correct unofficial 'best guess' processing.
- PTR validation processing cleanup
- Improved detection of exp= errors
- Keyword args for get_header, minor fixes
* Mon Jan 15 2007 Stuart Gathman <stuart@bmsi.com> 2.0.3-1
- pyspf requires pydns, python-pyspf requires python-pydns
- Record matching mechanism and add to Received-SPF header.
- Test for RFC4408 6.2/4, and fix spf.py to comply.
- Test for type SPF (type 99) by default in harsh mode only.
- Permerror for more than one exp or redirect modifier.
- Parse op= modifier
* Sat Dec 30 2006 Stuart Gathman <stuart@bmsi.com> 2.0.2-1
- Update openspf URLs
- Update Readme to better describe available pyspf interfaces
- Add basic description of type99.py and spfquery.py scripts
- Add usage instructions for type99.py DNS RR type conversion script
- Add spfquery.py usage instructions
- Incorporate downstream feedback from Debian packager
- Fix key-value quoting in get_header
* Fri Dec 08 2006 Stuart Gathman <stuart@bmsi.com> 2.0.1-1
- Prevent cache poisoning attack
- Prevent malformed RR attack
- Update license on a few files we missed last time
* Mon Nov 20 2006 Stuart Gathman <stuart@bmsi.com> 2.0-1
- Completed RFC 4408 compliance
- Added spf.check2 for RFC 4408 compatible result codes
- Full IP6 support
- Fedora Core compatible RPM spec file
- Update README, licenses
* Wed Sep 26 2006 Stuart Gathman <stuart@bmsi.com> 1.8-1
- YAML test suite syntax
- trailing dot support (RFC4408 8.1)
* Tue Aug 29 2006 Sean Reifschneider <jafo@tummy.com> 1.7-1
- Initial RPM spec file.
