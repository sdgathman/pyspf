%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           python-pyspf
Version:        2.0.2
Release:        1%{?dist}
Summary:        Python module and programs for SPF (Sender Policy Framework).

Group:          Development/Languages
License:        Python Software Foundation License
URL:            http://sourceforge.net/forum/forum.php?forum_id=596908
Source0:        pyspf-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildArch:      noarch
#BuildRequires:  python-setuptools
Requires:       python-pydns

%description
SPF does email sender validation.  For more information about SPF,
please see http://openspf.org

This SPF client is intended to be installed on the border MTA, checking
if incoming SMTP clients are permitted to send mail.  The SPF check
should be done during the MAIL FROM:<...> command.

%define namewithoutpythonprefix %(echo %{name} | sed 's/^python-//')
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

%changelog
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
* Wed Jul 26 2006 Stuart Gathman <stuart@bmsi.com> 1.8-1
- YAML test suite syntax
- trailing dot support (RFC4408 8.1)
* Tue Aug 29 2006 Sean Reifschneider <jafo@tummy.com> 1.7-1
- Initial RPM spec file.
