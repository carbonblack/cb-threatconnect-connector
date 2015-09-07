%define name python-cb-threatconnect-bridge
%define version 1.2
%define unmangled_version 1.2
%define release 1
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Carbon Black ThreatConnect Bridge
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Bit9
Url: http://www.bit9.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
pyinstaller carbonblack_threatconnect_bridge.spec

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%post
#!/bin/sh

chkconfig --add cb-threatconnect-bridge
chkconfig --level 345 cb-threatconnect-bridge on

# not auto-starting because conf needs to be updated
#/etc/init.d/cb-threatconnect-bridge start


%preun
#!/bin/sh

/etc/init.d/cb-threatconnect-bridge stop

chkconfig --del cb-threatconnect-bridge


%files -f INSTALLED_FILES
%defattr(-,root,root)
