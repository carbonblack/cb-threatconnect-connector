%define name python-cb-threatconnect-connector
%define version 2.1.1
%define unmangled_version 2.1.1
%define release 1
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
%define _build_id_links none


%define bare_version 2.1.1
%define build_timestamp %(date +%%y%%m%%d.%%H%%m%%S)

# If release_pkg is defined and has the value of 1, use a plain version string;
# otherwise, use the version string with a timestamp appended.
#
# if not otherwise defined (we do so on the rpmbuild command-line), release_pkg
# defaults to 0.
#
# see https://backreference.org/2011/09/17/some-tips-on-rpm-conditional-macros/
%if 0%{?release_pkg:1}
%if "%{release_pkg}" == "1"
%define decorated_version %{bare_version}
%else
%define decorated_version %{bare_version}.%{build_timestamp}
%endif
%endif

%define release 1


Summary: Carbon Black Enterprise Response ThreatConnect Bridge
Name: %{name}
Version: %{decorated_version}
Release: %{release}%{?dist}
Source0: %{name}-%{bare_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{decorated_version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: VMware Carbon Black
Url: http://www.carbonblack.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{bare_version}

%build
pyinstaller cb-threatconnect-connector.spec

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%pre
if [ -f "/etc/cb/integrations/threatconnect/connector.conf" ]; then
    cp /etc/cb/integrations/threatconnect/connector.conf /tmp/__bridge.conf.backup
fi

if [ -f "/usr/share/cb/integrations/cb-threatconnect-connector/cacert.pem" ]; then
    cp /usr/share/cb/integrations/cb-threatconnect-connector/cacert.pem /tmp/__cacert.pem.backup
fi

if [ -f "/etc/cb/integrations/threatconnect/cacert.pem" ]; then
    cp /etc/cb/integrations/threatconnect/cacert.pem /tmp/__cacert.pem.backup
fi

%post
if [ -f "/tmp/__bridge.conf.backup" ]; then
    mv /tmp/__bridge.conf.backup /etc/cb/integrations/threatconnect/connector.conf
fi
if [ -f "/tmp/_cacert.pem.backup" ]; then
    mv /tmp/__cacert.pem.backup /usr/share/cb/integrations/cb-threatconnect-connector/cacert.pem 
fi

chmod -R u+r /usr/share/cb/integrations/cb-threatconnect-connector/bin
chmod -R g+r /usr/share/cb/integrations/cb-threatconnect-connector/bin
chmod -R o+r /usr/share/cb/integrations/cb-threatconnect-connector/bin
chmod -R u+r /usr/share/cb/integrations/cb-threatconnect-connector/bin/cbapi/
chmod -R g+r /usr/share/cb/integrations/cb-threatconnect-connector/bin/cbapi/
chmod -R o+r /usr/share/cb/integrations/cb-threatconnect-connector/bin/cbapi/

%posttrans
chkconfig --add cb-threatconnect-connector
chkconfig --level 345 cb-threatconnect-connector on

# not auto-starting because conf needs to be updated
#/etc/init.d/cb-threatconnect-connector start

%preun
/etc/init.d/cb-threatconnect-connector stop

# only delete the chkconfig entry when we uninstall for the last time,
# not on upgrades
if [ "X$1" = "X0" ]
then
    echo "deleting threatconnect chkconfig entry on uninstall"
    chkconfig --del cb-threatconnect-connector
fi


%files -f INSTALLED_FILES
%defattr(-,root,root)
