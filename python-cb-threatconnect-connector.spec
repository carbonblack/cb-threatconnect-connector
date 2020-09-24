%define name python-cb-threatconnect-connector
%define version 2.1.0
%define unmangled_version 2.1.0
%define release 1
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
%define _build_id_links none


Summary: Carbon Black Enterprise Response ThreatConnect Bridge
Name: %{name}
Version: %{version}
Release: %{release}%{?dist}
Source0: %{name}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Carbon Black
Url: http://www.carbonblack.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

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

chmod -R u+r /usr/share/cb/integrations/threatconnect/bin
chmod -R g+r /usr/share/cb/integrations/threatconnect/bin
chmod -R o+r /usr/share/cb/integrations/threatconnect/bin
chmod -R u+r /usr/share/cb/integrations/threatconnect/bin/cbapi/
chmod -R g+r /usr/share/cb/integrations/threatconnect/bin/cbapi/
chmod -R o+r /usr/share/cb/integrations/threatconnect/bin/cbapi/

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
