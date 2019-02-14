me python-cb-threatconnect-connector
%define version 2.0
%define unmangled_version 2.0 
%define release 0 
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Carbon Black threatconnect Feed 
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: Commercial
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Carbon Black <support@carbonblack.com>
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
    chkconfig --del cb-threatconnect-connector
fi


%files -f INSTALLED_FILES
%defattr(-,root,root)
