Summary: ndff - nDPI for fluentd
Name: ndff
Version: 0.0.2
Release: 1
Group: DeNA-Security
Vendor: DeNA Security Dept
License: GPL
Source0: ndff-%{version}.tar.gz
Source1: ndffd.in
Source2: ndff.sysconfig
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot
BuildRequires: autoconf,automake,libtool,pkgconfig

%description
ndff package

%prep
%setup -q

%build
#./autogen.sh
%configure
make

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall

mkdir -p $RPM_BUILD_ROOT%{_initrddir}
install -m 755 %{SOURCE1} $RPM_BUILD_ROOT%{_initrddir}/ndffd
mkdir -p  $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
install -m 644 %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/ndff

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%{_bindir}/*
%config %{_initrddir}/*
%config %{_sysconfdir}/sysconfig/*

%changelog
* Sun Mar 13 2016 put.a.feud.pike011235@gmail.com
- Initial package

