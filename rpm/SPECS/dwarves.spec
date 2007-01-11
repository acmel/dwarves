%define libname libdwarves
%define libver 1

Name: dwarves
Version: 0
Release: 1
License: GPL
Summary: Dwarf Tools
Group: Base
URL: http://oops.ghostprotocols.net:81/blog
Source: pahole-%{version}.tar.bz2
BuildRequires: cmake
BuildRequires: binutils
BuildRequires: libelfutils1-devel
BuildRequires: gcc
BuildRequires: glibc-devel
BuildRequires: make
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
Set of dwarf tools

%package -n %{libname}%{libver}
Summary: DWARF processing library
Group: Libraries

%description -n %{libname}%{libver}
DWARF processing library

%package -n %{libname}-devel
Summary: DWARF processing library development files
Group: Development

%description -n %{libname}-devel
DWARF processing library development files

%prep
%setup -q -c -n %{name}-%{version}

%build
cmake .
make

%install
rm -Rf %{buildroot}
mkdir -p %{buildroot}{%{_libdir},%{_bindir},%{_includedir}}

make DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%files
%defattr(0644,root,root,0755)
%doc README.ctracer
%defattr(0755,root,root,0755)
%{_bindir}/codiff
%{_bindir}/ctracer
%{_bindir}/dtagnames
%{_bindir}/pahole
%{_bindir}/pfunct
%{_bindir}/prefcnt

%files -n %{libname}%{libver}
%defattr(0644,root,root,0755)
%{_libdir}/%{libname}.so.*

%files -n %{libname}-devel
%defattr(0644,root,root,0755)
%{_includedir}/dwarves.h
%{_libdir}/%{libname}.so

%changelog
* Wed Jan 11 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
- package created
