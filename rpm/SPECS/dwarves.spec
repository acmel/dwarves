%define libname libdwarves
%define libver 1

Name: dwarves
Version: 0
Release: 6
License: GPL
Summary: Dwarf Tools
Group: Base
URL: http://oops.ghostprotocols.net:81/blog
Source: pahole-%{version}.tar.bz2
BuildRequires: cmake
BuildRequires: binutils
BuildRequires: elfutils-devel
BuildRequires: gcc
BuildRequires: glibc-devel
BuildRequires: make
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
dwarves is a set of tools that use the DWARF debugging information inserted in
ELF binaries by compilers such as GCC , used by well known debuggers such as
GDB, and more recent ones such as systemtap.

Utilities in the dwarves suite include pahole, that can be used to find
alignment holes in structs and classes in languages such as C, C++, but not
limited to these, and other information such as CPU cacheline alignment,
helping pack those structures to achieve more cache hits, codiff, a diff like
tool to compare the effects changes in source code generate on the resulting
binaries, pfunct, that can be used to find all sorts of information about
functions, inlines, decisions made by the compiler about inlining, etc.

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
* Wed Jan 17 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
- e3786105c007a39ff3dbfb36a3037e786021e0c6
- First Fedora native build
- struct, enum, enum, void typedefs

* Sat Jan 13 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
- 9a413e60a3875980d99817722bf019cba3a24573
- pahole --nr_methods, improvements in tag__print, better support for unions

* Fri Jan 12 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
- a1f5422656a91568a8b4edbcebaae9c1837b5cbd
- Support a DW_TAG_reference_type

* Fri Jan 12 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
- 0ad467a32187e1929c14054a0fc7326bc4d235c8 
- Added a description

* Thu Jan 11 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
- new release with type not found asserts replaced by error messages

* Thu Jan 11 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
- package created
