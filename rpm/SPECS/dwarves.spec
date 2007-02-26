%define libname libdwarves
%define libver 1

Name: dwarves
Version: 0
Release: 15
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
BuildRoot: %{_tmppath}/%{name}-%{version}-acme

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
cmake -D __LIB=%{_lib} .
make

%install
rm -Rf %{buildroot}
mkdir -p %{buildroot}{%{_libdir},%{_bindir},%{_includedir},%{_libdir}/ctracer}

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
%{_bindir}/pdwtags
%{_bindir}/pfunct
%{_bindir}/pglobal
%{_bindir}/prefcnt
%{_bindir}/ostra-cg
%dir %{_libdir}/ctracer
%{_libdir}/ctracer/Makefile
%{_libdir}/ctracer/ctracer_jprobe.c
%{_libdir}/ctracer/ctracer_relay.c
%{_libdir}/ctracer/ctracer_relay.h
%dir %{_libdir}/ctracer/python
%{_libdir}/ctracer/python/ostra.py*

%files -n %{libname}%{libver}
%defattr(0644,root,root,0755)
%{_libdir}/%{libname}.so.*

%files -n %{libname}-devel
%defattr(0644,root,root,0755)
%{_includedir}/dwarves.h
%{_libdir}/%{libname}.so

%changelog
* Sun Feb 25 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- 3c148cd84b74b89663febdefab23356952906502
- _snprintf routines changed to _fprintf
- codiff shows diffs in number and total size of inline expansions
- codiff shows diffs in the number of lexblocks
- better alignment in the --expand_types case
- CMake improvements

* Fri Feb  2 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- d37f41df58c375412badf827e24dfc346cea2ff2
- ostra-cg
- relay/debugfs
- mini-structs
- ctracer2ostra
- All this in the Makefile

* Fri Feb  2 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- b7cad1782d683571ffb2601b429ab151bddad5d7
- pglobal, by Davi Arnaut
- pahole --show_reorg_steps
- Reorganize bitfields in pahole --reorganize

* Tue Jan 30 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- 8e236f4ca37b8a3d2057f4ede5a14ab1fa99f73c
- x86-64 lib install fixes

* Tue Jan 30 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- 4a4b75e75a6d7f34215d320cc4a9f669b6ba4075
- pahole --reorganize

* Mon Jan 29 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- 2de67fcaf401ac1e20feca5fa88dfc63fbc4203e
- Type expansion!

* Sat Jan 27 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- 6bf2d2d7707b65e7ca21a13706d8d07824cd6f2f
- ctracer improvements, /usr/lib/ctracer/, etc

* Fri Jan 26 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- c49f2c963425d5c09c429370e10d9af3d7d7fe32
- Emit typedefs of typedef arrays
- Detect typedef loops
- Fix emission of arrays of structs, unions, etc
- use sysconf for the default cacheline size

* Wed Jan 18 2007 Arnaldo Carvalho de Melo <acme@ghostprotocols.net>
- fab0db03ea9046893ca110bb2b7d71b764f61033
- pdwtags added

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
