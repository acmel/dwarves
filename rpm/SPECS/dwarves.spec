%define libname libdwarves
%define libver 1

Name: dwarves
Version: 0
Release: 24
License: GPL
Summary: Dwarf Tools
Group: Development/Tools
URL: http://oops.ghostprotocols.net:81/blog
Source: pahole-%{version}.tar.bz2
BuildRequires: cmake
BuildRequires: elfutils-devel
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

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
Group: Development/Libraries

%description -n %{libname}%{libver}
DWARF processing library

%package -n %{libname}%{libver}-devel
Summary: DWARF processing library development files
Group: Development/Libraries
Requires: %{libname}%{libver} = %{version}-%{release}

%description -n %{libname}%{libver}-devel
DWARF processing library development files

%prep
%setup -q -c -n %{name}-%{version}

%build
cmake -D__LIB=%{_lib} -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE="MinSizeRel" .
make %{?_smp_mflags}

%install
rm -Rf %{buildroot}
mkdir -p %{buildroot}{%{_libdir},%{_bindir},%{_includedir},%{_libdir}/ctracer}

make DESTDIR=%{buildroot} install

%post -n %{libname}%{libver} -p /sbin/ldconfig

%postun -n %{libname}%{libver} -p /sbin/ldconfig

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
%dir %{_libdir}/ctracer/python
%defattr(0644,root,root,0755)
%{_libdir}/ctracer/Makefile
%{_libdir}/ctracer/ctracer_jprobe.c
%{_libdir}/ctracer/ctracer_relay.c
%{_libdir}/ctracer/ctracer_relay.h
%attr(0755,root,root) %{_libdir}/ctracer/python/ostra.py*

%files -n %{libname}%{libver}
%defattr(0644,root,root,0755)
%{_libdir}/%{libname}.so.*
%{_libdir}/%{libname}_emit.so.*
%{_libdir}/%{libname}_reorganize.so.*

%files -n %{libname}%{libver}-devel
%defattr(0644,root,root,0755)
%doc MANIFEST README
%{_includedir}/dwarves.h
%{_includedir}/dwarves_emit.h
%{_includedir}/dwarves_reorganize.h
%{_libdir}/%{libname}.so
%{_libdir}/%{libname}_emit.so
%{_libdir}/%{libname}_reorganize.so

%changelog
* Tue May  8 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
* 161c6712f4ae1b7e2ea50df3a0d5c28310905cec
- handle --help, -? --usage on with_executable_option()

* Tue May  8 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
* b8eb5eb214f3897ea6faa3272879baa8bf2573c0
- Fix cus__loadfl detection of --executable

* Sun May  6 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- 05351ece16e5203717dd21a6fc1ad2e6ff87c203
- libdwarves_emit

* Tue Apr  3 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- f3c4f527f70053e39b402005107ead6cb10e0b4a
- Fix some --reorganize bugs

* Mon Apr  2 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- 1ec66565a12ce7f197cd40e3901ed6be84935781
- --reorganize improvements
- --packable uses --reorganize code to show structs that can be packed by
  reorganization done with --reorganize.

* Fri Mar 30 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- fd3542317508d04e8178c5d391385d2aa50d6fb7
- Use libdwfl in all tools that handle just one file, codiff and ctracer
  still need work and are still using plain libdw.

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
