%define libname libdwarves
%define libver 1

Name: dwarves
Version: 1.10
Release: 1%{?dist}
License: GPLv2
Summary: Debugging Information Manipulation Tools
Group: Development/Tools
URL: http://acmel.wordpress.com
Source: http://fedorapeople.org/~acme/dwarves/%{name}-%{version}.tar.bz2
BuildRequires: cmake
BuildRequires: elfutils-devel >= 0.130
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

%description
dwarves is a set of tools that use the debugging information inserted in
ELF binaries by compilers such as GCC, used by well known debuggers such as
GDB, and more recent ones such as systemtap.

Utilities in the dwarves suite include pahole, that can be used to find
alignment holes in structs and classes in languages such as C, C++, but not
limited to these.

It also extracts other information such as CPU cacheline alignment, helping
pack those structures to achieve more cache hits.

A diff like tool, codiff can be used to compare the effects changes in source
code generate on the resulting binaries.

Another tool is pfunct, that can be used to find all sorts of information about
functions, inlines, decisions made by the compiler about inlining, etc.

%package -n %{libname}%{libver}
Summary: Debugging information  processing library
Group: Development/Libraries

%description -n %{libname}%{libver}
Debugging information processing library.

%package -n %{libname}%{libver}-devel
Summary: Debugging information library development files
Group: Development/Libraries
Requires: %{libname}%{libver} = %{version}-%{release}

%description -n %{libname}%{libver}-devel
Debugging information processing library development files.

%prep
%setup -q -c -n %{name}-%{version}

%build
%cmake .
make VERBOSE=1 %{?_smp_mflags}

%install
rm -Rf %{buildroot}
make install DESTDIR=%{buildroot}

%post -n %{libname}%{libver} -p /sbin/ldconfig

%postun -n %{libname}%{libver} -p /sbin/ldconfig

%clean
rm -rf %{buildroot}

%files
%defattr(0644,root,root,0755)
%doc README.ctracer
%doc NEWS
%defattr(0755,root,root,0755)
%{_bindir}/codiff
%{_bindir}/ctracer
%{_bindir}/dtagnames
%{_bindir}/pahole
%{_bindir}/pdwtags
%{_bindir}/pfunct
%{_bindir}/pglobal
%{_bindir}/prefcnt
%{_bindir}/scncopy
%{_bindir}/syscse
%{_bindir}/ostra-cg
%dir %{_datadir}/dwarves/
%dir %{_datadir}/dwarves/runtime/
%dir %{_datadir}/dwarves/runtime/python/
%defattr(0644,root,root,0755)
%{_mandir}/man1/pahole.1*
%{_datadir}/dwarves/runtime/Makefile
%{_datadir}/dwarves/runtime/linux.blacklist.cu
%{_datadir}/dwarves/runtime/ctracer_relay.c
%{_datadir}/dwarves/runtime/ctracer_relay.h
%attr(0755,root,root) %{_datadir}/dwarves/runtime/python/ostra.py*

%files -n %{libname}%{libver}
%defattr(0644,root,root,0755)
%{_libdir}/%{libname}.so.*
%{_libdir}/%{libname}_emit.so.*
%{_libdir}/%{libname}_reorganize.so.*

%files -n %{libname}%{libver}-devel
%defattr(0644,root,root,0755)
%doc MANIFEST README
%{_includedir}/dwarves/dwarves.h
%{_includedir}/dwarves/dwarves_emit.h
%{_includedir}/dwarves/dwarves_reorganize.h
%{_includedir}/dwarves/dutil.h
%{_includedir}/dwarves/gobuffer.h
%{_includedir}/dwarves/list.h
%{_includedir}/dwarves/rbtree.h
%{_includedir}/dwarves/strings.h
%{_libdir}/%{libname}.so
%{_libdir}/%{libname}_emit.so
%{_libdir}/%{libname}_reorganize.so

%changelog
* Wed May 30 2012 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.10-1
- New release

* Sat Nov 20 2010 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.9-1
- New release

* Fri Dec  4 2009 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.8-1
- New release

* Fri Feb 13 2009 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.7-2
- Own /usr/share/dwarves, fixes #473645 

* Fri Feb 13 2009 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.7-1
- A CTF decoder based on work done by David S. Miller
- Handle DW_TAG_class_type,
- Add support for showing classes with a prefix
- Add support to DW_TAG_ptr_to_member_type
- Handle typedef definitions in functions
- Print the number of members in a struct/class
- Handle the empty base optimization trick (Zero sized C++ class)
- codiff detect changes in the prototype even when function size doesn't change
- pfunct: Implement --expand_types
- Reduce memory consumption by using a strings table
- Speed up struct search by name
- Several minor bug fixes and infrastructure improvements.
- Initial man page for pahole

* Mon Feb 11 2008 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.6-1
- c83d935a4fd561a3807f520c126c2a61ae1f4d83
- [DWARVES]: Use a hash table for the tags in a CU

* Thu Feb  7 2008 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.5-1
- c4e49add9e48ff08a8ba4187ea43d795af995136
- PAHOLE: Introduce --defined_in
- DWARVES: Another fix for DW_TAG_base_type entries without DW_AT_name
- PAHOLE: Cope with DW_TAG_basic_type entries without DW_AT_name
- CODIFF: Allow passing /dev/null as one of the files to compare
- DWARVES: Allow passing NULL as self to cu__find_
- DWARVES: Fixup usage messages
- DWARVES: Find holes in inner, nameless structs
- DWARVES: Adopt tag__follow_typedef from pahole
- DWARVES: Add some destructors: tag, cu, namespace
- CODIFF: Check if the objects are the same when we have build-id
- DWARVES: Introduce cu__same_build_id
- DWARVES_REORGANIZE: Proper tail padding fixup
- DWARVES: Don't search in empty structs
- DWARVES: Follow const and volatile tags to its ultimate types
- PAHOLE: Add a newline after the --class_dwarf_offset output
- PAHOLE: Expose type__find_first_biggest_size_base_type_member
- DWARVES: Introduce type__find_first_biggest_size_base_type_member
- PAHOLE: Account arrays properly when changing word-size
- PAHOLE: Follow typedefs too when resizing unions
- PAHOLE: Follow typedefs to find if they are resized structs/unions
- PAHOLE: Check if types of struct and union members were already resized
- DWARVES_REORGANIZE: Fixup class__fixup_alingment
- PAHOLE: Allow changing the architecture word-size
- DWARVES_REORGANIZE: Adopt class__add_offsets_from and class__fixup_alignment from ctracer
- DWARVES: build id support requires a recent elfutils package

* Sat Jan  5 2008 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.4-1
- 8e099cf5d1f204e9ea1a9c8c0f1a09a43458d9d3
- codiff fixes

* Sun Dec  9 2007 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.3-2
- c6c71398cd2481e219ea3ef63f32c6479ba4f08f
- SPEC file adjustments to follow http://fedoraproject.org/wiki/Packaging/cmake

* Sat Dec  8 2007 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.3-1
- c4ee21aa122f51f2601893b2118b7f7902d2f410
- Fixed bitfield byte offset handling, now there are no
  more BRAIN FART alerts on a x86_64 linux kernel and on
  an old openbsd kernel image.

* Thu Dec  6 2007 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.2-1
- 07e0974f2c3798acb8e9a2d06f6b2ece7a01c508
- Fix a patological bitfield case

* Thu Dec  6 2007 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.1-1
- 2c01420b51e889196b42a204910b46811ab22f1a
- ctracer now generates systemtap scripts
- Lots of other fixes, see git changelog.

* Tue May  8 2007 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.0-1
- 161c6712f4ae1b7e2ea50df3a0d5c28310905cec
- handle --help, -? --usage on with_executable_option()

* Tue May  8 2007 Arnaldo Carvalho de Melo <acme@redhat.com>
- b8eb5eb214f3897ea6faa3272879baa8bf2573c0
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
