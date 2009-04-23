%define libname libdwarves
%define libver 1

Name: dwarves
Version: 1.8pre1
Release: 1
License: GPLv2
Summary: Dwarf Tools
Group: Development/Tools
URL: http://oops.ghostprotocols.net:81/blog
Source: http://fedorapeople.org/~acme/dwarves/%{name}-%{version}.tar.bz2
BuildRequires: cmake
BuildRequires: elfutils-devel >= 0.130
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

%description
dwarves is a set of tools that use the DWARF debugging information inserted in
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

The documentation about ctracer is not updated to the latest developments: it
now generates systemtap scripts, stay tuned for improvements in this area!

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
%{_includedir}/dwarves/strings.h
%{_libdir}/%{libname}.so
%{_libdir}/%{libname}_emit.so
%{_libdir}/%{libname}_reorganize.so

%changelog
* Thu Apr 23 2009 Arnaldo Carvalho de Melo <acme@redhat.com> - 1.8pre1-1
- MANIFEST: add missing files
- dwarf_loader: Add containing_type to dwarf_tag
- dwarves: Move the fprintf code to a new source file.
- code: Combine the debugging_formats and debug_fmt_ops structs
- ctracer: blacklist functions in .init.text (__init marked)
- elf_symtab: Add elf_sym__section helper
- core: Be more strict with the return of __name() routines
- dutil: Allow returning the section index in elf_section_by_name
- strlist: Return false if NULL is passed to strlist__has_entry
- strlist: Allow strlist__add to distinguish ENOMEM from EEXIST
- libctf: ctf__delete must call elf_symtab__delete
- pahole: remove the alloc_detective include, it is not included yet :-\
- elf_symtab: elf_symtab__delete must free ->name too
- ctf_encoder: ctf__encode has to free the buf when compressing
- ctf_encoder: We have to free the gobuffer entries for the sections
- core: list__for_all_tags should delete shared enumerations
- core: Add ->init and ->exit hooks to be called at dwarves__{init,exit}
- core: cu__delete must delete ->filename too
- pahole: structure__delete should free ->name too.
- dwarf_loader: tag__recode_dwarf_bitfield should use cu__add_tag
- core: Only DWARF uses the global strings table, so move it there
- ctf: Plug debug_fmt_ops->strings__ptr
- core: Stop using strings__ptr(strings, i) directly
- pahole: Don't assume all strings are in the global strings table
- core: tag__name can't assume all cus use the global string table
- base_type: Don't combine names with attributes
- reorganize: class__demote_bitfield_members should update member->byte_size
- dwarf_loader: Handle volatile bitfields in class_member__cache_byte_size
- core: Fix thinko in type__find_first_biggest_size_base_type_member
- ctf_encoder: Add void entries for variables not found on DWARF
- core: Add variable__name to struct debug_fmt_ops
- pdwtags: Allow specifying the debug format to be decoded
- core: class__vtable_fprintf should use function__name
- core: cu__find_function_by_name must use function__name()
- core: Check if the debug_fmt_ops methods are available
- core: function__name in CTF gets the name from .strtab
- core: Rename cu_orig_info to debug_fmt_ops
- ctf_encoder: Add void (void) signature for functions not found on DWARF
- libctf: Ignore hidden symbols
- codiff: Support -F/--format_path
- core: Hasta la vista cu__for_each_tag
- codiff: Stop using cu__for_each_tag
- core: Fix cu__for_each_struct and cu__for_each_type
- pfunct: Stop using cu__for_each_tag
- prefcnt: Stop using cu__for_each_tag
- pglobal: Stop using cu__for_each_tag
- ctf_loader: Fill in the binding information for variables and functions
- syscse: Stop using cu__for_each_tag
- dtagnames: Stop using cu__for_each_tag
- pahole: Stop using cu__for_each_tag
- ctfdwdiff: Don't ask for variables and inline expansions in pfunct
- dwarf_loader: Delay recoding bitfield types
- dwarf_loader: Handle const and volatile bitfields in tag__recode_dwarf_bitfield
- ctf_encoder: ctf__ignore_symtab_object should ignore symbols with dots
- dwarf_loader: Fix thinko class_member__cache_byte_size
- core: Remove duplicate test for enums in tag__is_tag_type
- core: Fix cu__for_each_variable to cover an empty tags table
- ctf_encoder: Create objects section (data/variables)
- ctf_encoder: Rename hashaddr__find to hashaddr__find_function
- elf_symtab: Introduce elf_sym__is_local_object
- variable: Add ->addr member
- pdwtags: Print functions and variables too
- core: Introduce cu__for_each_variable
- gobuffer: Introduce gobuffer__copy
- core: Introduce cu__cache_symtab
- ctf_encoder: Convert DWARF functions to CTF
- ctf_loader: Load the function section
- ctf_encoder: Interface to encode functions
- core: Allow reusing the symtab already loaded and relocated
- libctf: fix ctf__delete
- core: Allow cachine an open Elf file handle for reuse
- pfunct: Introduce --no_parm_names
- elf_symtab: Fix bogus elf_symtab__is_local_function
- elf_symtab: Allow passing the name of the symtab to be parsed
- elf_symtab: Add accessor for the symbol size
- elf_symtab: Introduce elf_symtab__for_each_symbol
- dwarf_loader: Ditch that fugly oom crap, propagate errors
- core: Add destructors for the function and lexblock classes
- tag: Make tag__delete call the right destructors for non-trivial types
- ctf_loader: Ditch that fugly oom crap, propagate errors
- enumerator: Introduce enumerator__delete
- type: Introduce type__delete
- ftype: Introduce ftype__delete
- core: Introduce ftype__for_each_parameter_safe
- ctf: Move ctf_format_flt_attrs from the loader to libctf
- core: Add a per object file functions_table
- core: function__tag_fprintf should check if the alias name is NULL
- pahole: Remove --dwarf_offset/-O option
- ctf_loader: create_new_subroutine_type should create just a ftype
- ctf: combine the structs ctf_state and ctf
- ctf_loader: Remove the elf iteration functions/structs
- libctf: Adopt ctf__string from ctf_loader.c
- Also introduce a ctf__string32 for the very common idiom:
- elf_symtab: Introduce elf_symtab
- dutil: Move elf_section_by_name to dutil
- core: Rename {cus,dwarf,ctf}__load to {cus,dwarf,ctf}__load_file
- pfunct: Add --format_path/-F as in pahole
- dwarf: Handle DW_AT_GNU_vector attributes in arrays
- core: Handle GCC support for vector instructions
- pahole: Remove a not needed "the" article in the man page.
- core: Handle GCC support for vector instructions
- tag: tag__follow_typedef doesn't change self, make it const
- pdwtags: Use conf_load.stealer
- ctf_loader: One more attempt at handling packed enums
- ctfdwdiff: allow specifying just one file again
- ctfdwdiff: Handle files without DWARF info too
- ctfdwdiff: Make it work in directories
- pahole: don't print private members inside types when using show_private_classes
- dwarves: Fixup the flat_arrays code
- base_type: floats are 32 bits
- ctf_encoder: Check if something was encoded before saving the info
- dwarf: share the enumerators when recoding an enum bitfield
- enumeration: Allow sharing the enumerators
- ctf_encoder: Allow encoding a bit_size in enumeration types
- ctf_loader: enums can have a bit_size less than 8 * size(int)
- pahole: Introduce --show_private_classes
- strings: Allow calling strings__delete with a NULL pointer
- pahole: Introduce --flat_array
- ctfdwdiff: Make it more bulk test friendly
- base_type: Add "float" to base_type_name_to_size_table
- libctf: Encode VARARGS an extra 0 short at the end of the parm list
- ctfdwdiff: Simple shell script for testing the CTF encoder/decoder
- libctf: give up "for now" on using libelf to add a section to an existing file
- libctf: comment out some debug messages
- ctf: Give some more info about UNKNOWN types
- pahole: Add --format_path/-F to specify a list of formats to try
- ctf: Include the initial implementation of a ctf encoder
- ctf: class__fixup_ctf_bitfields has to handle enums
- ctf: Stop returning "(anonymous)" in ctf_string
- ctf: Add a filename member to struct ctf
- cus: Allow passing a debugging format path to cus__load
- enumeration: type->size for enumerations is in bits, not in bytes
- base_type__name_to_size: Complain when not finding the requested type name
- base_type_name_to_size: Add "long double long double"
- cu: Add a filename member
- gobuffer: Introduce gobuffer__allocate
- cu: Rename cu__find_{type,tag}_by_id to cu__{type,tag}
- class_member: Reencode DWARF bitfield types
- cu: Introduce cu__find_enumeration_by_sname_and_size
- base_type: Move base_type__name_to_size from the ctf loader to the core
- dutil: Move zalloc to dutil
- class_member: cache the byte size of the member
- class_member: cache byte_size
- ctf: improve base_type__name_to_size
- dwarves: Rename the class_member bitfields size and offset members
- pdwtags: cu->types_tables can have some NULL slots
- ctf: ctf_load can receive a NULL conf_load
- dwarves: Move abstract_origin to dwarf_tag
- dwarves: Don't double free vtable entries
- dwarves: the variable abstract_origin is resolved at load time too
- dwarf_loader: conf_load can be NULL
- dwarves: Remove some unused functions
- dwarves: reorganize dwarves.h to group classes with its methods
- coding style: remove trailing whitespaces, etc
- headers: remove not needed 'extern' noise from function prototypes
- dwarves: Introduce cu__find_base_type_by_sname_and_size
- pahole: Use the new progressive processing scheme
- dwarves: Allow the apps to steal compile units as they are created
- dwarves: Introduce cu__find_struct_by_sname
- dwarves: Fix cu__for_each_function when there are no functions
- dwarves: Rename cus__loadfl with cus__load_files
- dwarves: Ditch old cus__load and cus__load_filename
- dwarves: cu__find_struct_by_name should set id for non declarations
- ctracer: skip object files that don't have the target class
- dwarves: Add destructors
- dwarf: separate dwarf_tag from tag
- dwarves: Introduce cu__for_all_tags
- dwarves: replace high_pc by size in struct lex_block
- dwarves: Reduce the size of some data structures
- reorganize: Fix bug in cu__find_base_type_of_size alternate type names
- dwarf__loader: optimize tag__init a bit more
- dwarves: find holes when adding a fresh compile unit
- ctracer: Remove superfluous calls to class__find_holes in class__clone_base_types
- dwarves: use tag__is_function in the tools
- dwarves: Introduce tag__is_function()
- dwarves: check if the current pos is NULL in cu__for_each_function
- dwarves: remove now unused 'cu' argument to {type,class}__name
- dwarves: Ditch parameter__type and simplify parameter__name
- dwarves: Remove some more DWARF details from the core
- dwarf_loader: DW_TAG_label can have DW_AT_abstract_origin
- dwarf_loader: Accept empty enums, seen in the wild
- dwarves: Print arrays in tag__fprintf too
- dwarf_loader: Optimize tag__init a bit
- dwarves: Use hlist for the hashtables
- man-pages: Fixup typo
- dwarves: Add missing bits of separate hash table for types
- dwarves: Add DW_TAG_ptr_to_member_type to tag__is_tag_type
- dwarves: Add DW_TAG_reference_type to tag__is_tag_type
- dwarves: Move hashtags__find out of cu__find_tag_by_id
- dwarves: Introduce cu__hash
- dwarves: Introduce tag__is_tag_type
- dwarves: rename tag->refcnt to tag->visited and shrink it to 1 bit
- codiff: Detect changes in padding and the number of holes/bit_holes
- codiff: improve detection removal and addition of members in structs
- dwarves: Introduce tag__has_namespace
- reorganize: cu__find_base_type_of_size should look for alternative CTF base type names
- ctf: No need to concat "char " if attrs & CTF_TYPE_INT_CHAR is true
- ctf_loader: Fix up bitfields
- dwarves: Implement cu__find_base_type_by_name_and_size
- ctf: Find out word size on the ELF header

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
