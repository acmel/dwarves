#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test the similar cset grouping and the compact output of
# scripts/prep-release.sh, which combines near identical commit
# subjects, such as "Remove 6 dead functions found via coverage
# analysis" and "Remove 5 dead functions found via coverage analysis",
# into a single bullet ("Remove 11 dead functions found via coverage
# analysis, in 2 csets") in the changes-vX.Y draft, without squashing
# anything in git: NEWS keeps listing every cset.
#
# It also checks that the announcement CC list is derived from the
# release range, the people that authored, reviewed or tested the csets
# being released, plus the distro packagers and the mailing lists, not
# from the CC list of every cset ever, which some mailing lists refuse
# as long To: lines, and that the sender is not CCed on the
# announcement he sends.
#
# The announcement subject and intro paragraph are checked as well:
# built from the optional "Highlights:" section of the edited draft,
# one bullet per release milestone, falling back to the areas touched,
# kept under 80 characters, in the style of the previous announcements:
# related areas grouped, the pahole area itself, man pages, the Other
# catchall and the minor utilities left out.
#
# When ugrep is not installed, a fake FUZZY_GREP is used, implementing
# the ugrep subset that prep-release.sh relies on (-n -Z<T> -F -q --
# PATTERN [FILE]) with whole line edit distance matching.  For the near
# identical subjects used here, whole line and ugrep's contiguous
# substring approximate matching produce the same groups.

. "$(dirname "$0")"/test_lib.sh

outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "prep-release.sh: similar cset grouping and compact output."

if ! command -v git > /dev/null 2>&1; then
	info_log "skip: git not available"
	test_skip
fi

if ! command -v bash > /dev/null 2>&1; then
	info_log "skip: bash not available"
	test_skip
fi

if ! command -v gpg > /dev/null 2>&1 && ! command -v gpg2 > /dev/null 2>&1; then
	info_log "skip: no gpg found, prep-release.sh requires it even with --no-tag"
	test_skip
fi

# prep-release.sh requires a grep with fuzzy matching, ugrep, to find
# the similar csets.  When it is not installed, provide a fake
# FUZZY_GREP, which also exercises the FUZZY_GREP override:
if ! command -v ugrep > /dev/null 2>&1; then
	info_log "   ugrep not available, using a fake FUZZY_GREP"
	cat > "$outdir/fake-ugrep" << 'EOF'
#!/bin/sh
# Implements the ugrep subset used by scripts/prep-release.sh:
# -n -Z<T> -F -q -- PATTERN [FILE], matching lines within an edit
# distance of T from the pattern.
T=1
qflag=
nflag=
pat=
file=
while [ $# -gt 0 ]; do
	case $1 in
	-Z*)	T=${1#-Z} ;;
	-q)	qflag=1 ;;
	-n)	nflag=1 ;;
	-F)	;;
	--)	shift ; pat=${1:-} ; file=${2:-} ; break ;;
	*)	if [ -z "$pat" ]; then pat=$1; else file=$1; fi ;;
	esac
	shift
done
[ -n "$pat" ] || exit 2
prog='
	function lev(a, b,    la, lb, i, j, c, x, y, z) {
		la = length(a); lb = length(b)
		for (i = 0; i <= lb; i++) prev[i] = i
		for (i = 1; i <= la; i++) {
			curr[0] = i
			for (j = 1; j <= lb; j++) {
				c = (substr(a, i, 1) == substr(b, j, 1)) ? 0 : 1
				x = prev[j] + 1
				y = curr[j - 1] + 1
				z = prev[j - 1] + c
				curr[j] = (x < y) ? ((x < z) ? x : z) : ((y < z) ? y : z)
			}
			for (j = 0; j <= lb; j++) prev[j] = curr[j]
		}
		return prev[lb]
	}
	{
		if (lev(pat, $0) <= t) {
			if (q) { found = 1; exit 0 }
			if (n)
				printf "%d:%s\n", NR, $0
			else
				print $0
		}
	}
	END { if (q && !found) exit 1 }
'
if [ -n "$file" ]; then
	awk -v pat="$pat" -v t="$T" -v q="$qflag" -v n="$nflag" "$prog" "$file"
else
	awk -v pat="$pat" -v t="$T" -v q="$qflag" -v n="$nflag" "$prog"
fi
EOF
	chmod +x "$outdir/fake-ugrep"
	FUZZY_GREP="$outdir/fake-ugrep"
	export FUZZY_GREP
fi

script="$tests_root/../scripts/prep-release.sh"
[ -f "$script" ] || {
	error_log "FAIL: $script not found"
	test_fail
}

# ── Unit tests for the grouping helpers, extracted from the script ────
sed -n '/^combine_numbered_bullets() {/,/^}/p' "$script" > "$outdir/funcs.sh" ||
	test_fail
sed -n '/^group_similar_bullets() {/,/^}/p' "$script" >> "$outdir/funcs.sh" ||
	test_fail
sed -n '/^dedup_emails() {/,/^}/p' "$script" >> "$outdir/funcs.sh" ||
	test_fail
sed -n '/^subject_items() {/,/^}/p' "$script" >> "$outdir/funcs.sh" ||
	test_fail
sed -n '/^theme_words() {/,/^}/p' "$script" >> "$outdir/funcs.sh" ||
	test_fail
sed -n '/^noticed_highlights() {/,/^}/p' "$script" >> "$outdir/funcs.sh" ||
	test_fail
sed -n '/^check_rpm() {/,/^}/p' "$script" >> "$outdir/funcs.sh" ||
	test_fail
# check_rpm, noticed_highlights and the grouping helpers use them:
sed -n '/^warn() {/,/^}/p' "$script" >> "$outdir/funcs.sh" ||
	test_fail
sed -n '/^die() {/,/^}/p' "$script" >> "$outdir/funcs.sh" ||
	test_fail
sed -n '/^info() {/,/^}/p' "$script" >> "$outdir/funcs.sh" ||
	test_fail
# shellcheck source=/dev/null
. "$outdir/funcs.sh"

check_combine()
{
	local expected=$1
	shift
	if ! merged=$(printf '%s\n' "$@" | combine_numbered_bullets 2>/dev/null); then
		error_log "FAIL: combine_numbered_bullets rejected: $*"
		test_fail
	fi
	if [ "$merged" != "$expected" ]; then
		error_log "FAIL: got '$merged', expected '$expected'"
		test_fail
	fi
	info_log "   combined into '$merged': ok"
}

check_combine_rejected()
{
	if printf '%s\n' "$@" | combine_numbered_bullets > /dev/null 2>&1; then
		error_log "FAIL: should not have combined: $*"
		test_fail
	fi
	info_log "   rejected bullets that are not a number apart: ok"
}

# The example from the release notes: two csets, 6 + 5 dead functions.
check_combine "Remove 11 dead functions found via coverage analysis" \
	"Remove 6 dead functions found via coverage analysis" \
	"Remove 5 dead functions found via coverage analysis"

# Identical bullets mixed with a differing one: 6 + 6 + 5 = 17.
check_combine "Remove 17 dead functions found via coverage analysis" \
	"Remove 6 dead functions found via coverage analysis" \
	"Remove 6 dead functions found via coverage analysis" \
	"Remove 5 dead functions found via coverage analysis"

# Version numbers are not counts, they must not be added up:
check_combine_rejected \
	"Sync with libbpf-1.5" \
	"Sync with libbpf-1.1"

# Singular/plural, not a number apart:
check_combine_rejected \
	"Add test" \
	"Add tests"

# Numbers glued to other characters are not standalone counts:
check_combine_rejected \
	"Fix segfault in 64-bit systems" \
	"Fix segfault in 32-bit systems"

# Different number of words, even if one is a prefix of the other:
check_combine_rejected \
	"Add missing files" \
	"Add missing files to generate the tarball"

# ── Unit tests for the announcement CC list dedup ──────────────────────
check_dedup()
{
	local skip1=$1 skip2=$2 expected=$3
	shift 3
	if ! deduped=$(printf '%s\n' "$@" | dedup_emails "$skip1" "$skip2" 2>/dev/null); then
		error_log "FAIL: dedup_emails failed: $*"
		test_fail
	fi
	if [ "$deduped" != "$expected" ]; then
		error_log "FAIL: got '$deduped', expected '$expected'"
		test_fail
	fi
	info_log "   deduped to '$(printf '%s\n' "$expected" | wc -l)' recipients: ok"
}

# The same person under differently spelled names and address casing
# dedups to the first spelling, the same list bare and name qualified
# as well:
check_dedup "" "" "A Reviewer <a.reviewer@example.com>
Second Author <second@example.com>
bpf@vger.kernel.org" \
	"A Reviewer <a.reviewer@example.com>" \
	"a reviewer <A.REVIEWER@EXAMPLE.COM>" \
	"Second Author <second@example.com>" \
	"second author <SECOND@example.com>" \
	"bpf@vger.kernel.org" \
	"BPF list <bpf@vger.kernel.org>"

# The sender is dropped altogether, even when the csets are authored
# and tagged with another of his addresses:
check_dedup "acme@redhat.com" "acme@kernel.org" \
	"Second Author <second@example.com>
A Reviewer <a.reviewer@example.com>" \
	"Arnaldo Carvalho de Melo <acme@redhat.com>" \
	"Second Author <second@example.com>" \
	"Arnaldo Carvalho de Melo <acme@kernel.org>" \
	"Arnaldo Carvalho de Melo <ACME@REDHAT.COM>" \
	"A Reviewer <a.reviewer@example.com>"

# ── Unit tests for the announcement subject composition ────────────────
check_subject()
{
	local expected=$1
	shift
	if ! got=$(subject_items "$@" 2>/dev/null); then
		error_log "FAIL: subject_items failed: $*"
		test_fail
	fi
	if [ "$got" != "$expected" ]; then
		error_log "FAIL: got '$got', expected '$expected'"
		test_fail
	fi
	info_log "   subject from $# items: '$got': ok"
}

# The new_tag used by subject_items, as in a release:
new_tag=v1.31

# All the items fit:
check_subject "DWARF loader, BTF, Library, Regression tests and CI" \
	"DWARF loader" "BTF" "Library" "Regression tests and CI"

# The first item doesn't fit whole, its lead phrase, up to the first
# comma, is used, the second doesn't fit at all, acknowledged with
# "and more":
check_subject "Support for dwz files, and more" \
	"Support for dwz files, most distro userspace DWARF is now supported" \
	"Support for more CONFIG_DEBUG_INFO_DWARF options"

# Items are dropped from the end to fit the "and more" marker:
check_subject "Support for dwz files, and more" \
	"Support for dwz files" \
	"Another milestone phrase" \
	"Third" \
	"Fourth"

# Nothing fits, the caller falls back to a subject without items:
check_subject "" \
	"A very long milestone phrase that can not possibly fit in the subject, no way"

# ── End to end: a fixture repo with known similar csets ───────────────
fixture="$outdir/prep-release-fixture"
mkdir -p "$fixture/rpm/SPECS" "$fixture/scripts"
cd "$fixture" || test_fail
git init -q -b master 2>/dev/null || { git init -q && git checkout -q -b master; }
git config user.name "Test User"
git config user.email "test@example.com"

# Make the announcement sender a fixture address, so that its absence
# from the CC list can be checked end to end, not just in the unit
# tests:
export FROM="Test Sender <sender@example.com>"

cat > MANIFEST << 'EOF'
CMakeLists.txt
MANIFEST
NEWS
changes-v1.30
rpm/SPECS/dwarves.spec
EOF

cat > CMakeLists.txt << 'EOF'
cmake_minimum_required(VERSION 3.10)
# add_definitions(-D_GNU_SOURCE -DDWARVES_VERSION="v1.30")
add_definitions(-D_GNU_SOURCE -DDWARVES_MAJOR_VERSION=1)
add_definitions(-D_GNU_SOURCE -DDWARVES_MINOR_VERSION=30)
EOF

cat > NEWS << 'EOF'
v1.30

deadc0ffee123456 btf_encoder: Add DWARF-less BTF encoding
EOF

cat > rpm/SPECS/dwarves.spec << 'EOF'
Name: dwarves
Version: 1.30
Release: 1%{?dist}
License: GPL-2.0-only
Summary: Debugging Information Manipulation Tools (pahole & friends)

%files
%doc changes-v1.30
%doc NEWS

%changelog
EOF

cat > scripts/make-tarball.sh << 'EOF'
#!/bin/sh
# Not used, the release test runs with --no-tarball.
EOF

cat > PKG-MAINTAINERS << 'EOF'
# The distro packagers, CCed on the announcements.
Distro Packer <packer@example.com>
EOF

cat > changes-v1.30 << 'EOF'
Regression tests:

- Add an enumerator search test

BTF loader:

- Fix the inference of the explicit alignment attribute of zero length arrays.
EOF

# The regression tests at the previous release, so that the growth of
# their number can be noticed:
mkdir tests
: > tests/a.sh
: > tests/b.sh

git add -A
git commit -q -m "Prep 1.30"
git tag v1.30

# The csets being released, oldest first, so that the git log order,
# used for the changes draft, is newest first:
for subject in \
	"pahole: Fix -C -T segfault" \
	"btf_loader: Sync with libbpf-1.5" \
	"btf_loader: Sync with libbpf-1.1" \
	"gobuffer: Remove 5 dead functions found via coverage analysis" \
	"dwarves: Remove 6 dead functions found via coverage analysis" \
	"tests: Add enumerator search test" \
	"tests: Add enumerator search test" \
	"tests: Add tests" \
	"tests: Add test"
do
	git commit -q --allow-empty -m "$subject"
done

# Recipients of the announcement: a cset by a second author, one with
# Reviewed-by/Tested-by tags, one with just a Cc: trailer, and one
# pairing a differently spelled name with an email already in the list,
# which must be deduped:
git -c user.name="Second Author" -c user.email=second@example.com \
	commit -q --allow-empty \
	-m "pfunct: Second author commit for the announcement"
git commit -q --allow-empty -m "btf_encoder: Review tagged change" \
	-m "Reviewed-by: A Reviewer <a.reviewer@example.com>" \
	-m "Tested-by: A Tester <a.tester@example.com>"
git commit -q --allow-empty -m "pahole: Cc trailer only entry" \
	-m "Cc: Only Cced <only.cced@example.com>"
git commit -q --allow-empty -m "pfunct: Dedup exercise" \
	-m "Reviewed-by: second author <SECOND@example.com>"
# And a cset authored with the announcement's From: address, which must
# not be CCed either:
git -c user.name="Sender Author" -c user.email=sender@example.com \
	commit -q --allow-empty -m "pahole: Sender authored"

# Milestone and unworthy-from-the-subject areas: the draft will have
# sections for all of them, the subject assertions below check that
# only the worthy ones make it there:
git commit -q --allow-empty -m "dwarf_loader: Support DW_FORM_GNU_ref_alt references to dwz alternate debug files"
git commit -q --allow-empty -m "pahole: Add support for more CONFIG_DEBUG_INFO_DWARF options"
git commit -q --allow-empty -m "Other: Catch all bucket"
git commit -q --allow-empty -m "man-pages: Document the tools"
git commit -q --allow-empty -m "scncopy: Fix scncopy output"
git commit -q --allow-empty -m "btfdiff: Compare DWARF and BTF output"
git commit -q --allow-empty -m "CI: Add pahole build check"

# The regression tests growth, noticed by the script for the
# Highlights section:
for i in 1 2 3 4 5 6; do
	: > "tests/t$i.sh"
done
git add tests
git commit -q -m "tests: Add more tests"

# The highlights noticed programmatically, run where the release would
# be cut, with the same $prev_tag: the number of regression tests grew
# from 2 to 8, dramatic, and no theme word qualifies, as none repeats
# in the subject of six or more csets:
prev_tag=v1.30
hl=$(noticed_highlights)
if [ "$hl" != "- Regression tests: from 2 in v1.30 to 8" ]; then
	error_log "FAIL: unexpected noticed highlights: '$hl'"
	test_fail
fi
info_log "   noticed highlights have the regression tests growth: ok"
if [ -n "$(theme_words 6)" ]; then
	error_log "FAIL: unexpected theme words: '$(theme_words 6)'"
	test_fail
fi
info_log "   no theme word qualifies in the fixture: ok"
unset prev_tag

# The rpm build check: warn-only when rpmbuild is not installed, and
# with it installed, a real, minimal spec is built, exercising the
# whole check_rpm path, the same one the release flow uses with the
# real tarball and spec:
if ! command -v rpmbuild > /dev/null 2>&1; then
	warned=$(check_rpm "$outdir/no-such-spec.spec" 2>&1)
	case $? in
	0)	;;
	*)	error_log "FAIL: check_rpm failed without rpmbuild: rc $?: $warned"
		test_fail ;;
	esac
	case $warned in
	*"rpmbuild not found, the rpm build will not be checked"*) ;;
	*)	error_log "FAIL: no warning about the missing rpmbuild: '$warned'"
		test_fail ;;
	esac
	info_log "   missing rpmbuild is warn-only in check_rpm: ok"
else
	# check_rpm looks for the version in $version and builds its tree
	# in $tmpdir, as in the release flow:
	version=1.32
	tmpdir=$outdir
	tarball_dir=$outdir
	cat > "$outdir/dwarves.spec" << 'EOF'
Name: dwarves
Version: 1.32
Release: 1%{?dist}
License: GPL-2.0-only
Summary: Minimal spec to test the rpm build check

%description
Minimal spec to test the rpm build check.

%prep
echo test > README

%files
%doc README
EOF
	if built=$(check_rpm "$outdir/dwarves.spec" 2>&1); then
		case $built in
		*"dwarves-1.32"*) ;;
		*)	error_log "FAIL: no dwarves-1.32 rpm in the check_rpm output: $built"
			test_fail ;;
		esac
		case $built in
		*"rpm version check: dwarves 1.32"*) ;;
		*)	error_log "FAIL: the rpm version check output is missing: $built"
			test_fail ;;
		esac
		info_log "   check_rpm builds and checks a minimal rpm: ok"
	else
		error_log "FAIL: check_rpm failed with rpmbuild installed: $built"
		test_fail
	fi
fi

# ── Dry run: the changes draft and the compact announcement output ────
if ! bash "$script" --dry-run > "$outdir/dryrun.log" 2>&1; then
	error_log "FAIL: prep-release.sh --dry-run failed:"
	sed 's/^/   /' "$outdir/dryrun.log"
	test_fail
fi

# The similar csets are combined into single bullets, with the number
# of csets stated.  The dry run output indents the draft with spaces:
for expected in \
	"Remove 11 dead functions found via coverage analysis, in 2 csets" \
	"Add enumerator search test, in 2 csets" \
	"Add test" \
	"  - Add tests" \
	"Sync with libbpf-1.1" \
	"  - Sync with libbpf-1.5"
do
	if ! grep -q -- "$expected" "$outdir/dryrun.log"; then
		error_log "FAIL: '$expected' not in the dry run output:"
		grep -n "dead functions\|enumerator\|Sync with\|Add test" "$outdir/dryrun.log"
		test_fail
	fi
done
info_log "   dry run draft combines the 6+5 dead functions csets and the others: ok"

# Version numbers must not have been added up into a bogus bullet:
if grep -qE 'libbpf-1\.(6|11)' "$outdir/dryrun.log"; then
	error_log "FAIL: libbpf versions were added up as if they were counts"
	test_fail
fi
info_log "   dry run draft leaves version numbers alone: ok"

# The announcement is not repeated in full after the changes draft, its
# changes-vX.Y tail is elided:
if ! grep -q "followed by the changes-v1.31 contents, as shown above" "$outdir/dryrun.log"; then
	error_log "FAIL: the dry run announcement was not compacted"
	test_fail
fi
nr_announce=$(sed -n '/would write .*announce-v1.31/,$p' "$outdir/dryrun.log" |
	      grep -c "Add enumerator search test")
if [ "$nr_announce" -ne 0 ]; then
	error_log "FAIL: the changes draft is still repeated in the dry run announcement"
	test_fail
fi
info_log "   dry run announcement elides the changes-vX.Y contents: ok"

# The %changelog entry in the spec diff is collapsed to a taste plus a
# pointer to the changes draft:
if ! grep -q "more lines: the first line of each bullet in changes-v1.31, shown above" "$outdir/dryrun.log"; then
	error_log "FAIL: the spec %changelog entry was not collapsed in the dry run"
	test_fail
fi
# 'Sync with libbpf-1.1' is beyond the collapsed taste: it shows up
# once in the NEWS diff and once in the changes draft, not again in
# the spec %changelog diff:
if [ "$(grep -c "Sync with libbpf-1.1" "$outdir/dryrun.log")" -ne 2 ]; then
	error_log "FAIL: the changes draft is repeated in the dry run spec %changelog"
	test_fail
fi
info_log "   dry run spec diff collapses the %changelog entry: ok"

# The subject is built from the areas touched, in the style of the
# previous announcements: related areas grouped (BTF encoder and BTF
# loader are just "BTF", regression tests and CI are one item, coming
# last, the CI area is in the draft), the unworthy ones out (the pahole
# area itself, man pages, the Other catchall and the minor utilities),
# and under 80 characters.  The draft has sections for all of the
# unworthy ones, so this is not vacuously true:
for section in "pahole:" "Man pages:" "Other:" "scncopy:" "btfdiff:" "pfunct:"; do
	if ! grep -q "^    $section\$" "$outdir/dryrun.log"; then
		error_log "FAIL: the '$section' section is not in the dry run draft"
		test_fail
	fi
done
subject=$(sed -n 's/^    Subject: //p' "$outdir/dryrun.log" | head -1)
if [ "$subject" != "ANNOUNCE: pahole v1.31 (Regression tests, BTF, DWARF loader, Library, and more)" ]; then
	error_log "FAIL: unexpected dry run announcement subject: '$subject'"
	test_fail
fi
if [ "${#subject}" -ge 80 ]; then
	error_log "FAIL: the dry run subject is ${#subject} characters long"
	test_fail
fi
info_log "   dry run subject is short, grouped, unworthy areas out: ok"

# The Highlights section was pre-seeded with the noticed milestones,
# here just the regression tests growth:
if ! grep -q '^    Highlights:$' "$outdir/dryrun.log" ||
   ! grep -q "^    - Regression tests: from 2 in v1.30 to 8\$" "$outdir/dryrun.log"; then
	error_log "FAIL: the pre-seeded Highlights section is not in the dry run draft"
	test_fail
fi
info_log "   the Highlights section is pre-seeded in the draft: ok"

# And the rpm build check was announced as skipped when rpmbuild is
# not installed:
if ! command -v rpmbuild > /dev/null 2>&1; then
	if ! grep -q "rpmbuild not found, the rpm build will not be checked" "$outdir/dryrun.log"; then
		error_log "FAIL: no warning about the missing rpmbuild in the dry run"
		test_fail
	fi
	info_log "   the missing rpmbuild warning is in the dry run: ok"
fi

# ── Without a fuzzy grep it is warn-only, the draft is left as is ──────
if ! FUZZY_GREP=there-is-no-such-ugrep bash "$script" --dry-run \
		> "$outdir/nogrep.log" 2>&1; then
	error_log "FAIL: prep-release.sh --dry-run failed without ugrep:"
	sed 's/^/   /' "$outdir/nogrep.log"
	test_fail
fi
if ! grep -q "there-is-no-such-ugrep not found, similar csets will not be combined" "$outdir/nogrep.log"; then
	error_log "FAIL: no warning about the missing fuzzy grep"
	test_fail
fi
if grep -q "Remove 11 dead functions" "$outdir/nogrep.log"; then
	error_log "FAIL: the csets were combined even without a fuzzy grep"
	test_fail
fi
if ! grep -q -- "- Remove 6 dead functions found via coverage analysis" "$outdir/nogrep.log" ||
   ! grep -q -- "- Remove 5 dead functions found via coverage analysis" "$outdir/nogrep.log"; then
	error_log "FAIL: the draft without a fuzzy grep is missing the individual bullets"
	test_fail
fi
info_log "   missing fuzzy grep is warn-only, draft left ungrouped: ok"

# ── Real run, stopping before the commit, tag and tarballs ────────────
# The maintainer's edit of the draft is simulated with a $EDITOR that
# adds the milestones that only he knows about right after the ones
# pre-seeded by the script in the Highlights section:
cat > "$outdir/mark-editor" << 'EOF'
#!/bin/sh
# Adds the maintainer's milestones to the Highlights section of the
# changes draft, the only file prep-release.sh edits that is named
# changes-vX.Y:
case $1 in
changes-*)
	awk '/^- Regression tests: from/ {
		print
		print "- Support for dwz files, most distro userspace DWARF is now supported"
		print "- Support for more of the kernel CONFIG_DEBUG_INFO_DWARF options"
		next
	}
	{ print }' "$1" > "$1.new" && mv "$1.new" "$1"
	;;
esac
exit 0
EOF
chmod +x "$outdir/mark-editor"
export EDITOR="sh $outdir/mark-editor"
if ! bash "$script" --yes --no-commit --no-tarball \
		--no-build-check --no-tag > "$outdir/run.log" 2>&1; then
	error_log "FAIL: prep-release.sh exited with an error:"
	sed 's/^/   /' "$outdir/run.log"
	test_fail
fi

# The changes draft has the combined bullets:
if ! grep -q "^- Remove 11 dead functions found via coverage analysis, in 2 csets$" changes-v1.31; then
	error_log "FAIL: the 6+5 dead functions csets were not combined in changes-v1.31"
	test_fail
fi
if ! grep -q "^- Add enumerator search test, in 2 csets$" changes-v1.31; then
	error_log "FAIL: the identical 'Add enumerator search test' csets were not combined"
	test_fail
fi
info_log "   changes-v1.31 has the combined bullets: ok"

# NEWS keeps listing every cset, nothing was squashed:
if [ "$(grep -c "dead functions found via coverage analysis" NEWS)" -ne 2 ] ||
   [ "$(grep -c "Add enumerator search test" NEWS)" -ne 2 ]; then
	error_log "FAIL: NEWS stopped listing every cset"
	test_fail
fi
info_log "   NEWS still lists every cset: ok"

# The related, not number-mergeable csets are sub items in the draft,
# and they are dropped from the spec %changelog entry:
if ! grep -A1 "^- Add test$" changes-v1.31 | grep -q "^  - Add tests$"; then
	error_log "FAIL: 'Add tests' is not a sub item of 'Add test'"
	test_fail
fi
if grep -q "^  - Add tests$" rpm/SPECS/dwarves.spec; then
	error_log "FAIL: sub items leaked into the spec %changelog entry"
	test_fail
fi
info_log "   related csets are sub items, dropped from the %changelog: ok"

# The spec %changelog entry got the combined bullet:
if ! grep -q "^- Remove 11 dead functions found via coverage analysis, in 2 csets$" rpm/SPECS/dwarves.spec; then
	error_log "FAIL: the combined bullet is not in the spec %changelog entry"
	test_fail
fi

# The announcement ends with the changes-vX.Y contents:
if ! grep -q "Remove 11 dead functions found via coverage analysis, in 2 csets" announce-v1.31.txt; then
	error_log "FAIL: the combined bullet is not in the announcement"
	test_fail
fi

# And the run output is compact: the changes draft is not printed in
# full, the announcement print elides its changes-vX.Y tail:
if ! grep -q "followed by the changes-v1.31 contents, as shown above" "$outdir/run.log"; then
	error_log "FAIL: the announcement was not compacted in the run output"
	test_fail
fi
if grep -q "Add enumerator search test" "$outdir/run.log"; then
	error_log "FAIL: the changes draft is still printed in the run output"
	test_fail
fi
info_log "   run output is compact, the announcement elides the changes list: ok"

# The announcement CC list comes from the release range: the people that
# authored, reviewed or tested the csets, then the distro packagers,
# then the mailing lists last, not the CC list of every cset ever
# released:
tolist=$(sed -n 's/^  git send-email --to="\([^"]*\)".*/\1/p' "$outdir/run.log")
if [ -z "$tolist" ]; then
	error_log "FAIL: no send-email --to hint with the CC list in the run output"
	test_fail
fi
for person in \
	"Second Author <second@example.com>" \
	"A Reviewer <a.reviewer@example.com>" \
	"A Tester <a.tester@example.com>" \
	"Distro Packer <packer@example.com>"
do
	if ! printf '%s' "$tolist" | grep -qF -- "$person"; then
		error_log "FAIL: '$person' is not in the announcement CC list"
		test_fail
	fi
done
# The sender is not CCed, neither with the announcement's From: address
# nor with the git configured identity that authored the csets, and a
# person that shows up just in a Cc: trailer is not CCed either:
if printf '%s' "$tolist" | grep -qiF "sender@example.com" ||
   printf '%s' "$tolist" | grep -qiF "test@example.com" ||
   printf '%s' "$tolist" | grep -qF "Only Cced"; then
	error_log "FAIL: the sender or a Cc: only person made it to the CC list"
	test_fail
fi
# And the same person is not in there twice:
if [ "$(printf '%s' "$tolist" | grep -oiE 'second@example\.com' | wc -l)" -ne 1 ]; then
	error_log "FAIL: second@example.com is in the CC list more than once"
	test_fail
fi
# The kept authors come newest cset first:
if [ "$(printf '%s' "$tolist" | awk -F', ' '{print $1}')" != "Second Author <second@example.com>" ]; then
	error_log "FAIL: the CC list doesn't start with the newest kept cset author"
	test_fail
fi
if ! printf '%s' "$tolist" |
   grep -qF "Distro Packer <packer@example.com>, dwarves@vger.kernel.org, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, bpf@vger.kernel.org"
then
	error_log "FAIL: the mailing lists are not last in the CC list:"
	printf '%s\n' "$tolist"
	test_fail
fi
info_log "   CC list has the range authors, reviewers, testers, packagers, no sender, lists last: ok"

# The announcement itself carries the folded To: header:
if ! grep -q "A Reviewer <a.reviewer@example.com>" announce-v1.31.txt; then
	error_log "FAIL: no To: header with the CC list in the announcement"
	test_fail
fi
info_log "   the announcement carries the folded To: header: ok"

# The Highlights section, pre-seeded with the regression tests growth
# and extended by the maintainer with the dwz files support milestone,
# drives the announcement subject and intro, which stays under 80
# characters; the statements are spelled out in the intro, the section
# stays at the top of the announcement body and its bullets go to the
# spec %changelog entry:
subject=$(sed -n 's/^Subject: //p' announce-v1.31.txt)
if [ "$subject" != "ANNOUNCE: pahole v1.31 (Support for dwz files, Regression tests, BTF, and more)" ]; then
	error_log "FAIL: the Highlights are not in the announcement subject: '$subject'"
	test_fail
fi
if [ "${#subject}" -ge 80 ]; then
	error_log "FAIL: the announcement subject is ${#subject} characters long"
	test_fail
fi
if [ "$(grep -c '^Highlights:$' announce-v1.31.txt)" -ne 1 ]; then
	error_log "FAIL: the announcement body doesn't have exactly one Highlights section"
	test_fail
fi
introtxt=$(sed -n '/release of pahole is out/,/^$/p' announce-v1.31.txt | tr '\n' ' ')
for expected in \
	"Most notably, Support for dwz files, most distro userspace DWARF is now supported" \
	"Support for more of the kernel CONFIG_DEBUG_INFO_DWARF options; Regression tests: from 2 in v1.30 to 8." \
	"with changes in the BTF, DWARF loader, Library, Regression tests and CI areas"
do
	case $introtxt in
	*"$expected"*)	;;
	*)	error_log "FAIL: '$expected' not in the announcement intro"
		test_fail ;;
	esac
done
for hl in \
	"^- Regression tests: from 2 in v1.30 to 8\$" \
	"^- Support for dwz files, most distro userspace DWARF is now supported\$"
do
	if ! grep -q "$hl" rpm/SPECS/dwarves.spec; then
		error_log "FAIL: the Highlights bullet is not in the spec %changelog entry: $hl"
		test_fail
	fi
done
info_log "   the Highlights drive the subject and emphasize the intro: ok"

rm -rf "$fixture" "$outdir/funcs.sh" "$outdir/rpmbuild"

test_pass
