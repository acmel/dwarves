#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# prep-release.sh - prepare a new pahole/dwarves release, up to and
#		    including the text of the announcement to be sent to
#		    the mailing lists, which is left as a manual step.
#
# What it does, in order:
#
#   1. Checks that everything that has to be in MANIFEST is there, as
#      the tarballs are built from it and won't even configure otherwise
#   2. Bumps DWARVES_{MAJOR,MINOR}_VERSION and the "vX.Y-tarball-"
#      version used when building from a tarball, in CMakeLists.txt
#   3. Adds the new changes-vX.Y file to MANIFEST
#   4. Prepends the list of commits since the previous release to NEWS
#   5. Creates changes-vX.Y, opening $EDITOR on a draft built from the
#      commit subjects, grouped by area (pahole:, btf_encoder:, ...),
#      with very similar csets, such as "Remove 6 dead functions found
#      via coverage analysis" and "Remove 5 dead functions found via
#      coverage analysis", combined into a single bullet ("Remove 11
#      dead functions found via coverage analysis, in 2 csets"): they
#      were published as separate csets, so NEWS keeps listing all of
#      them, this is just for the release notes.  Finding them uses
#      ugrep's fuzzy matching, see FUZZY_GREP below: warn-only, when it
#      is not available the draft just lists every cset separately.
#      A "Highlights:" section is pre-seeded at the top with the
#      milestones that are programmatically noticeable: a dramatic
#      growth in the number of regression tests and new development
#      themes, words appearing in the subject of several csets and in
#      none of the previous release notes, e.g. the coverage analysis
#      work; the maintainer rewords or drops them and adds the ones
#      that only he knows about, e.g. dwz files support.
#   6. Bumps Version: and %doc changes-vX.Y in rpm/SPECS/dwarves.spec and
#      adds a %changelog entry derived from changes-vX.Y
#   7. Commits all of the above as "Prep X.Y"
#   8. Builds dwarves-X.Y.tar{,.xz,.bz2}, checks that the tarball builds
#      and that pahole --version in it reports X.Y, checks that the rpm
#      for it builds, then signs the uncompressed one, producing
#      dwarves-X.Y.tar.sign
#   9. Creates the signed vX.Y tag, using changes-vX.Y as its message
#  10. Writes the announcement to announce-vX.Y.txt, addressed to the
#      people that authored, reviewed or tested the csets in the range
#      since the previous release, to the distro packagers listed in
#      PKG-MAINTAINERS and to the mailing lists.  Its subject and intro
#      paragraph are built from the optional "Highlights:" section of
#      changes-vX.Y, one bullet per release milestone, falling back to
#      the areas touched, kept under 80 characters, in the style of the
#      previous announcements
#
# It stops there: pushing the branch and the tag, uploading the tarballs
# to fedorapeople.org and sending the announcement are up to the
# maintainer.  The commands to do all of that are printed at the end,
# use --push/--upload to have them performed here.
#
# The usual workflow is to first look at what is being released:
#
#   $ scripts/prep-release.sh --dry-run
#
# and then, on the master or next branch, with a clean working tree:
#
#   $ scripts/prep-release.sh
#
# which stops in $EDITOR three times: on the changes-vX.Y draft (edit it
# into the release notes, it is also the tag message and the body of the
# announcement), on the tag message (to check the collected review tags)
# and on the announcement (to fix up the subject and the intro paragraph).

set -eu

progname=${0##*/}

# ── Release boilerplate ────────────────────────────────────────────────
TARBALL_URL_BASE=${TARBALL_URL_BASE:-https://fedorapeople.org/~acme/dwarves}
UPLOAD_DEST=${UPLOAD_DEST:-acme@fedorapeople.org:public_html/dwarves}
GIT_URL=${GIT_URL:-https://git.kernel.org/pub/scm/devel/pahole/pahole.git}
MIRROR_URL=${MIRROR_URL:-https://github.com/acmel/dwarves.git}
PUSH_REMOTE=${PUSH_REMOTE:-korg}
MIRROR_REMOTE=${MIRROR_REMOTE:-github}
FROM=${FROM:-Arnaldo Carvalho de Melo <acme@kernel.org>}

# The mailing lists, they come last, as in the previous announcements,
# right after the distro packagers in $PKG_MAINTAINERS.
read -r -d '' MAILING_LISTS <<'EOF' || true
dwarves@vger.kernel.org
Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
bpf@vger.kernel.org
EOF

PKG_MAINTAINERS=${PKG_MAINTAINERS:-PKG-MAINTAINERS}

# ── Options ────────────────────────────────────────────────────────────
version=
dry_run=
assume_yes=
no_edit=
tarball_dir=.
key=
announce_file=
maintainer=
subject=
link=
remote=$PUSH_REMOTE
mirror_remote=$MIRROR_REMOTE
do_commit=1
do_tarball=1
do_build_check=1
rpm_check=
do_tag=1
do_push=
do_upload=
force=
declare -a trailers=()

usage() {
	cat <<EOF
Usage: $progname [OPTIONS] [X.Y]

  X.Y			version to release, defaults to the current version
			in CMakeLists.txt with the minor number bumped

Options:
  -n, --dry-run		show what would be done, change nothing
  -y, --yes		don't ask for confirmation before starting
  -e, --no-edit		don't open \$EDITOR on the changes file, on the tag
			message nor on the announcement
  -d, --tarball-dir DIR	where to put the tarballs (default: .)
  -k, --key KEYID	gpg key to sign the tarball and the tag with
			(default: git's user.signingkey, else gpg's default)
  -a, --announce FILE	where to write the announcement
			(default: ./announce-vX.Y.txt)
  -m, --maintainer ID	"Name <email>" used in the spec changelog entry and
			in the tag Signed-off-by: (default: git's user.name
			and user.email)
  -s, --subject SUBJ	subject for the announcement (default: generated
			from the areas touched in changes-vX.Y)
  -l, --link URL	add a Link: tag with URL to the "Prep X.Y" commit
  -r, --remote REMOTE	where to push with --push (default: $PUSH_REMOTE)
  -t, --trailer TAG	add TAG (e.g. "Tested-by: Someone <some@one>") to the
			"Prep X.Y" commit and to the tag message, can be
			used multiple times
      --push		push the branch and the vX.Y tag to REMOTE
      --upload		scp the tarballs and the signature to UPLOAD_DEST
			(default: $UPLOAD_DEST)
      --no-commit	stop before creating the "Prep X.Y" commit
      --no-tarball	don't build nor sign the tarballs
      --no-build-check	don't configure and build the tarball to check that
			it builds, that 'pahole --version' reports X.Y and
			that the rpm for it builds
      --no-tag		don't create the signed vX.Y tag
      --force		go ahead even if not on the master/next branch
  -h, --help		show this help

Environment variables to override the release boilerplate:
  TARBALL_URL_BASE, UPLOAD_DEST, GIT_URL, MIRROR_URL, PUSH_REMOTE,
  MIRROR_REMOTE, FROM, PKG_MAINTAINERS, FUZZY_GREP
EOF
}

die() {
	printf 'Error: %s\n' "$*" >&2
	exit 1
}

warn() {
	printf 'Warning: %s\n' "$*" >&2
}

info() {
	printf '%s\n' "$*"
}

step() {
	printf '\n== %s\n' "$*"
}

while [ $# -gt 0 ]; do
	case "$1" in
	-n|--dry-run)		dry_run=1 ;;
	-y|--yes)		assume_yes=1 ;;
	-e|--no-edit)		no_edit=1 ;;
	-d|--tarball-dir)	tarball_dir=$2 ; shift ;;
	-k|--key)		key=$2 ; shift ;;
	-a|--announce)		announce_file=$2 ; shift ;;
	-m|--maintainer)	maintainer=$2 ; shift ;;
	-s|--subject)		subject=$2 ; shift ;;
	-l|--link)		link=$2 ; shift ;;
	-r|--remote)		remote=$2 ; shift ;;
	-t|--trailer)		trailers+=("$2") ; shift ;;
	--push)			do_push=1 ;;
	--upload)		do_upload=1 ;;
	--no-commit)		do_commit= ;;
	--no-tarball)		do_tarball= ;;
	--no-build-check)	do_build_check= ;;
	--no-tag)		do_tag= ;;
	--force)		force=1 ;;
	-h|--help)		usage ; exit 0 ;;
	-*)			usage >&2 ; die "unknown option '$1'" ;;
	*)
		[ -z "$version" ] || die "too many arguments, version already set to '$version'"
		version=$1
		;;
	esac
	shift
done

# ── Preflight ──────────────────────────────────────────────────────────
git rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
	die "not inside a git repository"

cd "$(git rev-parse --show-toplevel)"

for f in MANIFEST CMakeLists.txt rpm/SPECS/dwarves.spec scripts/make-tarball.sh NEWS; do
	[ -f "$f" ] || die "$f not found, run this from the source root"
done

# ── Helpers ────────────────────────────────────────────────────────────
# The version lives in these CMakeLists.txt lines:
#
#   # add_definitions(-D_GNU_SOURCE -DDWARVES_VERSION="v1.31")
#   add_definitions(-D_GNU_SOURCE -DDWARVES_MAJOR_VERSION=1)
#   add_definitions(-D_GNU_SOURCE -DDWARVES_MINOR_VERSION=31)
cmake_field_from() { # $1 = CMakeLists.txt to look at, $2 = MAJOR|MINOR
	sed -n "s/^.*DWARVES_${2}_VERSION=\([0-9][0-9]*\).*\$/\1/p" "$1" | sed -n 1p
}

cmake_version_field() { # $1 = MAJOR|MINOR
	cmake_field_from CMakeLists.txt "$1"
}

git_editor() {
	local e=${VISUAL:-${EDITOR:-}}
	[ -n "$e" ] || e=$(git var GIT_EDITOR 2>/dev/null) || e=
	printf '%s' "${e:-vi}"
}

edit_file() {
	local file=$1 editor
	[ -n "$no_edit" ] && return 0
	editor=$(git_editor)
	info "  (slipping into $editor on $file, save and exit to continue)"
	if [ -r /dev/tty ] && [ -w /dev/tty ] &&
	   { : < /dev/tty; } 2>/dev/null; then
		$editor "$file" < /dev/tty > /dev/tty 2>&1 ||
			die "$editor failed on $file"
	else
		# No controlling terminal to put the editor on, e.g. in a
		# CI job or under a test harness: it inherits whatever
		# stdin/stdout we were given.
		$editor "$file" || die "$editor failed on $file"
	fi
}

# Wrap $1 at 76 columns, first line indented with a tab, continuation
# lines starting at column 0, as in the release announcements.
wrap_tagged() {
	if command -v fmt >/dev/null; then
		printf '\t%s\n' "$1" | fmt -t -w 76
	else
		printf '\t%s\n' "$1"
	fi
}

# Is $1 in MANIFEST, either by name ("pahole.c"), as a glob
# ("tests/*.sh") or inside one of the directories listed there
# ("scripts/", "lib/bpf/", "lib/include/bpf")?
in_manifest() {
	local file=$1 dir entry
	grep -qxF "$file" MANIFEST && return 0
	while IFS= read -r entry; do
		[ -n "$entry" ] || continue
		# $entry is unquoted on purpose: MANIFEST entries such as
		# "tests/*.sh" are globs.
		# shellcheck disable=SC2053
		if [[ $file == $entry ]]; then
			return 0
		fi
	done < MANIFEST
	while :; do
		dir=${file%/*}
		[ "$dir" != "$file" ] || return 1
		for entry in "$dir/" "$dir"; do
			grep -qxF "$entry" MANIFEST && return 0
		done
		file=$dir
	done
}

# Everything that has to be in MANIFEST for the tarballs to even
# configure: the sources, the headers and the man pages git knows about.
# Not being fatal here means shipping a tarball that doesn't build, as
# MANIFEST is what scripts/make-tarball.sh packs.
check_manifest() {
	local missing
	missing=$(git ls-files '*.c' '*.h' 'man-pages/*' |
		  while IFS= read -r f; do
			  in_manifest "$f" || printf '%s\n' "$f"
		  done)
	[ -z "$missing" ] && return 0
	printf 'Error: these files are in git but not in MANIFEST, so they\n' >&2
	printf '       would be missing from the tarballs, which then do not build:\n\n' >&2
	# $missing is a list of filenames, one per line: let it be split.
	# shellcheck disable=SC2086
	printf '  %s\n' $missing >&2
	printf '\nAdd them to MANIFEST, commit, and run this again.\n' >&2
	return 1
}

# Dedup "Name <email>" or bare "email" lines by email address, case
# insensitively, keeping the first occurrence, as the same person shows
# up with differently spelled names in different commits and trailers.
# $1 and $2, when set, are email addresses of the announcement sender,
# dropped altogether: one doesn't get CCed on the announcement one
# sends, even when the csets are authored with another of one's
# addresses.
dedup_emails() {
	awk -v skip1="$1" -v skip2="$2" '
	{
		email = $0
		sub(/.*</, "", email)
		sub(/>.*$/, "", email)
		if (email == "")
			email = $0
		key = tolower(email)
		if (key == tolower(skip1) || key == tolower(skip2))
			next
		if (!(key in seen)) {
			seen[key] = 1
			print
		}
	}'
}

# The announcement recipients: the people that authored, reviewed or
# tested patches in the range being announced, then the distro
# packagers listed in $PKG_MAINTAINERS, then the mailing lists, without
# duplicates, in that order, minus the sender, whose addresses arrive
# as $2 and $3: the announcement goes out as $FROM and the csets are
# mostly authored with the git configured identity, both are the sender
# and neither gets CCed.
#
# Not the union of the CC list of every cset ever released, which the
# last announcement's had accumulated: some mailing lists refuse long
# CC lines, so this is limited to the people involved with the csets in
# this release range.  People that show up just in a Cc: trailer are
# not included, the review tags in the csets and in the release notes
# credit everybody that contributed.
build_recipients() {
	local range=$1 skip1=$2 skip2=$3

	{
		git log --no-merges --format='%an <%ae>' "$range"
		git log --no-merges --format='%b' "$range" |
			grep -E '^(Reviewed-by|Tested-by):' |
			sed -e 's/^[^:]*:[[:space:]]*//' \
			    -e 's/[[:space:]]*#.*$//'
		if [ -f "$PKG_MAINTAINERS" ]; then
			sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
			    "$PKG_MAINTAINERS" | grep -v '^$' ||
				warn "no distro packagers in $PKG_MAINTAINERS"
		else
			warn "$PKG_MAINTAINERS not found, no distro packager will be CCed"
		fi
		printf '%s\n' "$MAILING_LISTS"
	} | dedup_emails "$skip1" "$skip2"
}

# Extract $1, configure it, build it and check that the pahole in it
# reports the version being released.  This is the last chance to catch
# a file missing from MANIFEST, which makes the tarball not even
# configure, or a version that wasn't bumped everywhere in
# CMakeLists.txt: DWARVES_{MAJOR,MINOR}_VERSION for '--version' and the
# "vX.Y-tarball-g<sha>" string built into tarball builds for
# '--devel_version'.
verify_tarball() {
	local tarball=$1 dir=$tmpdir/tarball-check src reported expected
	local log jobs

	command -v cmake >/dev/null ||
		die "cmake not found, install it or use --no-build-check"

	mkdir -p "$dir"
	tar xf "$tarball" -C "$dir" || die "couldn't extract $tarball"
	src=$dir/dwarves-$version

	for f in "$changes_file" HEAD CMakeLists.txt; do
		[ -f "$src/$f" ] || die "$tarball doesn't contain $f"
	done

	jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 4)

	log=$tmpdir/cmake.log
	if ! cmake -DCMAKE_BUILD_TYPE=Release -B "$src/build" -S "$src" \
			>"$log" 2>&1; then
		sed 's/^/    /' "$log" >&2
		die "couldn't configure the source in $tarball, see above"
	fi
	grep -E '^-- Version:' "$log" | sed 's/^/  /'

	log=$tmpdir/make.log
	if ! make -j"$jobs" -C "$src/build" >"$log" 2>&1; then
		tail -20 "$log" | sed 's/^/    /' >&2
		die "couldn't build the source in $tarball, see above"
	fi

	for opt in --version --devel_version --numeric_version; do
		reported=$("$src/build/pahole" "$opt" | head -1)
		case $opt in
		--version)	expected="v$version" ;;
		--devel_version) expected="v$version-tarball-g" ;;
		--numeric_version) expected="${version%%.*}${version#*.}" ;;
		esac
		case $reported in
		"$expected"*)	info "  pahole $opt: $reported" ;;
		*)	die "the pahole built from $tarball reports '$reported' for $opt, expected $expected*" ;;
		esac
	done
}

# Build the rpm for the release being prepared, with the spec file
# already updated for it and the tarball just built: checks that the
# spec file points at the right %doc changes-vX.Y and that the sources
# in the tarball build the way distro users get them.
check_rpm() {
	local spec=$1 topdir=$tmpdir/rpmbuild rpm subdir reported sourcedir
	local log

	command -v rpmbuild >/dev/null ||
		{ warn "rpmbuild not found, the rpm build will not be checked"; return 0; }

	for subdir in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS; do
		mkdir -p "$topdir/$subdir" ||
			die "couldn't create the rpm build tree in $topdir"
	done

	# The tarball is where the release was built, _sourcedir, rpmbuild
	# picks it up by the basename in the spec's Source: line, which
	# has to be an absolute path, as %setup chdirs around:
	sourcedir=$(cd "$tarball_dir" && pwd) ||
		die "couldn't find the tarball directory $tarball_dir"
	log=$topdir/build.log
	if ! rpmbuild --define "_topdir $topdir" \
		      --define "_sourcedir $sourcedir" \
		      -bb "$spec" > "$log" 2>&1; then
		tail -20 "$log" | sed 's/^/    /' >&2
		die "the rpm build failed, see above"
	fi

	info "  rpm built:"
	for rpm in "$topdir"/RPMS/*/*.rpm; do
		[ -e "$rpm" ] || continue
		info "  ${rpm##*/}"
	done

	rpm=$(printf '%s\n' "$topdir"/RPMS/*/dwarves-"$version"-*.rpm | head -1)
	[ -e "$rpm" ] || die "the rpm build produced no dwarves-$version rpm"
	reported=$(rpm -qp --qf '%{NAME} %{VERSION}\n' "$rpm") ||
		die "couldn't query the built $rpm"
	[ "$reported" = "dwarves $version" ] ||
		die "the built $rpm reports '$reported', expected 'dwarves $version'"
	info "  rpm version check: $reported"
}

# Print $1 as a changelog/notes bullet, wrapping it at 76 columns and
# indenting the continuation lines with $2.
wrap_bullet() {
	local text=$1 indent=$2 first=1 line
	# Sub items for related csets, produced when grouping similar
	# csets, are ready as is, they continue the bullet above them.
	if [[ $text == '  - '* ]]; then
		printf '%s\n' "$text"
		return
	fi
	while IFS= read -r line; do
		if [ -n "$first" ]; then
			printf -- '- %s\n' "$line"
			first=
		else
			printf '%s%s\n' "$indent" "$line"
		fi
	done <<< "$(fold -s -w 74 <<< "$text" | sed 's/[[:space:]]*$//')"
}

# Join the areas as "a, b and c".
# Compose the parenthesized part of the announcement subject from the
# candidate items, in order, taking as many as fit in a subject under 80
# characters, as some mailing lists and archivers truncate long
# subjects, adding "and more" when items were left out.  An item with a
# lead phrase, ending at the first comma, colon or semicolon,
# contributes just that lead to the subject, the announcement intro
# carries the whole statement.  Items that don't fit are skipped, the
# smaller ones that follow may still fit.
subject_items() {
	local prefix="ANNOUNCE: pahole $new_tag ("
	local phrase= item probe lead
	local -i nr_added=0
	local marker=", and more"

	for item in "$@"; do
		# The subject wants short items: an item with a lead
		# phrase, ending at the first comma, colon or semicolon,
		# contributes just that lead, the announcement intro
		# carries the whole statement:
		lead=${item%%[,;:]*}
		if [ "$lead" = "$item" ]; then
			lead=$item
		else
			lead=${lead%"${lead##*[! ]}"}
		fi
		if [ -z "$lead" ]; then
			continue
		fi
		if [ -n "$phrase" ]; then probe="$phrase, $lead"; else probe=$lead; fi
		if [ "$(( ${#prefix} + ${#probe} + 1 ))" -lt 80 ]; then
			phrase=$probe
			((++nr_added))
			continue
		fi
		# Doesn't fit, skip it, the smaller ones that follow may
		# still fit, what was left out is acknowledged with "and
		# more":
	done

	# "and more" when items were left out, dropping items already
	# taken from the end when that is what it takes to fit the
	# marker:
	if [ "$nr_added" -lt "$#" ]; then
		while [ -n "$phrase" ] &&
		      [ "$(( ${#prefix} + ${#phrase} + ${#marker} + 1 ))" -ge 80 ]
		do
			case $phrase in
			*,*)	phrase=${phrase%, *} ;;
			*)	phrase= ;;
			esac
			((nr_added--))
		done
		if [ -n "$phrase" ]; then
			phrase="$phrase$marker"
		fi
	fi
	printf '%s' "$phrase"
}

# ── Versions ───────────────────────────────────────────────────────────
prev_version=$(cmake_version_field MAJOR).$(cmake_version_field MINOR)
[ "$prev_version" != . ] || die "couldn't get the current version from CMakeLists.txt"

prev_tag=v$prev_version
git rev-parse --verify -q "$prev_tag" >/dev/null ||
	die "tag $prev_tag not found, can't list the commits since the previous release"

git merge-base --is-ancestor "$prev_tag" HEAD ||
	die "$prev_tag is not an ancestor of HEAD, is this the branch to release from?"

if [ -z "$version" ]; then
	version=${prev_version%.*}.$(( ${prev_version#*.} + 1 ))
fi

case $version in
[0-9]*.[0-9]*)	;;
*)		die "version '$version' doesn't look like X.Y" ;;
esac

new_tag=v$version
changes_file=changes-$new_tag

git rev-parse --verify -q "$new_tag" >/dev/null &&
	die "tag $new_tag already exists, use another version or delete it first"

[ ! -e "$changes_file" ] || [ -n "$dry_run" ] ||
	die "$changes_file already exists, remove it or use another version"

grep -qxF "changes-$prev_tag" MANIFEST ||
	die "MANIFEST doesn't list changes-$prev_tag, was the previous release prepped here?"

# The tarballs are built from MANIFEST, so check that now, before
# changing anything, as a tarball missing a source file doesn't build.
check_manifest || exit 1

[ -n "$announce_file" ] || announce_file=./announce-$new_tag.txt

# The announcement goes to the people that authored, reviewed or tested
# patches since $prev_tag, to the distro packagers listed in
# $PKG_MAINTAINERS and to the mailing lists, without the sender: it
# goes out as $FROM and the csets are mostly authored with the git
# configured identity, both are the sender and neither gets CCed on
# one's own announcement.
[ -n "$maintainer" ] || maintainer="$(git config user.name) <$(git config user.email)>"
from_email=${FROM##*<} ; from_email=${from_email%>}
git_email=${maintainer##*<} ; git_email=${git_email%>}
RECIPIENTS=$(build_recipients "$prev_tag..HEAD" "$from_email" "$git_email")

# ── Identity and environment ───────────────────────────────────────────

[ -n "$key" ] || key=$(git config user.signingkey || true)

gpg_program=$(git config gpg.program || true)
[ -n "$gpg_program" ] || gpg_program=$(command -v gpg2 || command -v gpg) ||
	die "gpg not found, install it or set git config gpg.program"

command -v fmt >/dev/null || warn "fmt not found, long lines will not be rewrapped"

# The rpm build check: when rpmbuild is not available, warn once here
# and have check_rpm skip it, the release can still be prepared.
if command -v rpmbuild >/dev/null; then
	rpm_check=1
else
	warn "rpmbuild not found, the rpm build will not be checked"
fi

# Combining very similar csets in the changes draft, e.g. "Remove 6 dead
# functions found via coverage analysis" and "Remove 5 dead functions
# found via coverage analysis", uses the fuzzy matching of ugrep, an
# improved, widely available grep that can also do approximate matching
# within an edit distance (-Z), which plain grep can't.  Not a hard
# requirement: when it is not available the draft is left with every
# cset listed separately, after a warning.
FUZZY_GREP=${FUZZY_GREP:-ugrep}
fuzzy_grep_ok=
if command -v "$FUZZY_GREP" >/dev/null; then
	# Check that it really is a grep that does fuzzy matching, as
	# plain grep, for instance, doesn't know about -Z:
	if printf 'Remove 6 dead functions found via coverage analysis\n' |
	   "$FUZZY_GREP" -Z1 -F -q \
	   'Remove 5 dead functions found via coverage analysis' 2>/dev/null
	then
		fuzzy_grep_ok=1
	else
		warn "$FUZZY_GREP doesn't do fuzzy matching (-Z), point FUZZY_GREP
at ugrep to have similar csets combined in $changes_file"
	fi
else
	warn "$FUZZY_GREP not found, similar csets will not be combined in
$changes_file, install it (dnf/apt/zypper/apk install ugrep or brew
install ugrep) or point FUZZY_GREP at a compatible grep"
fi

branch=$(git symbolic-ref --short HEAD 2>/dev/null || printf '(detached)')
case $branch in
master|next)	;;
*)
	if [ -z "$force" ] && [ -z "$dry_run" ]; then
		die "on branch '$branch', releases are cut from 'master' or 'next' (--force to override)"
	fi
	warn "on branch '$branch', releases are usually cut from 'master' or 'next'"
	;;
esac

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
	die "the working tree has changes to tracked files, commit or stash them first"
fi

# ── What goes in this release ──────────────────────────────────────────
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# NEWS: one line per commit, newest first, excluding the "Prep X.Y" commit
# this script creates, as in the previous releases.
git log --no-merges --abbrev=16 --format='%h %s' "$prev_tag..HEAD" |
	awk '$2 != "Prep"' > "$tmpdir/news"

nr_commits=$(wc -l < "$tmpdir/news" | tr -d ' ')
[ "$nr_commits" -gt 0 ] || die "no commits since $prev_tag, nothing to release"

# ── The changes-vX.Y draft ─────────────────────────────────────────────
# Group the commits by the area in the subject prefix ("btf_encoder:",
# "pahole:", "tests:", ...), using the section names from the previous
# changes-vX.Y files.  It is a draft: it gets edited into the release
# notes, which are also the tag message and the announcement body.
area_of() {
	case $1 in
	btf_encoder|btf\ encoder)	printf 'BTF encoder:' ;;
	btf_loader|btf\ loader)		printf 'BTF loader:' ;;
	btf)				printf 'BTF:' ;;
	dwarf_loader|dwarf\ loader|dwarf) printf 'DWARF loader:' ;;
	ctf_encoder|ctf\ encoder)	printf 'CTF encoder:' ;;
	ctf_loader|ctf\ loader)		printf 'CTF loader:' ;;
	ctf)				printf 'CTF:' ;;
	tests|tests/tests|test)		printf 'Regression tests:' ;;
	coverage)			printf 'Regression tests:' ;;
	github\ CI|github|CI|workflows|.github) printf 'CI:' ;;
	cmake|CMakeLists.txt|build|scripts) printf 'Build:' ;;
	dutil|dwarves|dwarves_fprintf|dwarves_emit|lib|libbpf|core) printf 'Library:' ;;
	gobuffer|hash|list|rbtree|elfcreator|elf_symtab) printf 'Library:' ;;
	man-pages|man)			printf 'Man pages:' ;;
	rpm|packaging)			printf 'Packaging:' ;;
	# perf data type profiling is a pahole feature, even if lives in
	# its own source file.
	perf_dt)			printf 'pahole:' ;;
	pahole|codiff|pfunct|pdwtags|pglobal|prefcnt|syscse|scncopy|ctracer|dtagnames|btfdiff)
					printf '%s:' "$1" ;;
	*)
		# Unknown area, e.g. "gitignore:", just capitalize it.
		printf '%s%s:' "$(printf '%s' "${1:0:1}" | tr '[:lower:]' '[:upper:]')" "${1:1}"
		;;
	esac
}

declare -A area_index=()
declare -a areas=() area_counts=() area_commits=()

add_commit() {
	local area=$1 bullet=$2 idx
	if [ -z "${area_index[$area]+set}" ]; then
		idx=${#areas[@]}
		area_index[$area]=$idx
		areas[idx]=$area
		area_counts[idx]=0
		area_commits[idx]=
	else
		idx=${area_index[$area]}
	fi
	area_counts[idx]=$(( area_counts[idx] + 1 ))
	if [ -n "${area_commits[idx]}" ]; then
		area_commits[idx]="${area_commits[idx]}
$bullet"
	else
		area_commits[idx]=$bullet
	fi
}

while IFS= read -r line; do
	commit_subject=${line#* }
	prefix=${commit_subject%%:*}
	# A prefix is short, made of just these characters and is not a
	# script name, otherwise the colon is part of the sentence, as in
	# "pahole: Foo: bar" or "build-and-test-cmd.sh: something".
	if [ "$prefix" != "$commit_subject" ] && [ ${#prefix} -le 32 ] &&
	   # The comma has to come before the dash, which is a range in a
	   # bracket expression when it is not the last character.
	   [ -z "${prefix//[A-Za-z0-9_., \/+-]/}" ] &&
	   case $prefix in *.sh) false ;; *) true ;; esac; then
		bullet=${commit_subject#*: }
		# "pfunct, dwarves_fprintf:" and "dwarf_loader/btf_encoder:"
		# touch more than one area: the first one decides where the
		# commit gets listed in the changes file.
		prefix=$(printf '%s' "$prefix" |
			 sed -e 's/[,/].*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		area=$(area_of "$prefix")
	else
		bullet=$commit_subject
		area='Other:'
	fi
	add_commit "$area" "$bullet"
done < "$tmpdir/news"

# ── Combining similar csets ────────────────────────────────────────────
# Several csets in a release can be minor variations of the same theme,
# as the "Remove N dead functions found via coverage analysis" ones:
# they were published as separate csets, so NEWS keeps listing each of
# them, but the changes draft reads better with them combined into a
# single bullet.
#
# The ones that differ in a single number are added up ("Remove 6 dead
# functions..." and "Remove 5 dead functions..." combine into "Remove 11
# dead functions..."), the ones that are similar in other ways are left
# as sub items for the maintainer to consolidate when editing the draft
# into the release notes.

# Add up the numbers of bullets that are identical except for exactly
# one of their words, which has to be a number in all of them, exiting
# with an error status when they don't fit that pattern, so that the
# caller leaves them as related sub items.  The bullets come from
# stdin, one per line.
combine_numbered_bullets() {
	awk '
		{
			n = split($0, t, / /)
			wl[NR] = n
			for (i = 1; i <= n; i++) words[NR, i] = t[i]
		}
		END {
			if (NR < 1) exit 1
			nf = wl[1]
			# Find the one word position where the bullets
			# differ, all of them have to differ in just that
			# position, which has to hold a number.
			pos = 0
			for (r = 2; r <= NR; r++) {
				if (wl[r] != nf) exit 1
				for (i = 1; i <= nf; i++) {
					if (words[r, i] == words[1, i]) continue
					if (pos != 0 && pos != i) exit 1
					# Only a standalone number can be
					# added up: this way "64-bit",
					# "v1.26" and "libbpf-1.5" are
					# left alone.
					if (words[r, i] !~ /^[0-9]+$/ ||
					    words[1, i] !~ /^[0-9]+$/) exit 1
					pos = i
				}
			}
			if (pos == 0) exit 1
			# Each cset adds up its own number, including
			# the ones that are identical to the first one.
			sum = 0
			for (r = 1; r <= NR; r++) sum += words[r, pos]
			words[1, pos] = sum
			printf "%s", words[1, 1]
			for (i = 2; i <= nf; i++) printf " %s", words[1, i]
			printf "\n"
		}
	'
}

# Combine the bullets in $1 (file, one per line) into $2 (file), using
# $FUZZY_GREP to find the ones that are near identical, i.e. within an
# edit distance that grows with the bullet length.  Sets
# $nr_similar_groups and $nr_similar_csets for the caller to report.
group_similar_bullets() {
	local src=$1 dst=$2
	local -a bullet=() handled=() members=()
	local -i nr=0 i j max_errors
	local line merged identical matches

	while IFS= read -r line; do
		bullet[nr]=$line
		((++nr))
	done < "$src"

	for ((i = 0; i < nr; i++)); do
		handled[i]=
	done

	if [ "$nr" -lt 2 ]; then
		cat "$src" > "$dst"
		return
	fi

	: > "$dst"
	for ((i = 0; i < nr; i++)); do
		[ -n "${handled[i]}" ] && continue
		handled[i]=1
		members=("$i")
		# How fuzzy the matching can be: roughly one edit
		# operation per 25 characters, so that longer subjects
		# have room for a reworded word or two, capped to leave
		# merely related csets alone.
		max_errors=$(( ${#bullet[i]} / 25 ))
		[ "$max_errors" -ge 1 ] || max_errors=1
		[ "$max_errors" -le 4 ] || max_errors=4
		# The pattern is a fixed string, commit subjects have
		# regular expression metacharacters, and -n numbers the
		# lines, so that the matches map back to the bullets.
		matches=$("$FUZZY_GREP" -n -Z"$max_errors" -F -- "${bullet[i]}" "$src" 2>/dev/null) ||
			matches=
		while IFS= read -r line; do
			j=$(( ${line%%:*} - 1 ))
			[ "$j" -ne "$i" ] || continue
			[ -z "${handled[j]}" ] || continue
			handled[j]=1
			members+=("$j")
		done <<< "$matches"
		if [ "${#members[@]}" -eq 1 ]; then
			printf '%s\n' "${bullet[i]}" >> "$dst"
			continue
		fi
		((++nr_similar_groups))
		nr_similar_csets=$(( nr_similar_csets + ${#members[@]} - 1 ))
		# Identical subjects, e.g. two csets both named "Fix
		# typo": the subject stays, just tell how many csets.
		identical=1
		for j in "${members[@]:1}"; do
			[ "${bullet[j]}" = "${bullet[i]}" ] || identical=
		done
		if [ -n "$identical" ]; then
			printf '%s, in %d csets\n' "${bullet[i]}" "${#members[@]}" >> "$dst"
			continue
		fi
		local -a group_bullets=()
		for j in "${members[@]}"; do
			group_bullets+=("${bullet[j]}")
		done
		if merged=$(printf '%s\n' "${group_bullets[@]}" | combine_numbered_bullets); then
			printf '%s, in %d csets\n' "$merged" "${#members[@]}" >> "$dst"
		else
			# Similar but not a single number apart: the
			# newest cset as the main bullet, the rest as sub
			# items for the maintainer to consolidate.
			printf '%s\n' "${bullet[i]}" >> "$dst"
			for j in "${members[@]:1}"; do
				printf '  - %s\n' "${bullet[j]}" >> "$dst"
			done
		fi
	done
}

nr_similar_groups=
nr_similar_csets=0
if [ -n "$fuzzy_grep_ok" ]; then
	for idx in "${!areas[@]}"; do
		[ -n "${area_commits[idx]}" ] || continue
		printf '%s\n' "${area_commits[idx]}" > "$tmpdir/area_bullets"
		group_similar_bullets "$tmpdir/area_bullets" "$tmpdir/area_grouped"
		area_commits[idx]=$(< "$tmpdir/area_grouped")
		area_counts[idx]=$(wc -l < "$tmpdir/area_grouped")
	done
fi

# Most active areas first, in git log order for areas with the same
# number of commits.
declare -a order=()
while IFS= read -r i; do
	order+=("$i")
done <<< "$(
	for i in "${!areas[@]}"; do
		printf '%06d %s\n' "$(( 100000 - area_counts[i] ))" "$i"
	done | sort -n -k1,1 -k2,2 | cut -d' ' -f2
)"

# Words that show up in the subject of at least $1 csets in this
# release range and in none of the previous release notes: new
# development themes, candidates for the Highlights section.  "count
# word" lines are printed.
theme_words() {
	local min=$1
	git log --no-merges --format='%s' "$prev_tag..HEAD" |
	sed 's/^[a-zA-Z0-9_.-]*: //' |
	tr ' ' '\n' |
	tr -d ':,.' |
	tr '[:upper:]' '[:lower:]' |
	grep -E '^[a-z][a-z-]{3,}$' |
	sort | uniq -c |
	awk -v min="$min" '$1 >= min { print $1, $2 }' |
	while read -r count word; do
		if ! grep -qiE "(^|[^a-z])$word([^a-z]|$)" changes-v* 2>/dev/null; then
			printf '%s %s\n' "$count" "$word"
		fi
	done
}

# The milestones that are programmatically noticeable, printed one
# "Highlights:" bullet per line, pre-seeded at the top of the changes
# draft for the maintainer to reword, drop and extend with the ones
# that only he knows about:
noticed_highlights() {
	local old_tests new_tests count word

	# The number of regression tests: the test scripts in tests/,
	# which is what tests/tests runs:
	old_tests=$(git ls-tree -r --name-only "$prev_tag" -- tests/ 2>/dev/null |
		    grep '\.sh$' | grep -cv 'test_lib\.sh$' || true)
	new_tests=$(git ls-tree -r --name-only HEAD -- tests/ 2>/dev/null |
		    grep '\.sh$' | grep -cv 'test_lib\.sh$' || true)
	if [ "$new_tests" -ge 5 ] &&
	   [ "$new_tests" -ge $(( 2 * old_tests )) ] &&
	   [ "$(( new_tests - old_tests ))" -ge 5 ]; then
		printf -- '- Regression tests: from %s in %s to %s\n' \
			"$old_tests" "$prev_tag" "$new_tests"
	fi

	# New development themes, a word appearing in the subject of
	# several csets and in none of the previous release notes:
	theme_words 6 |
	while read -r count word; do
		printf -- '- New %s work, %s csets\n' "$word" "$count"
	done
}

{
	first=1
	for i in ${order+"${order[@]}"}; do
		[ -n "$first" ] || printf '\n'
		first=
		printf '%s\n\n' "${areas[i]}"
		while IFS= read -r bullet; do
			wrap_bullet "$bullet" '  '
		done <<< "${area_commits[i]}"
	done
} > "$tmpdir/changes"

# Pre-seed the Highlights section at the top of the draft with the
# programmatically noticeable milestones, saving them so that
# gen_announcement can tell them apart from the maintainer's own:
noticed=$(noticed_highlights)
if [ -n "$noticed" ]; then
	printf '%s\n' "$noticed" > "$tmpdir/noticed_highlights"
	{
		printf 'Highlights:\n\n%s\n\n' "$noticed"
		cat "$tmpdir/changes"
	} > "$tmpdir/changes.new" && mv "$tmpdir/changes.new" "$tmpdir/changes"
fi

# ── The files that get changed ─────────────────────────────────────────
{ printf '%s\n\n' "$new_tag"; cat "$tmpdir/news"; printf '\n'; cat NEWS; } > "$tmpdir/NEWS.new"

awk -v prev="changes-$prev_tag" -v new="$changes_file" '
	{ print }
	$0 == prev && !done { print new; done = 1 }
' MANIFEST > "$tmpdir/MANIFEST.new"

grep -qxF "$changes_file" "$tmpdir/MANIFEST.new" ||
	die "couldn't add $changes_file to MANIFEST"

sed -e "s/DWARVES_MAJOR_VERSION=${prev_version%%.*})/DWARVES_MAJOR_VERSION=${version%%.*})/" \
    -e "s/DWARVES_MINOR_VERSION=${prev_version#*.})/DWARVES_MINOR_VERSION=${version#*.})/" \
    -e "s/v${prev_version//./\\.}/v${version}/g" \
    CMakeLists.txt > "$tmpdir/CMakeLists.txt.new"

bumped="$(cmake_field_from "$tmpdir/CMakeLists.txt.new" MAJOR).$(cmake_field_from "$tmpdir/CMakeLists.txt.new" MINOR)"
[ "$bumped" = "$version" ] ||
	die "bumping CMakeLists.txt didn't work: got $bumped, expected $version"

# The version also appears in the string used when building from a
# tarball, where there is no git to ask: 'pahole --devel_version' in a
# tarball build reports vX.Y-tarball-g<sha>.
if grep -q "v$prev_version" "$tmpdir/CMakeLists.txt.new"; then
	die "CMakeLists.txt still mentions v$prev_version, check the tarball version string"
fi

# Show the announcement $1, indenting it for the script's output.  It
# ends with the contents of the changes file $2, which was already
# shown as the changes draft or edited by the maintainer, so when that
# tail is still verbatim the changes file, print just the part before
# it.  $3 is the first line to print, for skipping the mail headers.
print_announcement() {
	local announce=$1 changes=$2 first=${3:-1}
	local tail_nr total last

	tail_nr=$(wc -l < "$changes")
	total=$(wc -l < "$announce")
	last=$(( total - tail_nr ))
	if [ "$tail_nr" -gt 0 ] && [ "$last" -ge "$first" ] &&
	   [ "$(tail -n "$tail_nr" "$announce")" = "$(cat "$changes")" ]; then
		sed -n "${first},${last}p" "$announce" | sed 's/^/    /'
		info "    ... followed by the $changes_file contents, as shown above"
	else
		sed -n "${first},\$p" "$announce" | sed 's/^/    /'
	fi
}

# Write the release announcement to $2: $1 is the changes file, its
# contents go at the end, after the boilerplate, $3 is the signature file
# when the tarball was signed.
gen_announcement() {
	local final_changes=$1 out=$2 signed=$3
	local intro areas_phrase subject_phrase item lead area headline noticed
	local -i h
	declare -a area_names=() highlights=() areas=()
	declare -a headline_areas=() housekeeping_areas=()
	declare -a maintainer_highlights=() noticed_hl=() subject_candidates=()
	local -A headline_seen=()

	# The areas touched, from the section headers in changes-vX.Y, used
	# for the subject and for the intro paragraph.
	while IFS= read -r area; do
		[ -n "$area" ] && area_names+=("$area")
	done <<< "$(sed -n 's/^\([^ 	-].*\):$/\1/p' "$final_changes" | awk '!seen[$0]++')"

	# The release milestones, from the optional "Highlights:" section
	# the maintainer adds at the top of changes-vX.Y while editing it
	# into the release notes: its bullets go to the announcement
	# subject, ahead of the areas touched, and are spelled out in the
	# intro paragraph; the section itself stays at the top of the
	# announcement body, as the headline of the release notes.
	while IFS= read -r item; do
		[ -n "$item" ] && highlights+=("$item")
	done <<< "$(awk '
		/^Highlights:[ \t]*$/	{ inhl = 1; next }
		/^[^ \t-].*:[ \t]*$/	{ inhl = 0 }
		inhl && /^- /		{ sub(/^- /, ""); print }
	' "$final_changes")"

	if grep -q '^Highlights:[ \t]*$' "$final_changes" &&
	   [ ${#highlights[@]} -eq 0 ]; then
		warn "the Highlights: section in $final_changes is empty, drop it or add one bullet per release milestone to it"
	fi

	# Split the highlights into the maintainer's own, the ones that
	# only he knows are the most important aspects of the release,
	# e.g. the alt DWARF support, and the ones the script noticed
	# programmatically and pre-seeded in the draft: the maintainer's
	# come first in the subject and in the intro paragraph, so that
	# the noticed ones, facts such as the growth in the number of
	# regression tests, don't crowd them out of the subject:
	noticed=
	if [ -s "$tmpdir/noticed_highlights" ]; then
		noticed=$(< "$tmpdir/noticed_highlights")
	fi
	for item in "${highlights[@]}"; do
		if [ -n "$noticed" ] &&
		   printf '%s\n' "$noticed" | grep -qxF -- "- $item"; then
			noticed_hl+=("$item")
		else
			maintainer_highlights+=("$item")
		fi
	done

	# The areas, styled after the previous announcements, which list
	# only the big things: what is being released ("pahole"),
	# catchalls ("Other"), man pages and the minor utilities (scncopy,
	# prefcnt, pglobal, btfdiff, pfunct, codiff, ...) are not headline
	# material, related areas are grouped (BTF encoder and BTF loader
	# are just "BTF", CTF loader is "CTF"), and the housekeeping areas
	# come last.
	for area in "${area_names[@]}"; do
		case $area in
		pahole|Other|Man\ pages|Highlights|scncopy|prefcnt|pglobal|btfdiff|codiff|pfunct|pdwtags|dtagnames|syscse|ctracer)
			continue ;;
		BTF\ encoder|BTF\ loader)	headline="BTF" ;;
		CTF\ encoder|CTF\ loader)	headline="CTF" ;;
		*)				headline=$area ;;
		esac
		[ -n "${headline_seen[$headline]-}" ] && continue
		headline_seen[$headline]=1
		case $headline in
		Regression\ tests|CI|Build|Packaging)
			housekeeping_areas+=("$headline") ;;
		*)	headline_areas+=("$headline") ;;
		esac
	done

	# Regression tests and CI are one thing, group them when both are
	# in the release:
	if [ -n "${headline_seen[Regression tests]-}" ] &&
	   [ -n "${headline_seen[CI]-}" ]; then
		for ((h = 0; h < ${#housekeeping_areas[@]}; h++)); do
			case ${housekeeping_areas[h]} in
			"Regression tests")
				housekeeping_areas[h]="Regression tests and CI" ;;
			CI)
				housekeeping_areas=("${housekeeping_areas[@]:0:h}"
						    "${housekeeping_areas[@]:h+1}")
				break ;;
			esac
		done
	fi

	[ ${#headline_areas[@]} -eq 0 ] || areas=("${headline_areas[@]}")
	[ ${#housekeeping_areas[@]} -eq 0 ] || areas+=("${housekeeping_areas[@]}")

	# The intro paragraph, one sentence for the areas touched:
	areas_phrase=$(subject_items "${areas[@]}")
	case ${#areas[@]} in
	0)	intro="The $new_tag release of pahole is out." ;;
	1)	intro="The $new_tag release of pahole is out, with changes in the $areas_phrase area." ;;
	*)	intro="The $new_tag release of pahole is out, with changes in the $areas_phrase areas." ;;
	esac

	# The subject: the maintainer's own milestones first, then the
	# ones the script noticed programmatically, then as many of the
	# areas touched as fit, all under 80 characters:
	if [ -z "$subject" ]; then
		[ ${#maintainer_highlights[@]} -eq 0 ] ||
			subject_candidates+=("${maintainer_highlights[@]}")
		[ ${#noticed_hl[@]} -eq 0 ] ||
			subject_candidates+=("${noticed_hl[@]}")
		[ ${#areas[@]} -eq 0 ] || subject_candidates+=("${areas[@]}")
		if [ ${#subject_candidates[@]} -gt 0 ]; then
			subject_phrase=$(subject_items "${subject_candidates[@]}")
			[ -n "$subject_phrase" ] || subject_phrase=$areas_phrase
		else
			subject_phrase=$areas_phrase
		fi
		case $subject_phrase in
		'')	subject="ANNOUNCE: pahole $new_tag" ;;
		*)	subject="ANNOUNCE: pahole $new_tag ($subject_phrase)" ;;
		esac
	fi

	# The release milestones, spelled out by the maintainer in the
	# Highlights section, the maintainer's own first, emphasized in
	# the intro paragraph:
	local -a hl_order=()
	[ ${#maintainer_highlights[@]} -eq 0 ] ||
		hl_order+=("${maintainer_highlights[@]}")
	[ ${#noticed_hl[@]} -eq 0 ] || hl_order+=("${noticed_hl[@]}")
	if [ ${#hl_order[@]} -gt 0 ]; then
		local notably=
		for item in "${hl_order[@]}"; do
			item=${item%"${item##*[! ]}"}
			item=${item%.}
			if [ -z "$notably" ]; then notably=$item
			else notably="$notably; $item"
			fi
		done
		intro="$intro  Most notably, $notably."
	fi

	{
		printf 'From: %s\n' "$FROM"
		printf 'Subject: %s\n' "$subject"
		# Fold the recipients, one per line here, into a To: header.
		printf 'To: '
		printf '%s\n' "$RECIPIENTS" | awk '
			{	if (line == "")
					line = $0
				else if (length(line) + length($0) + 2 > 74) {
					printf "%s,\n\t", line
					line = $0
				} else
					line = line ", " $0
			}
			END { if (line != "") printf "%s\n", line }
		'
		cat <<EOF
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Hi,

$(wrap_tagged "$intro")

Main git repo:

   $GIT_URL

Mirror git repo:

   $MIRROR_URL

tarball + gpg signature:

   $TARBALL_URL_BASE/dwarves-${version}.tar.xz
   $TARBALL_URL_BASE/dwarves-${version}.tar.bz2
EOF
		if [ -n "$signed" ]; then
			printf '   %s/dwarves-%s.tar.sign\n' "$TARBALL_URL_BASE" "$version"
		fi
		cat <<'EOF'

	Thanks a lot to all the contributors and distro packagers,
you're on the CC list, we appreciate a lot the work you put into these
tools,

Best Regards,

- Arnaldo & Alan

EOF
		cat "$final_changes"
	} > "$out"
}

# ── The plan ───────────────────────────────────────────────────────────
areas_summary=
for i in ${order+"${order[@]}"}; do
	areas_summary="$areas_summary${areas_summary:+, }${areas[i]%:}"
done

if [ -n "$do_tarball" ] && [ -n "$do_build_check" ]; then
	build_check="${tarball_dir}/dwarves-${version}.tar.xz (cmake, make, pahole --version${rpm_check:+, rpm})"
else
	build_check="no (--no-tarball or --no-build-check)"
fi

cat <<EOF
Preparing pahole $version:

  branch:       $branch
  previous:     $prev_tag ($(git log -1 --format='%h %s' "$prev_tag^{commit}"))
  HEAD:         $(git log -1 --format='%h %s')
  commits:      $nr_commits since $prev_tag
  areas:        $areas_summary
  tarballs:     ${tarball_dir}/dwarves-${version}.tar{,.xz,.bz2}${do_tarball:+
                ${tarball_dir}/dwarves-${version}.tar.sign}
  build check:  $build_check
  tag:          $([ -n "$do_tag" ] && printf '%s (signed)' "$new_tag" || printf 'none, --no-tag was used')
  announcement: $announce_file

EOF

if [ -z "$assume_yes" ] && [ -z "$dry_run" ]; then
	if [ -r /dev/tty ]; then
		printf 'Continue? [y/N] '
		read -r answer < /dev/tty
	else
		answer=n
		info "no terminal to ask for confirmation, use --yes to go ahead"
	fi
	case $answer in
	[yY]*)	;;
	*)	info "aborted" ; exit 0 ;;
	esac
fi

# Collapse the %changelog entry when showing the diff for the spec
# file in a dry run: it is the first line of each bullet in the
# changes draft, shown right above, so a taste of it plus the number of
# elided lines is enough.
changelog_diff_taste() {
	awk -v changes="$changes_file" '
		/^\+\* /	{ inlog = 1 }
		inlog && /^\+/	{
					if (shown < 3) { print; ++shown; next }
					++elided
					next
				}
				{
					if (elided) {
						printf "+  ...\n+  (%d more lines: the first line of each bullet in %s, shown above)\n", elided, changes
						elided = 0
					}
					print
				}
		END		{
					if (elided)
						printf "+  ...\n+  (%d more lines: the first line of each bullet in %s, shown above)\n", elided, changes
				}
	'
}

apply() { # $1 = file to change, $2 = the generated contents, $3 = diff display filter
	if [ -n "$dry_run" ]; then
		info "--- would change $1:"
		diff -u --label "a/$1" --label "b/$1" "$1" "$2" | ${3:-cat} | sed 's/^/    /' || true
	else
		cat "$2" > "$1"
		info "  $1"
	fi
}

# ── Steps 1 to 3: CMakeLists.txt, MANIFEST and NEWS ────────────────────
step "Bumping the version in CMakeLists.txt, MANIFEST and NEWS"
apply CMakeLists.txt "$tmpdir/CMakeLists.txt.new"
apply MANIFEST "$tmpdir/MANIFEST.new"
apply NEWS "$tmpdir/NEWS.new"

# ── Step 4: changes-vX.Y ───────────────────────────────────────────────
step "Creating $changes_file"
if [ -n "$dry_run" ]; then
	info "--- would create $changes_file:"
	sed 's/^/    /' "$tmpdir/changes"
	final_changes=$tmpdir/changes
else
	cat "$tmpdir/changes" > "$changes_file"
	info "  $changes_file (draft, the $nr_commits commits grouped by area${nr_similar_groups:+, $nr_similar_groups groups of similar csets combined})"
	info "  Edit the 'Highlights:' section at the top, pre-seeded with what"
	info "  was noticed programmatically: reword or drop those and add the"
	info "  milestones that only you know about, e.g. dwz files support:"
	info "  its bullets go to the announcement subject and are spelled out"
	info "  in its intro paragraph."
	edit_file "$changes_file"
	[ -s "$changes_file" ] || die "$changes_file is empty"
	final_changes=$changes_file
fi

# ── Step 5: the spec file ──────────────────────────────────────────────
step "Updating rpm/SPECS/dwarves.spec"
{
	# %changelog entry: one line per top level bullet in changes-vX.Y,
	# unwrapping the continuation lines and dropping the sub items, then
	# trimmed of the trailing punctuation used to introduce them.
	printf '* %s %s - %s-1\n' "$(LC_ALL=C date +'%a %b %e %Y')" "$maintainer" "$version"
	awk '
		function flush() { if (line != "") print line; line = "" }
		/^- /			{ flush(); line = $0; next }
		/^[[:space:]]+- /	{ next }
		/^[[:space:]]+[^[:space:]]/ { s = $0; sub(/^[[:space:]]+/, "", s);
					     line = line " " s; next }
					{ flush() }
		END			{ flush() }
	' "$final_changes" |
		sed -e 's/^- //' -e 's/[[:space:]]*$//' -e 's/[:,;]$//' \
		    -e 's/,\{0,1\} for instance$//' -e 's/,\{0,1\} e\.g\.$//' |
		while IFS= read -r bullet; do
			[ -n "$bullet" ] || continue
			wrap_bullet "$bullet" '  '
		done
	printf '\n'
} > "$tmpdir/changelog_entry"

nr_bullets=$(grep -c '^- ' "$final_changes" || true)
[ "$nr_bullets" -gt 0 ] ||
	warn "no top level bullets in $final_changes, the %changelog entry is empty"
# The previous releases condense the changes into a handful of
# %changelog lines, which is the maintainer's job when editing
# changes-vX.Y: warn when that didn't happen.
[ "$nr_bullets" -le 15 ] || [ -n "$dry_run" ] || [ -n "$no_edit" ] ||
	warn "$nr_bullets bullets in $final_changes became as many lines in the %changelog entry, which is usually a condensed version of it, fix it with 'git commit --amend rpm/SPECS/dwarves.spec'"

sed -e "s/^Version: ${prev_version}\$/Version: ${version}/" \
    -e "s/^%doc changes-${prev_tag}\$/%doc ${changes_file}/" \
    -e "/^%changelog\$/r $tmpdir/changelog_entry" \
    rpm/SPECS/dwarves.spec > "$tmpdir/dwarves.spec.new"

grep -q "^Version: ${version}\$" "$tmpdir/dwarves.spec.new" ||
	die "couldn't bump Version: in rpm/SPECS/dwarves.spec"
grep -q "^%doc ${changes_file}\$" "$tmpdir/dwarves.spec.new" ||
	die "couldn't bump %doc changes-$prev_tag in rpm/SPECS/dwarves.spec"

apply rpm/SPECS/dwarves.spec "$tmpdir/dwarves.spec.new" changelog_diff_taste

if [ -n "$dry_run" ]; then
	step "Dry run, stopping here"
	# $do_tarball is what decides if there is a signature to point to
	# in the announcement, nothing was built here.
	gen_announcement "$tmpdir/changes" "$tmpdir/announce" \
			 "${do_tarball:+${tarball_dir}/dwarves-${version}.tar.sign}"
	info "--- would write $announce_file:"
	print_announcement "$tmpdir/announce" "$tmpdir/changes"
	info ""
	if [ -n "$do_build_check" ] && [ -n "$do_tarball" ]; then
		info "would also check that ${tarball_dir}/dwarves-${version}.tar.xz builds"
		info "and that 'pahole --version' in it reports v$version"
		if [ -n "$rpm_check" ]; then
			info "and that the rpm for it builds"
		fi
		info ""
	fi
	info "nothing was changed: no commit, tag, tarball nor announcement were created"
	exit 0
fi

# ── Step 6: the "Prep X.Y" commit ──────────────────────────────────────
if [ -n "$do_commit" ]; then
	step "Committing as 'Prep $version'"
	{
		printf 'Prep %s\n' "$version"
		for trailer in ${trailers+"${trailers[@]}"}; do
			printf '\n%s\n' "$trailer"
		done
		if [ -n "$link" ]; then
			printf '\nLink: %s\n' "$link"
		fi
	} > "$tmpdir/commit_msg"

	git add CMakeLists.txt MANIFEST NEWS "$changes_file" rpm/SPECS/dwarves.spec
	git commit -s -q -F "$tmpdir/commit_msg"
	git log -1 --format='  %h %s'
fi

# ── Step 7: the tarballs, the build check and the signature ─────────────
signed=
if [ -n "$do_tarball" ]; then
	step "Building the release tarballs in $tarball_dir"
	for compression in tar xz bz2; do
		TARBALL_DIR=$tarball_dir scripts/make-tarball.sh $compression >/dev/null
		info "  ${tarball_dir}/dwarves-${version}.tar$(case $compression in tar) printf '' ;; *) printf '.%s' "$compression" ;; esac)"
	done

	tarball=${tarball_dir}/dwarves-${version}.tar
	signature=$tarball.sign

	# A tarball that doesn't build, or that reports the previous
	# version, is not something to tag and announce: check it here,
	# while it is still easy to undo the "Prep X.Y" commit.  The rpm
	# for it is built as well, checking that the spec file points at
	# the right %doc changes-vX.Y and that the sources in the tarball
	# build the way distro users get them.
	if [ -n "$do_build_check" ]; then
		step "Checking that ${tarball_dir}/dwarves-${version}.tar.xz builds"
		verify_tarball "${tarball_dir}/dwarves-${version}.tar.xz"
		check_rpm rpm/SPECS/dwarves.spec
	else
		warn "not checking that the tarball builds, --no-build-check was used"
	fi

	step "Signing $tarball"
	if $gpg_program --batch --yes --armor --detach-sign \
			${key:+--local-user "$key"} \
			--output "$signature" "$tarball" &&
	   $gpg_program --verify "$signature" "$tarball" 2>/dev/null; then
		signed=$signature
		info "  $signature"
	else
		warn "couldn't sign $tarball, continuing without a signature"
		rm -f "$signature"
	fi
fi

# ── Step 8: the signed vX.Y tag ────────────────────────────────────────
if [ -n "$do_tag" ]; then
	step "Creating the signed $new_tag tag"
	# The review tags in the commits being released, they go between the
	# changes and the maintainer's Signed-off-by:, as in the previous
	# releases.  A tag has to have an email address in it, which filters
	# out the ones some tools leave behind, such as
	# "Reported-by: SomeTool:model-name".
	review_tags_re='^(Acked-by|Reviewed-by|Tested-by|Reported-by|Suggested-by):'

	dropped=$(git log --no-merges --format='%B' "$prev_tag..HEAD" |
		  grep -E "$review_tags_re" | grep -vE '<[^>]+>$' | sort -u)
	if [ -n "$dropped" ]; then
		warn "ignoring these review tags, they have no email address:"
		printf '%s\n' "$dropped" | sed 's/^/  /' >&2
	fi

	{
		cat "$final_changes"
		printf '\n'
		{
			git log --no-merges --format='%B' "$prev_tag..HEAD" |
				grep -E "$review_tags_re" |
				grep -E '<[^>]+>$' || true
			for trailer in ${trailers+"${trailers[@]}"}; do
				printf '%s\n' "$trailer"
			done
		} | awk '!seen[$0]++'
		printf 'Signed-off-by: %s\n' "$maintainer"
	} > "$tmpdir/tag_msg"

	edit_file "$tmpdir/tag_msg"

	if git tag -s -F "$tmpdir/tag_msg" ${key:+-u "$key"} "$new_tag"; then
		info "  $new_tag"
		git tag -l --format='  tagger: %(taggername) %(taggeremail)' "$new_tag"
	else
		die "couldn't create the signed $new_tag tag, fix it and re-run with --no-commit --no-tarball"
	fi
fi

# ── Step 9: the announcement ───────────────────────────────────────────
step "Writing the announcement"
gen_announcement "$final_changes" "$announce_file" "$signed"

edit_file "$announce_file"
info "  $announce_file"

# ── What is left for the maintainer ────────────────────────────────────
cat <<EOF

== pahole $version is ready, what is left to be done by hand:
EOF

git remote | grep -qx "$mirror_remote" || mirror_remote=

if [ -n "$do_push" ]; then
	step "Pushing to $remote"
	git push "$remote" "$branch"
	[ -z "$do_tag" ] || git push "$remote" "$new_tag"
	if [ -n "$mirror_remote" ]; then
		step "Pushing to $mirror_remote"
		git push "$mirror_remote" "$branch"
		[ -z "$do_tag" ] || git push "$mirror_remote" "$new_tag"
	fi
else
	printf '  git push %s %s\n' "$remote" "$branch"
	[ -z "$do_tag" ] || printf '  git push %s %s\n' "$remote" "$new_tag"
	if [ -n "$mirror_remote" ]; then
		printf '  git push %s %s\n' "$mirror_remote" "$branch"
		[ -z "$do_tag" ] || printf '  git push %s %s\n' "$mirror_remote" "$new_tag"
	fi
fi

if [ -n "$do_upload" ]; then
	step "Uploading the tarballs"
	scp "${tarball_dir}/dwarves-${version}.tar.xz" \
	    "${tarball_dir}/dwarves-${version}.tar.bz2" \
	    ${signed:+"$signed"} "$UPLOAD_DEST"
else
	printf '  scp %s/dwarves-%s.tar.xz \\\n' "$tarball_dir" "$version"
	printf '      %s/dwarves-%s.tar.bz2 \\\n' "$tarball_dir" "$version"
	printf '      %s \\\n' "${signed:-${tarball_dir}/dwarves-${version}.tar.sign}"
	printf '      %s\n' "$UPLOAD_DEST"
fi

cat <<EOF

  Send the announcement, after reviewing it and fixing the subject and
  the intro paragraph:

EOF
printf '  git send-email --to="%s" \\\n      %s\n' \
	"$(printf '%s' "$RECIPIENTS" | paste -sd, - | sed 's/,/, /g')" "$announce_file"
cat <<EOF

  Or, with a mailer that takes the headers from the file:

  mutt -H $announce_file
EOF

cat <<EOF

To undo all of this:

  git tag -d $new_tag
EOF
[ -z "$do_commit" ] || cat <<EOF
  git reset --hard HEAD^		# drops the 'Prep $version' commit
EOF
cat <<EOF
  rm -f ${tarball_dir}/dwarves-${version}.tar* $announce_file
EOF

info ""
info "The announcement, also in $announce_file (the changes-vX.Y list is at its end):"
info ""
print_announcement "$announce_file" "$final_changes" \
		   "$(awk '/^Hi,$/ { print NR; exit }' "$announce_file")"
