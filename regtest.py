#! /usr/bin/python
# -*- python -*-
# -*- coding: utf-8 -*-
#   tuna - Application Tuning GUI
#   Copyright (C) 2009 Arnaldo Carvalho de Melo
#   Arnaldo Carvalho de Melo <acme@redhat.com>
#
#   This application is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; version 2.
#
#   This application is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   General Public License for more details.

import filecmp, os, sys

regtest_output_dir = "/media/tb/pahole/regtest/"
regtest_obj_dir = "/media/tb/debuginfo/usr/lib/debug/"
tools = ("pahole -A",)
len_debug_dir = len(regtest_obj_dir)
len_regtest_output_dir_before = len(regtest_output_dir) + len("before/")
verbose = 1

def diff_file(tool_filename):
	command = 'diff -u "%s" "%s" > /tmp/regtest.diff' % \
		  (os.path.join(regtest_output_dir, "before", tool_filename),
		   os.path.join(regtest_output_dir, "after", tool_filename))
	if verbose > 0:
		print command
	os.system(command)
	os.system("vim /tmp/regtest.diff")

def dir_has_no_diffs(dirname):
	return os.access(os.path.join(dirname, ".no_diffs"), os.F_OK)

def set_dir_has_no_diffs(dirname):
	f = file(os.path.join(dirname, ".no_diffs"), "w")
	f.close()

def reset_dir_has_no_diffs(dirname):
	os.unlink(os.path.join(dirname, ".no_diffs"))

def diff_dir(before, after, dir = None):
	if dir:
		before = os.path.join(before, dir)
		after = os.path.join(after, dir)
	print "\r%-120s" % before,
	sys.stdout.flush()
	diff = filecmp.dircmp(before, after)
	if not dir_has_no_diffs(after):
		diff_files = diff.diff_files
		if diff_files:
			print "\n  %s:\n	%s" % (before, diff_files)
			sys.stdout.flush()
			for f in diff_files:
				diff_file(os.path.join(before[len_regtest_output_dir_before:], f))
		else:
			set_dir_has_no_diffs(after)
	for dir in diff.common_dirs:
		diff_dir(before, after, dir)

def do_diffs():
	before = os.path.join(regtest_output_dir, "before")
	after = os.path.join(regtest_output_dir, "after")
	diff_dir(before, after)

def do_tool(tool, before_after, dirname, fname, prepend_obj_dir = False):
	if prepend_obj_dir:
		fname += ".debug"
		fixed_dirname = dirname
	else:
		fixed_dirname = dirname[len_debug_dir:]
	tool_output_dir = os.path.join(regtest_output_dir,
				       before_after,
				       fixed_dirname)
	try:
		os.makedirs(tool_output_dir)
	except:
		pass
	if dir_has_no_diffs(tool_output_dir):
		reset_dir_has_no_diffs(tool_output_dir)
	obj_path = os.path.join(dirname, fname)
	if prepend_obj_dir:
		obj_path = os.path.join(regtest_obj_dir, obj_path)
	command = '%s %s > "%s.%s.c"' % (tool, obj_path,
				         os.path.join(tool_output_dir,
						      fname[:-6]), tool)
	if verbose > 1:
		print command
	elif verbose > 0:
		print os.path.join(fixed_dirname, fname[:-6])
	os.system(command)

def do_tool_on_files(arg, dirname, fnames):
	if dirname.find("/.") >= 0:
		return
	tool, before_after = arg
	for fname in fnames:
		if fname[-6:] != ".debug":
			continue

		do_tool(tool, before_after, dirname, fname)

def do_tools(before_after):
	for tool in tools:
		os.path.walk(regtest_obj_dir, do_tool_on_files, (tool, before_after))

def do_move():
	print 'rm -f regtest_output_dir/before/*'
	print 'mv -f regtest_output_dir/after/* regtest_output_dir/before/'

def main(argv):
	try:
		if argv[1] in ('before', 'after'):
			if len(argv) > 3:
				dirname = argv[2]
				for fname in argv[3:]:
					for tool in tools:
						do_tool(tool, argv[1], dirname, fname, True)
			else:
				do_tools(argv[1])
		elif argv[1] == 'diff':
			if len(argv) > 3:
				dirname = argv[2]
				for fname in argv[3:]:
					for tool in tools:
						diff_file("%s.%s.c" % (os.path.join(dirname, fname), tool))
			else:
				do_diffs()
		elif argv[1] == 'move':
			do_move()
	except IOError:
		pass

if __name__ == '__main__':
    main(sys.argv)
