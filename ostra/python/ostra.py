#!/usr/bin/python3
#
# Copyright (C) 2005, 2006, 2007 Arnaldo Carvalho de Melo
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.

from datetime import timedelta

class trace_points:
	def __init__(self, hooks):
		self.entry = "entry" in hooks
		self.exit  = "exit" in hooks

	def __repr__(self):
		return str(self.__dict__.values())
	__str__ = __repr__

class change_point:
	def __init__(self, tstamp, value, seq):
		self.tstamp = tstamp
		self.value  = value
		self.seq    = seq

class class_field:
	def __init__(self, line, class_def_file):
		field, self.name, cgtraced, self.grab_expr, \
			self.collector_fmt, hooks, self.plot_fmt = line.strip().split(':')

		self.field	   = int(field)
		self.cg		   = cgtraced == "yes"
		self.hooks	   = trace_points(hooks.split(','))
		self.value	   = None
		self.last_value	   = None
		self.changes	   = []
		self._load_text_table(class_def_file)

	def _text_table_tokenizer(self, line):
		tokens = line.split(":")
		return int(tokens[0]), tokens[1][:-1]

	def _load_text_table(self, class_def_file):
		try:
			f = file("%s.%s.table" % (class_def_file, self.name))
		except:
			self.table = {}
			return
		self.table = dict([self._text_table_tokenizer(line) for line in f.readlines()])
		f.close()

	def set_last_value(self, tstamp, seq):
		if self.value != None:
			if self.cg and self.changed():
				self.changes.append(change_point(tstamp, self.value, seq))
			self.last_value = self.value

	def changed(self):
		return self.value != None and self.value != self.last_value

	def __repr__(self):
		return self.name
	__str__ = __repr__

class class_method:
	def __init__(self, line):
		fields = line.strip().split(':')
		self.function_id = fields[0]
		self.name = fields[1]
		self.print_return_value = fields[-1]
		self.function_id = int(self.function_id)
		self.print_return_value = self.print_return_value == "yes"
		self.calls = 0
		self.total_time = timedelta()
		self.last_tstamp = None
		self.times = []
		self.exits = {}
	
	def begin(self, tstamp):
		self.calls += 1
		self.last_tstamp = tstamp

	def end(self, tstamp):
		tstamp_delta = tstamp - self.last_tstamp
		if tstamp_delta < timedelta():
			tstamp_delta = timedelta()

		self.total_time += tstamp_delta
		self.times.append(tstamp_delta.seconds * 1000000 + tstamp_delta.microseconds)

	def plot(self, directory, entries, samples, nr_samples, verbose = False):
		from matplotlib import use as muse
		muse('Agg')
		from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
		from matplotlib.figure import Figure
		from matplotlib.ticker import FuncFormatter, FixedFormatter, LinearLocator
		from matplotlib.mlab import std as std_deviation
		from matplotlib.mlab import mean
		from time import asctime

		yfont = { 'fontname'   : 'Bitstream Vera Sans',
			  'color'      : 'r',
			  'fontsize'   : 8 }

		xfont = { 'fontname'   : 'Bitstream Vera Sans',
			  'color'      : 'b',
			  'fontsize'   : 8 }

		titlefont = { 'fontname'   : 'Bitstream Vera Sans',
			      'color'      : 'g',
			      'fontweight' : 'bold',
			      'fontsize'   : 10 }

		inches = 0.00666667
		width  = 950 * inches
		height = 680 * inches

		fig = Figure(figsize = (width, height))
		canvas = FigureCanvas(fig)
		ax = fig.add_subplot(111)
		ax.grid(False)
		xtickfontsize = 5
		ytickfontsize = 5

		plot_type = 'b-'
		field_mean = mean(samples)
		yaxis_plot_fmt = FuncFormatter(pylab_formatter_ms)
			
		ax.plot(entries, samples, "b-")

		ax.set_xlabel("samples", xfont)
		ax.set_ylabel("time", yfont)

		for label in ax.get_xticklabels():
			label.set(fontsize = xtickfontsize)
		for label in ax.get_yticklabels():
			label.set(fontsize = ytickfontsize)

		ax.yaxis.set_major_formatter(yaxis_plot_fmt)
		ax.set_title("%d %s samples (%s)" % (nr_samples, self.name, asctime()), titlefont)
		canvas.print_figure("%s/methods/%s.png" % (directory, self.name))
		del fig, canvas, ax

class class_definition:
	def __init__(self, class_def_file = None, class_methods_file = None):
		self.fields = {}
		self.methods = {}
		self.tstamp = None
		self.last_tstamp = None
		self.last_method = None
		self.epoch = None

		if class_def_file:
			f = file(class_def_file)
			for line in f.readlines():
				field = class_field(line, class_def_file)
				self.fields[field.name] = field
			f.close()

		if class_methods_file:
			f = file(class_methods_file)
			self.methods = dict([self._method_tokenizer(line) for line in f.readlines()])
			f.close()

	def _method_tokenizer(self, line):
		method = class_method(line)
		return method.function_id, method

	def set_last_values(self, seq = 0):
		self.last_method = self.current_method()
		for field in self.fields.values():
			field.set_last_value(self.tstamp, seq)
		self.last_tstamp = self.tstamp

	def parse_record(self, line):
		nsec, record = line[:-1].split(' ', 1)
		line_fields = record.split(':')

		self.tstamp = timedelta(microseconds = int(nsec) / 1000)
		if self.epoch == None:
			self.epoch = self.tstamp
		self.tstamp -= self.epoch
		
		action = line_fields[0][0]
		nr_fields = len(line_fields)
		for field in self.fields.values():
			if field.field >= nr_fields or \
			   (action == 'i' and not field.hooks.entry) or \
			   (action == 'o' and not field.hooks.exit):
				field.value = None
				continue
			field.value = line_fields[field.field]

	def parse_file(self, filename, process_record = None, verbose = False,
		       my_object = None):
		f = file(filename)
		current_object = None
		object_stack = []

		if verbose:
			nr_lines = 0

		while True:
			line = f.readline()
			if not line:
				break
			if verbose:
				nr_lines += 1
				print("\r%d" % nr_lines,)

			self.parse_record(line)

			method = self.current_method()
			# print method.name
			if my_object:
				if self.fields["action"].value[0] == 'i':
					current_object = self.fields["object"].value
					object_stack.append(current_object)
				else:
					current_object = object_stack.pop()

				if current_object != my_object:
					continue

			if self.fields["action"].value[0] == 'i':
				method.begin(self.tstamp)
			else:
				method.end(self.tstamp)
			seq = 0
			if process_record:
				seq = process_record()
			self.set_last_values(seq)

		f.close()
		if verbose:
			print

	def current_method(self):
		return self.methods[int(self.fields["function_id"].value)]

	def plot_methods(self, callgraph, verbose = False):
		for current_method in self.methods.values():
			nr_samples = len(current_method.times)
			if nr_samples < 4:
				continue

			if verbose:
				print("plot_methods: plotting %s method (%d samples)" % \
					(current_method.name, nr_samples))

			entries = [float("%d.0" % entry) for entry in range(nr_samples)]
			samples = current_method.times
			current_method.plot(callgraph, entries, samples,
					    nr_samples, verbose)

def pylab_formatter_kbps(x):
	mb = 1024 * 1024
	if x > mb:
		return "%d,%d Mbps" % (x / mb, x % mb)
	else:
		return "%d,%d Kbps" % (x / 1024, x % 1024)

def pylab_formatter_ms(x, pos = 0):
	ms = x / 1000
	us = x % 1000
	s = "%d" % ms
	if us > 0:
		s += ".%03d" % us
		s = s.rstrip('0')
	s += "ms"

	return s

def pylab_formatter(x, pos = 0):
	if current_plot_fmt == "kbps":
		return pylab_formatter_kbps(x)
	elif current_plot_fmt == "ms":
		return pylab_formatter_ms(x)
	else:
		return "%s" % str(int(x))

def plot_field(name, directory, tstamps, samples, nr_samples, plot_fmt = None,
	       table = None, verbose = False):
	global current_plot_fmt

	from matplotlib import use as muse
	muse('Agg')
	from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
	from matplotlib.figure import Figure
	from matplotlib.ticker import FuncFormatter, FixedFormatter, LinearLocator
	from matplotlib.mlab import std as std_deviation
	from matplotlib.mlab import mean
	from time import asctime

	yfont = { 'fontname'   : 'Bitstream Vera Sans',
		  'color'      : 'r',
		  'fontsize'   : 8 }

	xfont = { 'fontname'   : 'Bitstream Vera Sans',
		  'color'      : 'b',
		  'fontsize'   : 8 }

	titlefont = { 'fontname'   : 'Bitstream Vera Sans',
		      'color'      : 'g',
		      'fontweight' : 'bold',
		      'fontsize'   : 10 }

	inches = 0.00666667
	width  = 950 * inches
	height = 680 * inches

	fig = Figure(figsize = (width, height))
	canvas = FigureCanvas(fig)
	ax = fig.add_subplot(111)
	ax.grid(False)
	xtickfontsize = 5
	ytickfontsize = 5

	current_plot_fmt = plot_fmt
	field_mean = None

	plot_type = 'b-'
	if current_plot_fmt == "filter_dev":
		std = std_deviation(samples) * 2
		if verbose:
			print("filter_dev(%s) std=%d" % (name, std))
		for i in range(nr_samples):
			if samples[i] > std:
				if verbose:
					print("%s: filtering out %d" % (name, samples[i]))
				samples[i] = 0
		field_mean = mean(samples)
		yaxis_plot_fmt = FuncFormatter(pylab_formatter)
	elif current_plot_fmt == "table":
		ax.grid(True)
		plot_type = 'bo-'
		max_value = max(samples)
		without_zero = 1
		if table.has_key(0):
			without_zero = 0
			max_value += 1
		ax.yaxis.set_major_locator(LinearLocator(max_value))
		tstamps = range(nr_samples)
		seq = [ " " ] * max_value
		for key in table.keys():
			if key in samples:
				seq[key - without_zero] = "%s(%d)" % (table[key], key)
		ytickfontsize = 4
		yaxis_plot_fmt = FixedFormatter(seq)
	else:
		field_mean = mean(samples)
		yaxis_plot_fmt = FuncFormatter(pylab_formatter)
		
	ax.plot(tstamps, samples, plot_type)

	ax.set_xlabel("time", xfont)
	yname = name
	if field_mean:
		yname += " (mean=%s)" % pylab_formatter(field_mean)
	ax.set_ylabel(yname, yfont)

	for label in ax.get_xticklabels():
		label.set(fontsize = xtickfontsize)
	for label in ax.get_yticklabels():
		label.set(fontsize = ytickfontsize)

	ax.yaxis.set_major_formatter(yaxis_plot_fmt)
	ax.set_title("%d %s samples (%s)" % (nr_samples, name, asctime()), titlefont)
	canvas.print_figure("%s/%s.png" % (directory, name))
	del fig, canvas, ax

def plot(class_def, callgraph, verbose = False):
	for current_field in class_def.fields.values():
		nr_samples = len(current_field.changes)
		if nr_samples < 4:
			continue

		if verbose:
			print("ostra-plot: plotting %s field (%d samples)" % (current_field.name, nr_samples))

		tstamps = [float("%d.%06d" % (entry.tstamp.seconds, entry.tstamp.microseconds)) \
			   for entry in current_field.changes]
		try:
			samples = [int(entry.value) for entry in current_field.changes]
		except:
			continue
		plot_field(current_field.name, callgraph, tstamps, samples,
			   nr_samples, current_field.plot_fmt,
			   current_field.table, verbose)

if __name__ == '__main__':
	import sys
	c = class_definition(sys.argv[1], sys.argv[2])
	for field in c.fields.values():
		print("%s: %s" % (field, field.table))
	for method in c.methods.values():
		print("%d: %s" % (method.function_id, method.name))
