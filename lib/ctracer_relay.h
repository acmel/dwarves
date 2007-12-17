#ifndef _CTRACER_RELAY_H_
#define _CTRACER_RELAY_H_ 1
/* 
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

struct trace_entry {
	unsigned long long nsec;
	unsigned long long probe_type:1; /* Entry or exit */
	unsigned long long function_id:63;
	const void	   *object;
};

void ctracer__method_hook(const unsigned long long now,
			  const int probe_type,
			  const unsigned long long function,
			  const void *object, const int state_len);

#endif
