#ifndef _CTRACER_RELAY_H_
#define _CTRACER_RELAY_H_ 1

struct trace_entry {
	unsigned int	   sec;
	unsigned int	   usec:31;
	unsigned int	   probe_type:1; /* Entry or exit */
	const void	   *object;
	unsigned long long function_id;
};

void ctracer__method_entry(const unsigned long long function,
			   const void *object, const int state_len);
void ctracer__method_exit(unsigned long long function);

int ctracer__relay_init(void);
void ctracer__relay_exit(void);

#endif
