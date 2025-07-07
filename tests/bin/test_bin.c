// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>

#define noinline __attribute__((noinline))
#define __packed __packed

struct test_bin_struct {
	char a;
	short b;
	int c;
	unsigned long long d;
};

struct test_bin_struct_packed {
	char a;
	short b;
	int c;
	unsigned long long d;
} __packed;

int test_bin_func_ok(int a, void *b, char c, short d);
int test_bin_func_struct_ok(int a, void *b, char c, struct test_bin_struct d);
int test_bin_func_struct_on_stack_ok(int a, void *b, char c, short d, int e,
				      void *f, char g, short h,
				      struct test_bin_struct i);
int test_bin_func_struct_on_stack_ko(int a, void *b, char c, short d, int e,
				      void *f, char g, short h,
				      struct test_bin_struct_packed i);

noinline int test_bin_func_ok(int a, void *b, char c, short d)
{
	return a + (long)b + c + d;
}

noinline int test_bin_func_struct_ok(int a, void *b, char c,
				      struct test_bin_struct d)
{
	return a + (long)b + c + d.a + d.b + d.c + d.d;
}

noinline int test_bin_func_struct_on_stack_ok(int a, void *b, char c, short d,
					       int e, void *f, char g, short h,
					       struct test_bin_struct i)
{
	return a + (long)b + c + d + e + (long)f + g + h + i.a + i.b + i.c + i.d;
}

noinline int test_bin_func_struct_on_stack_ko(int a, void *b, char c, short d,
					       int e, void *f, char g, short h,
					       struct test_bin_struct_packed i)
{
	return a + (long)b + c + d + e + (long)f + g + h + i.a + i.b + i.c + i.d;
}

int main(void)
{
	struct test_bin_struct test;
	struct test_bin_struct_packed test_bis;

	test_bin_func_ok(0, NULL, 0, 0);
	test_bin_func_struct_ok(0, NULL, 0, test);
	test_bin_func_struct_on_stack_ok(0, NULL, 0, 0, 0, NULL, 0, 0, test);
	test_bin_func_struct_on_stack_ko(0, NULL, 0, 0, 0, NULL, 0, 0, test_bis);
	return 0;
}

