CC=${CROSS_COMPILE}gcc

test_bin: test_bin.c
	${CC} $^ -Wall -Wextra -Werror -g -o $@

clean:
	rm -rf test_bin

.PHONY: clean

