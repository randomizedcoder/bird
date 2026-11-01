src := packets.c rip.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

tests_objs := $(tests_objs) $(src-o-files)

tests_src := packets_test.c
tests_targets := $(tests_targets) $(tests-target-files)

# packets_test.c includes packets.c for its static functions
$(o)packets_test: tests_exclude := $(o)packets.o
