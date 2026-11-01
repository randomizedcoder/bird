src := bridge.c
obj := $(src-o-files)
$(all-daemon)
$(cf-local)

tests_objs := $(tests_objs) $(src-o-files)

tests_src := bridge_test.c
tests_targets := $(tests_targets) $(tests-target-files)

# bridge_test.c includes bridge.c for its static functions
$(o)bridge_test: tests_exclude := $(o)bridge.o
