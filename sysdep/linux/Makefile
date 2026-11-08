src := netlink.c
obj := $(src-o-files)
$(all-daemon)
$(conf-y-targets): $(s)netlink.Y

tests_src := netlink_test.c
tests_targets := $(tests_targets) $(tests-target-files)
tests_objs := $(tests_objs) $(src-o-files)

# netlink_test.c includes netlink.c for its static parsers
$(o)netlink_test: tests_exclude := $(o)netlink.o
