use strict;
use warnings;
use Test::More;

eval "use Test::Pod::Coverage 1.04";
plan skip_all => "Test::Pod::Coverage 1.04 required for testing POD coverage" if $@;
plan skip_all => "Currently a developer-only test" if !$ENV{TEST_AUTHOR};

all_pod_coverage_ok();
