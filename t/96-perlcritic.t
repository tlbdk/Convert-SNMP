use strict;
use warnings;

use Test::More;

eval { 
    require Test::Perl::Critic;
};
plan skip_all => 'Test::Perl::Critic required to criticise code' if $@;
plan skip_all => "Currently a developer-only test" if !$ENV{TEST_AUTHOR};

import Test::Perl::Critic(-profile => 't/perlcriticrc');

all_critic_ok();
