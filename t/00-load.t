use strict;
use warnings;

use Test::More tests => 1;

BEGIN {
    use_ok('Convert::SNMP');
}

diag( "Testing Convert::SNMP $Convert::SNMP::VERSION, Perl $], $^X" );
