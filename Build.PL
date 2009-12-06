use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name        => 'Convert::SNMP',
    license            => 'perl',
    dist_author        => 'Troels Liebe Bentsen <troels@it-kartellet.dk>',
    dist_version_from  => 'lib/Convert/SNMP.pm',
    create_readme      => 1,
    create_makefile_pl => 'passthrough',
    requires => { 
        'perl'           => '>= 5.8.0',
        'Convert::ASN1'  => 0,
    },
    build_requires => {
        'Test::More' => 0,
    },
    add_to_cleanup => [ 
        'Convert-SNMP-*',
        'Makefile',
        'blib',
    ],
);

$builder->create_build_script();
