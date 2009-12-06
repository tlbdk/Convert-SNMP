package Convert::SNMP;
use strict;
use warnings;
use Carp;

our $VERSION = '0.01';

=head1 NAME

Convert::SNMP - Utility functions for creating and parsing SNMP packets

=head1 VERSION

This documentation refers to Convert::SNMP version 0.01. 

=head1 SYNOPSIS

  use Convert::SNMP;
 
  my $packet;
  
  # Next line taken from Net::SNMP::PDU
  my $current_request_id = int(rand(0xFFFF) + ($^T & 0xff));
  
  my $request_id = create_request_id();

  # Make get packet with community 'public' for the oid "sysDescr.0"
  $packet = snmp_encode($request_id, 'get-request, 'public', ".1.3.6.1.2.1.1.1.0");
  
  # Make get-next packet
  $packet = snmp_encode('get-next-request, $community, $oid);
  
  # Make set packet
  $packet = snmp_encode('set-request, $community, $oid, 'value', 'value-type');

  # This code is borrowed from Net::SNMP::PDU
  sub create_request_id {
     if (++$current_request_id > ((2**31) - 1)) {
         # $^T is the time at which the program began running
         return $current_request_id = ($^T & 0xff) + 1;
     } else {
         return $current_request_id;
     }
  }

=head1 METHODS

=cut

use base qw(Exporter);

our @EXPORT_OK = qw(snmp_encode snmp_decode snmp_error);

use Convert::ASN1;

my $asn = Convert::ASN1->new;
$asn->prepare(\*DATA) or die;
close DATA or die;

my $asn_message = $asn->find("Message") or die;
my $asn_pdus = $asn->find("PDUs") or die;

=head2 snmp_encode($request_id, $command, $community, $oid, @args)

@args = ($type, $value) or ($repetitions) TODO: Rewrite

Accepts a community string and an oid in dotted-decimal notation. Returns a
($packet, $request_id) in array context or just $packet in scalar context.

The $repetitions parameter controls the max-repetitions value in the request.
On conforming SNMP implementations, it should be no problem to set this high
(e.g. 100). However, if you are only walking a small table, all extra
information returned here will be a waste of resources.

=cut

sub snmp_encode {
    my ($request_id, $command, $community, $oid, @args) = @_;
    my ($type, $value, $repetitions);

    # Default to SNMP v.1
    my $version = 0;

    if($command eq 'set-request') {
        ($type, $value) = @args; 
    } elsif($command eq 'get-bulk-request') {
        ($repetitions) = @args;
        # Upgrade to SNMP v.2 when doing bulk
        $version = 1;
    }

    $oid = _fix_oid($oid);

    my $buf_pdu = $asn_pdus->encode(
        $command => {
            "request-id"   => $request_id,
            $repetitions ? (
                "non-repeaters"     => 0,
                "max-repetitions"   => $repetitions,
            ) : (
                "error-status" => 0,
                "error-index"  => 0,
            ),
            "variable-bindings" => [
                {
                    name  => $oid,
                    value => { 
                        simple => { 
                            $type ? (
                                $type => $value
                            ) : (
                                empty => 1
                            )
                        } 
                    },
                },
            ],
        }
    ) or die; # $@ is propagated

    my $buf_message = $asn_message->encode(
        version   => $version,
        community => $community,
        data      => $buf_pdu,

    ) or die; # $@ is propagated

    return wantarray ? ($buf_message, $request_id) : $buf_message;
}

=head2 snmp_decode($packet)

Returns a hash reference:

    version      => 0,
    community    => $community,
    type         => "get" or "getnext",
    request_id   => $request_id,
    error_status => $error_status,
    error_index  => $error_index,
    vars         => [
        {
            oid   => $oid1,
            value => $value1,
            type  => $type1,
        },
        {
            oid   => $oid2,
            error => $error2,
        },
    ],

Known types will be decoded to sensible Perl types. Possible types are:

    number
    etring
    object
    empty (the only type where value is undef)
    address-internet
    counter
    gauge
    ticks
    arbitrary
    big-counter

=cut

sub snmp_decode {
    my ($packet) = @_;
    
    croak "Empty SNMP packet" if length $packet == 0;

    my $hash_message = $asn_message->decode($packet);
    my $hash_pdu = $asn_pdus->decode($hash_message->{data});

    croak "Malformed SNMP packet" if !$hash_message;
    croak "Malformed SNMP pdu" if !$hash_pdu;

    my ($pdutype) = keys %$hash_pdu;
    
    my %hash = (
        version      => $hash_message->{version},
        community    => $hash_message->{community},
        type         => $pdutype,
        request_id   => $hash_pdu->{$pdutype}{"request-id"},
        error_status => $hash_pdu->{$pdutype}{"error-status"},
        error_index  => $hash_pdu->{$pdutype}{"error-index"},
        vars         => [],
    );

    foreach my $binding (@{$hash_pdu->{$pdutype}{"variable-bindings"}}) {
        my $oid = $binding->{name} or next;
        my %var = (oid => $oid);

        if (exists $binding->{value}) {
            my $value = $binding->{value};

            my ($supertype) = keys %$value            or next;
            my ($type) = keys %{$value->{$supertype}} or next;

            if ($type eq "empty") {
                $var{value} = undef;
                $var{type} = "empty";

            } elsif ($type eq "address"
                    and ref($value->{$supertype}{$type}) eq "HASH"
                    and $value->{$supertype}{$type}{internet}) {

                my $ip = $value->{$supertype}{$type}{internet};
                $var{value} = join ".", unpack("C4", $ip);
                $var{type} = "address-internet";

            } else {
                $var{value} = $value->{$supertype}{$type};
                $var{type} = $type;
            }

        } else {
            my ($error) = grep { $_ ne "name" } keys(%$binding);
            $var{error} = $error;
        }

        push @{$hash{vars}}, \%var;
    }

    return \%hash;
}

# From the definitions in http://www.ietf.org/rfc/rfc1905.txt
my %errors = (
      0 => "noError",
      1 => "tooBig",
      2 => "noSuchName",
      3 => "badValue",
      4 => "readOnly",
      5 => "genErr",
      6 => "noAccess",
      7 => "wrongType",
      8 => "wrongLength",
      9 => "wrongEncoding",
     10 => "wrongValue",
     11 => "noCreation",
     12 => "inconsistentValue",
     13 => "resourceUnavailable",
     14 => "commitFailed",
     15 => "undoFailed",
     16 => "authorizationError",
     17 => "notWritable",
     18 => "inconsistentName",
);

=head2 snmp_error($errno)

Returns the human-readable name of a numeric error code, as obtained from the
error_status field in an SNMP response.

=cut

sub snmp_error {
    my ($errno) = @_;

    return $errors{$errno} || "unknown($errno)";
}


# Emulate net-snmp
sub _fix_oid {
    my ($oid) = @_;

    $oid || "0.1";
}

__DATA__

-- The ASN.1 definitions below are more or less copy-pasted from the relevant
-- RFCs. To make them compile, change "INTEGER { whatever }" to just "INTEGER"
-- and fix bad line wrappings. Also, some length/range parameters have to be
-- removed.
-- 
-- To make Convert::ASN1 explain syntax errors, use:
--     $asn1->prepare($string) or die;

--
-- From http://www.ietf.org/rfc/rfc1902.txt
--

        -- indistinguishable from INTEGER, but never needs more than
        -- 32-bits for a two's complement representation
        Integer32 ::=
            [UNIVERSAL 2]
                IMPLICIT INTEGER -- (-2147483648..2147483647)

--
-- From http://www.faqs.org/rfcs/rfc1155.html
--
           ObjectName ::=
               OBJECT IDENTIFIER

           ObjectSyntax ::=
               CHOICE {
                   simple
                       SimpleSyntax,

           -- note that simple SEQUENCEs are not directly
           -- mentioned here to keep things simple (i.e.,
           -- prevent mis-use).  However, application-wide
           -- types which are IMPLICITly encoded simple
           -- SEQUENCEs may appear in the following CHOICE

                   application-wide
                       ApplicationSyntax
               }

              SimpleSyntax ::=
                  CHOICE {
                      number
                          INTEGER,

                      string
                          OCTET STRING,

                      object
                          OBJECT IDENTIFIER,

                      empty
                          NULL
                  }

              ApplicationSyntax ::=
                  CHOICE {
                      address
                          NetworkAddress,

                      counter
                          Counter,

                      gauge
                          Gauge,

                      ticks
                          TimeTicks,

                      arbitrary
                          Opaque,

              -- other application-wide types, as they are
              -- defined, will be added here

                      -- From http://www.ietf.org/rfc/rfc1902.txt
                      big-counter
                          Counter64
                  }

              -- application-wide types

              NetworkAddress ::=
                  CHOICE {
                      internet
                          IpAddress
                  }

              IpAddress ::=
                  [APPLICATION 0]          -- in network-byte order
                      IMPLICIT OCTET STRING

              Counter ::=
                  [APPLICATION 1]
                      IMPLICIT INTEGER

              Gauge ::=
                  [APPLICATION 2]
                      IMPLICIT INTEGER

              TimeTicks ::=
                  [APPLICATION 3]
                      IMPLICIT INTEGER

              Opaque ::=
                  [APPLICATION 4]          -- arbitrary ASN.1 value,
                      IMPLICIT OCTET STRING   --   "double-wrapped"

              -- From http://www.ietf.org/rfc/rfc1902.txt :
              -- for counters that wrap in less than one hour with only 32 bits
              Counter64 ::=
                  [APPLICATION 6]
                        IMPLICIT INTEGER -- (0..18446744073709551615)

--
-- From http://www.ietf.org/rfc/rfc1905.txt (SNMP v2c Protocol Operations)
--

     -- protocol data units

     PDUs ::=
         CHOICE {
             get-request
                 GetRequest-PDU,

             get-next-request
                 GetNextRequest-PDU,

             get-bulk-request
                 GetBulkRequest-PDU,

             response
                 Response-PDU,

             set-request
                 SetRequest-PDU,

             -- Old-style trap added from SNMP1 RFC
             trap
                 Trap-PDU,

             inform-request
                 InformRequest-PDU,

             snmpV2-trap
                 SNMPv2-Trap-PDU,

             report
                 Report-PDU
         }

     -- PDUs

     GetRequest-PDU ::=
         [0]
             IMPLICIT PDU

     GetNextRequest-PDU ::=
         [1]
             IMPLICIT PDU

     Response-PDU ::=
         [2]
             IMPLICIT PDU

     SetRequest-PDU ::=
         [3]
             IMPLICIT PDU

     -- [4] is obsolete

     GetBulkRequest-PDU ::=
         [5]
             IMPLICIT BulkPDU

     InformRequest-PDU ::=
         [6]
             IMPLICIT PDU

     SNMPv2-Trap-PDU ::=
         [7]
             IMPLICIT PDU

     --   Usage and precise semantics of Report-PDU are not presently
     --   defined.  Any SNMP administrative framework making use of
     --   this PDU must define its usage and semantics.
     Report-PDU ::=
         [8]
             IMPLICIT PDU

     PDU ::=
         SEQUENCE {
             request-id
                 Integer32,

             error-status            -- sometimes ignored
                 INTEGER,

             error-index            -- sometimes ignored
                 INTEGER,

             variable-bindings   -- values are sometimes ignored
                 VarBindList
         }


     BulkPDU ::=                     -- MUST be identical in
         SEQUENCE {                  -- structure to PDU
             request-id
                 Integer32,

             non-repeaters
                 INTEGER,

             max-repetitions
                 INTEGER,

             variable-bindings       -- values are ignored
                 VarBindList
         }


     -- variable binding

     VarBind ::=
         SEQUENCE {
             name
                 ObjectName,

             CHOICE {
                 value
                     ObjectSyntax,

                 unSpecified         -- in retrieval requests
                         NULL,

                                     -- exceptions in responses
                 noSuchObject[0]
                         IMPLICIT NULL,

                 noSuchInstance[1]
                         IMPLICIT NULL,

                 endOfMibView[2]
                         IMPLICIT NULL
             }
         }


     -- variable-binding list

     VarBindList ::=
         SEQUENCE OF
             VarBind

--
-- From http://www.faqs.org/rfcs/rfc1157.html (SNMP v1)
--
      Message ::=
              SEQUENCE {
                  version          -- version-1 for this RFC
                      INTEGER,

                  community        -- community name
                      OCTET STRING,

                  data             -- e.g., PDUs if trivial
                      ANY          -- authentication is being used
              }

      Trap-PDU ::=
          [4]
             IMPLICIT SEQUENCE {
                  enterprise        -- type of object generating
                                    -- trap, see sysObjectID in [5]

                      OBJECT IDENTIFIER,

                  agent-addr        -- address of object generating
                      NetworkAddress, -- trap

                  generic-trap      -- generic trap type
                      INTEGER,

                  specific-trap  -- specific code, present even
                      INTEGER,   -- if generic-trap is not
                                 -- enterpriseSpecific

                  time-stamp     -- time elapsed between the last
                      TimeTicks, -- (re)initialization of the network
                                 -- entity and the generation of the trap

                   variable-bindings -- "interesting" information
                      VarBindList
              }

--  vim: et ts=4 sts=4 sw=4 tw=79
