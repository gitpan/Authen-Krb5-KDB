package Authen::Krb5::KDB::V3;

# $Id: V3.pm,v 1.9 2002/03/19 19:55:15 steiner Exp $

use Carp;
use POSIX qw(strftime);
use Authen::Krb5::KDB_H qw(KRB5_KDB_V1_BASE_LENGTH);
use strict;
use vars qw($VERSION);

$VERSION = do{my@r=q$Revision: 1.9 $=~/\d+/g;sprintf '%d.'.'%02d'x$#r,@r};

# If value is 1, the value is read/write and we build the accessor function;
#  if 0, the value is read-only and an accessor function is built.
#  if -1, the accessor function is written by hand

my %Princ_Fields = (
    'type'            =>  0,
    'len'             =>  0,
    'name_len'        =>  0,
    'n_tl_data'       =>  0,
    'n_key_data'      =>  0,
    'e_length'        =>  0,
    'name'            => -1,
    'attributes'      =>  1,
    'max_life'        =>  1,
    'max_renew_life'  =>  1,
    'expiration'      =>  1,
    'pw_expiration'   =>  1,
    'last_success'    => -1,
    'last_failed'     => -1,
    'fail_auth_count' =>  1,
    'tl_data'         => -1,
    'key_data'        => -1,
    'e_data'          => -1,
 );

my %Princ_Ext_Fields = (
    'last_success_dt' => 0,
    'last_failed_dt'  => 0,
 );

### From krb5-1.2.4/src/kadmin/dbutil/dump.c
# * The dump format is as follows:
# *	len strlen(name) n_tl_data n_key_data e_length
# *	name
# *	attributes max_life max_renewable_life expiration
# *	pw_expiration last_success last_failed fail_auth_count
# *	n_tl_data*[type length <contents>]
# *	n_key_data*[ver kvno ver*(type length <contents>)]
# *	<e_data>
# * Fields which are not encapsulated by angle-brackets are to appear
# * verbatim.  Bracketed fields absence is indicated by a -1 in its
# * place

sub new {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = @_;
        # checks => level
        # lineno => N
        # data => "string"

    $args{'raw_data'} = $args{'data'};

    my $p = $class->new_princ ( %args );
    return $p;
}

sub new_princ {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = @_;
        # checks => level
        # lineno => N
        # data => "string"
        # raw_data => "string"
    my $self = {};
    my (@data, $n_data_fields, $n_fields);
    my $n_key_data_fields = 0;

    if (defined($args{'data'})) {
	if ($args{'data'} =~ /;$/) { 
	    chop($args{'data'});
	} else {
	    croak "princ record missing final ';' at line $args{'lineno'}";
	}
	@data = split(/\t/, $args{'data'});
	$self->{'raw_data'} = defined($args{'raw_data'}) ? $args{'raw_data'} : $args{'data'};
    } else {
	croak "data for new principal not defined at line $args{'lineno'}";
    }

    $n_data_fields = scalar @data;

    $self->{'type'} = 'princ';

    $self->{'tl_data'} = [];
    $self->{'key_data'} = [];

    $self->{'len'} = shift @data;
    if ($args{'checks'}) {
	if ($self->{'len'} != KRB5_KDB_V1_BASE_LENGTH) {
	    croak "princ len field not ok at line $args{'lineno'}";
	}
    }
    $self->{'name_len'} = shift @data;
    $self->{'n_tl_data'} = shift @data;
    $self->{'n_key_data'} = shift @data;
    $self->{'e_length'} = shift @data;
    $self->{'name'} = shift @data;
    $self->{'attributes'} = shift @data;
    $self->{'max_life'} = shift @data;
    $self->{'max_renew_life'} = shift @data;
    $self->{'expiration'} = shift @data;
    $self->{'pw_expiration'} = shift @data;
    $self->{'last_success'} = shift @data;
    $self->{'last_success_dt'} = _strdate($self->{'last_success'});
    $self->{'last_failed'} = shift @data;
    $self->{'last_failed_dt'} = _strdate($self->{'last_failed'});
    $self->{'fail_auth_count'} = shift @data;

    if ($args{'checks'}) {
	if ($self->{'name_len'}  != length($self->{'name'})) {
	    carp "princ name length field not ok at line $args{'lineno'}";
	}
    }

    for my $i (1..$self->{'n_tl_data'}) {
	my $type = shift @data;
	my $len = shift @data;
	my $contents = shift @data;
	if ($args{'checks'}) {
	    if (_check_len($len*2, $contents)) {
		carp "princ tl length field not ok at line $args{'lineno'}";
	    }
	}
	push @{$self->{'tl_data'}}, [ $type, $len, $contents ];
    }

    for my $i (1..$self->{'n_key_data'}) {
	my $ver = shift @data;
	my $kvno = shift @data;
	$n_key_data_fields += 2;
	my $vers = [];
	for my $j (1..$ver) {
	    my $type = shift @data;
	    my $len = shift @data;
	    my $contents = shift @data;
	    $n_key_data_fields += 3;
	    if ($args{'checks'}) {
		if (_check_len($len*2, $contents)) {
		    carp "princ key length field not ok at line $args{'lineno'}";
		}
	    }
	    push @$vers, [ $type, $len, $contents ];
	}
	push @{$self->{'key_data'}}, [ $ver, $kvno, $vers ];
    }

    $self->{'e_data'} = shift @data;
    if ($args{'checks'}) {
	if (_check_len($self->{'e_length'}, $self->{'e_data'})) {
	    carp "princ e_data length field not ok at line $args{'lineno'}";
	}
    }

    # Note: do tl and key data separately and don't count 'type' field
    $n_fields = scalar(keys %Princ_Fields) - 3;
    $n_fields += 3 * $self->{'n_tl_data'};
    $n_fields += $n_key_data_fields;

    if ($n_data_fields != $n_fields) {
	carp "wrong number of data fields for princ at line $args{'lineno'}";
    }

    if (@data) {
	carp "Still data left from principal at line $args{'lineno'}: @data";
    }

    bless($self, $class);
    return $self;
}

sub print_principal {
    my $self = shift;

    if ($self->type() ne 'princ') {
	croak "data is not a princ record but a '" . $self->type() . "'";
    }

    print "Length:        ", $self->len(), "\n";
    print "strlen(Name):  ", $self->name_len(), "\n";
    print "No. tl Data:   ", $self->n_tl_data(), "\n";
    print "No. Key Data:  ", $self->n_key_data(), "\n";
    print "E Length:      ", $self->e_length(), "\n";
    print "Name:          ", $self->name(), "\n";
    print "Attributes:    ", $self->attributes(), "\n";
    print "MaxLife:       ", $self->max_life(), "\n";
    print "MaxRenewLife:  ", $self->max_renew_life(), "\n";
    print "Expiration:    ", $self->expiration(), "\n";
    print "PW Expiration: ", $self->pw_expiration(), "\n";
    print "Last Success:  ", $self->last_success_dt(),
		       " (", $self->last_success(), ")\n";
    print "Last Failed:   ", $self->last_failed_dt(),
		       " (", $self->last_failed(), ")\n";
    print "Fail Count:    ", $self->fail_auth_count(), "\n";

    my $i = 1;
    print "TL Data:\n";
    foreach my $tl (@{$self->tl_data()}) {
	print " $i: Type:     $tl->[0]\n";
	print "    Length:   $tl->[1]\n";
	print "    Contents: $tl->[2]\n";
	$i++;
    }
    
    $i = 1;
    print "Key Data:\n";
    foreach my $key (@{$self->key_data()}) {
	print " $i: Ver: $key->[0]\n";
	print "    Kvno: $key->[1]\n";
	foreach my $data (@{$key->[2]}) {
	    print "      Type:     $data->[0]\n";
	    print "      Length:   $data->[1]\n";
	    print "      Contents: $data->[2]\n";
	}
	$i++;
    }

    print "E Data: ", $self->e_data(), "\n";
    print "\n";
}

sub _strdate {
    my $when = shift;
    return "[never]"  if (not $when);
    my @tm = localtime($when);
    return strftime("%a %b %d %H:%M:%S %Z %Y", @tm);
}

# Returns true if two values don't "match", false if they do "match".
#  To "match": If the first value is 0, the second one must be -1;
#              Or the first value must be the length of the second.
sub _check_len ($$) {
    my $len = shift;
    my $data = shift;

    if ($len == 0) {
	return (not ($data == -1));
    } else {
	return ($len != length($data));
    }
}

### Accessor methods

sub name {
    my $self = shift;
    if (@_) {
	$self->{'name'} = shift;
	$self->{'name_len'} = length($self->{'name'});
    }
    return $self->{'name'};
}

sub last_success {
    my $self = shift;
    if (@_) {
	$self->{'last_success'} = shift;
	$self->{'last_success_dt'} = _strdate($self->{'last_success'});
    }
    return $self->{'last_success'};
}

sub last_failed {
    my $self = shift;
    if (@_) {
	$self->{'last_failed'} = shift;
	$self->{'last_failed_dt'} = _strdate($self->{'last_failed'});
    }
    return $self->{'last_failed'};
}

### XXX next two accessor methods need work

sub tl_data {
    my $self = shift;
    if (@_) {
	carp "Argument must be a reference to an array"
	    if (ref($_[0]) ne 'ARRAY');
	$self->{'tl_data'} = shift;
	$self->{'n_tl_data'} = scalar @{$self->{'tl_data'}};
    }
    return $self->{'tl_data'};
}

sub key_data {
    my $self = shift;
    if (@_) {
	carp "Argument must be a reference to an array"
	    if (ref($_[0]) ne 'ARRAY');
	$self->{'key_data'} = shift;
	$self->{'n_key_data'} = scalar @{$self->{'key_data'}};
    }
    return $self->{'key_data'};
}

sub e_data {
    my $self = shift;
    if (@_) {
	$self->{'e_data'} = shift;
	if ($self->{'e_data'} == -1) {
	    $self->{'e_length'} = 0;
	} else {
	    $self->{'e_length'} = length($self->{'e_data'});
	}
    }
    return $self->{'e_data'};
}

# generate rest of accessor methods
foreach my $field (keys %Princ_Fields) {
    no strict "refs";
    if ($Princ_Fields{$field} == 1) {
	*$field = sub {
	    my $self = shift;
	    $self->{$field} = shift  if @_;
	    return $self->{$field};
	};
    } elsif (not $Princ_Fields{$field}) {
	*$field = sub {
	    my $self = shift;
	    carp "Can't change value via $field method"  if @_;
	    return $self->{$field};
	};
    }
}

# all these methods are read-only
foreach my $field (keys %Princ_Ext_Fields) {
    no strict "refs";
    *$field = sub {
	my $self = shift;
	carp "Can't change value via $field method"  if @_;
	return $self->{$field};
    };
}

1;
__END__

=head1 NAME

Authen::Krb5::KDB::V3 - objects for Kerberos V5 database V3 principals


=head1 SYNOPSIS

Generally you won't load this library or call it's C<new> methods directly.
See L<Authen::Krb5::KDB> for more information.

    use Authen::Krb5::KDB::V3;

    $p = Authen::Krb5::KDB::V3->new( data => "..." );

    if ($p->type eq 'princ') {
	print $p->name, ": ", $p->fail_auth_count"\n";
    }


=head1 DESCRIPTION

=over 4

=item  new( data => "..." )

Parses version 3 principal entries and returns the data via an object.
Calls C<new_princ> to do the work.

Arguments are:

data => E<lt>stringE<gt>

Data to be parsed.  This argument is required.

checks => E<lt>levelE<gt>

Data checking level.  Level 0 means no checks; level 1 (the default)
does basic checks like checking that the lengths in the records are
correct; level 2 does much further consistency checks on the data.

lineno => E<lt>NE<gt>

Line number of the data file where this data came from (for error messages).

=back


=head2 Principals

=over 4

=item  new_princ( data => "..." )

Parses version 3 principal entries and returns the data via an object.

Arguments are:

data => E<lt>stringE<gt>

Data to be parsed.  This argument is required.

checks => E<lt>levelE<gt>

Data checking level.  Level 0 means no checks; level 1 (the default)
does basic checks like checking that the lengths in the records are
correct; level 2 does much further consistency checks on the data.

lineno => E<lt>NE<gt>

Line number of the data file where this data came from (for error messages).

=back

Methods to retrieve and set data fields are:

=over 4

=item  type (I<read only>)

=item  len (I<read only>)

=item  name_len (I<read only>)

=item  n_tl_data (I<read only>)

=item  n_key_data (I<read only>)

=item  e_length (I<read only>)

=item  name

=item  attributes

=item  max_life

=item  max_renew_life

=item  expiration

=item  pw_expiration

=item  last_success

=item  last_success_dt (I<read only>)

=item  last_failed

=item  last_failed_dt (I<read only>)

=item  fail_auth_count

=item  tl_data

=item  key_data

=item  e_data

=back


=head1 AUTHOR

Dave Steiner, E<lt>steiner@td.rutgers.eduE<gt>


=head1 COPYRIGHT

Copyright (c) 2002 David K. Steiner.  All rights reserved.  

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.


=head1 SEE ALSO

perl(1), kerberos(1), Authen::Krb5::KDB, Authen::Krb5::KDB_H.

=cut
