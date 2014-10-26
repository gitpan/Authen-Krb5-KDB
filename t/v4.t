# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..29\n"; }
END {print "not ok 1\n" unless $loaded;}
use Authen::Krb5::KDB;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

my $db = Authen::Krb5::KDB->new( file  => 't/slave_datatrans.b7', save => 1 );
print "not " unless (ref($db) eq "Authen::Krb5::KDB");
print "ok 2\n";

my $Nprincs   = 0;
my $Npolicies = 0;
while (my $p = $db->next) {
    if ($p->type eq 'princ') {
	$Nprincs++;
    }
    if ($p->type eq 'policy') {
	$Npolicies++;
    }
}
print "not " unless ($Nprincs   == 9);
print "ok 3\n";
print "not " unless ($Npolicies == 2);
print "ok 4\n";

print "not " unless ($db->close);
print "ok 5\n";

my $pr = $db->principals;
print "not " unless (ref($pr) eq "ARRAY");
print "ok 6\n";
print "not " unless (scalar @{$pr} == 9);
print "ok 7\n";
foreach my $p (@{$pr}) {
    if ($p->name eq 'foo@TEST.ORG') {
	print "not " unless ($p->name_len == length($p->name));
	print "ok 8\n";

	print "not " unless ($p->max_life == 36000);
	print "ok 9\n";

	print "not " unless ($p->max_renew_life == 604800);
	print "ok 10\n";

	print "not " unless ($p->expiration == 0);
	print "ok 11\n";

	print "not " unless ($p->pw_expiration == 0);
	print "ok 12\n";

	print "not " unless ($p->last_success == 0);
	print "ok 13\n";

	print "not " unless ($p->last_success_dt eq '[never]');
	print "ok 14\n";

	print "not " unless ($p->last_failed == 0);
	print "ok 15\n";

	print "not " unless ($p->last_failed_dt eq '[never]');
	print "ok 16\n";

	print "not " unless ($p->fail_auth_count == 0);
	print "ok 17\n";
    }
}

my $pol = $db->policies;
print "not " unless (ref($pol) eq "ARRAY");
print "ok 18\n";
print "not " unless (scalar @{$pol} == 2);
print "ok 19\n";

foreach my $p (@{$pol}) {
    if ($p->name eq 'default') {
	print "not " unless ($p->pw_max_life == 0);
	print "ok 20\n";

	print "not " unless ($p->pw_min_life == 0);
	print "ok 21\n";

	print "not " unless ($p->pw_min_length == 5);
	print "ok 22\n";

	print "not " unless ($p->pw_min_classes == 2);
	print "ok 23\n";

	print "not " unless ($p->pw_history_num == 5);
	print "ok 24\n";
    }
}

foreach my $p (@{$pol}) {
    if ($p->name eq 'max-two-months') {
	print "not " unless ($p->pw_max_life == 5266800);
	print "ok 25\n";

	print "not " unless ($p->pw_min_life == 0);
	print "ok 26\n";

	print "not " unless ($p->pw_min_length == 5);
	print "ok 27\n";

	print "not " unless ($p->pw_min_classes == 2);
	print "ok 28\n";

	print "not " unless ($p->pw_history_num == 5);
	print "ok 29\n";
    }
}

