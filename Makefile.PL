#  -*- Perl -*-

$VERSION = "0.05";

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Authen::Krb5::KDB',
    'VERSION'   => $VERSION,
    'dist'      => {'COMPRESS' => 'gzip', suffix => 'gz' },

);
