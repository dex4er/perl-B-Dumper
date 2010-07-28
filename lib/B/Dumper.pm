#!/usr/bin/perl -c

package B::Dumper;

=head1 NAME

B::Dumper - Dump all B objects at once

=head1 SYNOPSIS

  $ perl -MO=Dumper -e 'print $scalar, @array, %hash'

=head1 DESCRIPTION

This compiler backend dumps all <B> objects in one data structure.

=for readme stop

=cut

use 5.006;

use strict;
use warnings;

our $VERSION = '0.01';


1;


=head1 SEE ALSO

B<B>, B<O>.

=for readme continue

=head1 AUTHOR

Piotr Roszatycki <dexter@cpan.org>

=head1 LICENSE

Copyright (c) 2010 Piotr Roszatycki <dexter@cpan.org>.

This program is free software; you can redistribute it and/or modify it
under GNU Lesser General Public License.
