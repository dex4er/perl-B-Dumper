#!/usr/bin/perl -c

package B::Dumper::Perl;

=head1 NAME

B::Dumper::Perl - Dump B objects via Data::Dumper

=head1 SYNOPSIS

  $ perl -MB::Dumper::Perl -e 'print B::Dumper::Perl->dump(\%INC)'

=for readme stop

=cut

use 5.006;

use strict;
use warnings;

our $VERSION = '0.01';


use Data::Dumper;

use B::Dumper;
our @ISA = qw(B::Dumper);


sub dump {
    my ($self, @args) = @_;
    $self = $self->new if not ref $self;
    return Dumper $self->SUPER::dump(@args);
};

sub compile (@) {
    # ... # TODO compile
};


1;


=head1 SEE ALSO

B<B::Dumper>

=head1 AUTHOR

Piotr Roszatycki <dexter@cpan.org>

=head1 LICENSE

Copyright (c) 2010 Piotr Roszatycki <dexter@cpan.org>.

This program is free software; you can redistribute it and/or modify it
under GNU Lesser General Public License.
