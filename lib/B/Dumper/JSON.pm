#!/usr/bin/perl -c

package B::Dumper::JSON;

=head1 NAME

B::Dumper::JSON - Dump B objects via JSON

=head1 SYNOPSIS

  $ perl -MB::Dumper::JSON -e 'print B::Dumper::JSON->dump(\%INC)'

=for readme stop

=cut

use 5.006;

use strict;
use warnings;

our $VERSION = '0.01';


use JSON;

use B::Dumper;
our @ISA = qw(B::Dumper::Base);


sub dump {
    my ($self, @args) = @_;
    $self = $self->new if not ref $self;
    return JSON->new->ascii(1)->encode($self->get_objects(@args));
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
