#!/usr/bin/perl -c

package B::Dumper;

=head1 NAME

B::Dumper - Dump all B objects at once

=head1 SYNOPSIS

  use B::Dumper;
  use Scalar::Utils qw(refaddr);

  my @a = (1..4);
  my $m = B::Dumper::Memory->new;
  $m->add_object(\@a);
  my $key = $m->key(refaddr \@a);
  print $m->addr->{$key}->{fill};   # index for last element

  $ perl -MB::Dumper::YAML -MO=-qq,Dumper -e '$scalar, @array, %hash'

  $ perl -MB::Dumper::JSON -e 'print B::Dumper::JSON->dump(\%INC)'

=head1 DESCRIPTION

This compiler backend dumps all <B> objects in one data structure.

=for readme stop

=cut

use 5.006;

use strict;
use warnings;

our $VERSION = '0.01';

sub compile (@) {
    my @args = @_;

    my @newargs;
    my $dumper_class = 'B::Dumper::YAML';

    foreach my $arg (@args) {
        if ($arg eq '-perl') {
            $dumper_class = 'B::Dumper::Perl';
        }
        elsif ($arg eq '-yaml') {
            $dumper_class = 'B::Dumper::YAML';
        }
        elsif ($arg eq '-json') {
            $dumper_class = 'B::Dumper::JSON';
        }
        else {
            push @newargs, $arg;
        }
    };

    return sub {
        my $main_stash = \%main::;

        print $dumper_class->dump(@newargs || $main_stash);

        return @newargs;
    };
};

package B::Dumper::Memory;

use B;

sub new {
    my ($class, @args) = @_;

    return bless {
        addr => {},
        key  => sub { sprintf "0x%x", $_[0] },
        @args,
    } => $class;
};

sub addr   { $_[0]->{addr} };
sub key { $_[0]->{key}->($_[1]) };

sub add_object {
    my ($self, $what) = @_;

    my $bobj = eval { $what->isa('B::OBJECT') || $what->isa('B::MAGIC') }
        ? $what
        : B::svref_2object(ref $what ? $what : \$what);
    my $addr = $$bobj;
    my $key = $self->key($addr);

    return if exists $self->addr->{$key};

    $self->addr->{$key} = undef;
    $self->addr->{$key} = {
        addr => $addr,
        key => $key,
        $bobj->dump($self),
    };

    return { $key => $self->addr->{$key} };
};


package B::Dumper::Base;

sub new {
    my ($class, @args) = @_;
    return bless {
        memory => B::Dumper::Memory->new(@args),
    } => $class;
};

sub memory { $_[0]->{memory} };

sub get_objects {
    my ($self, @args) = @_;

    $self->memory->add_object($_) foreach @args;

    my %hash = %{$self->memory->addr};
    return \%hash;
};

sub dump {
    my ($self, @args) = @_;
    $self = $self->new if not ref $self;
    return $self->get_objects(@args);
};


package B::BASE;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        class => B::class($self),
    );
    unshift @{ $data{isa} }, __PACKAGE__; # TODO remove it

    return %data;
};

sub get {
    my ($self, $what, @args) = @_;
    no warnings;
    return eval { $self->$what(@args) };
};


package B::MAGIC;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->B::BASE::dump(@args),
    );
    $data{lc($_)} = $self->get($_) foreach qw(FLAGS MOREMAGIC OBJ PRIVATE PTR REGEX TYPE precomp);
    unshift @{ $data{isa} }, __PACKAGE__;

    $m->add_object($self->OBJ);

    return %data;
};

sub get {
    goto &B::BASE::get;
};


package B::OBJECT;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->B::BASE::dump(@args),
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};

sub get {
    my ($self, @args);
    goto &B::BASE::get;
};


package B::SPECIAL;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_special => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::SV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_sv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    $data{lc($_)} = $self->get($_) foreach qw(REFCNT FLAGS);
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::RV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_rv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    my $rv = $self->get('RV');
    if (defined $rv) {
          $m->add_object($rv);
          $data{rv} = $m->key($$rv);
    };

    return %data;
};


package B::IV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_iv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    if ($self->FLAGS & B::SVf_IOK) {
        $data{lc($_)} = $self->get($_) foreach qw(int_value needs64bits packiv);
        if ($self->FLAGS & B::SVf_IVisUV) {
            $data{uvx} = $self->get('UVX');
        }
        else {
            $data{lc($_)} = $self->get($_) foreach qw(IV IVX);
        };

    };

    if ($self->FLAGS & B::SVf_ROK) {
        my $rv = $self->get('RV');
        if (defined $rv) {
              $m->add_object($rv);
              $data{rv} = $m->key($$rv);
        };
    };

    return %data;
};


package B::NV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_nv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    if ($self->FLAGS & B::SVf_NOK) {
        $data{lc($_)} = $self->get($_) foreach qw(NV NVX);
    };

    return %data;
};


package B::PV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_pv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    if ($self->FLAGS & B::SVf_POK) {
        $data{lc($_)} = $self->get($_) foreach qw(PV PVX);
    };

    my $rv = $self->get('RV');
    if (defined $rv) {
          $m->add_object($rv);
          $data{rv} = $m->key($$rv);
    };

    return %data;
};


package B::PVIV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_pviv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::PVNV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_pvnv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::PVMG;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_pvmg => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    my $svstash = $self->get('SvSTASH');
    if (defined $svstash) {
          $m->add_object($svstash);
          $data{svstash} = $m->key($$svstash);
    };

    my $magic = $self->get('MAGIC');
    if (defined $magic) {
          $m->add_object($magic);
          $data{magic} = $m->key($$magic);
    };

    return %data;
};


package B::HV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %array = $self->ARRAY;
    my %newarray;

    while (my ($key, $val) = each %array) {
        $m->add_object($val);
        $newarray{$key} = $m->key($$val);
    };

    my %data = (
        $self->next::method(@args),
        array => \%newarray,
    );
    $data{lc($_)} = $self->get($_) foreach qw(FILL MAX KEYS RITER NAME PMROOT);
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::AV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my @array = $self->ARRAY;
    my @newarray;

    foreach my $val (@array) {
        $m->add_object($val);
        push @newarray, $m->key($$val);
    };

    my %data = (
        $self->next::method(@args),
        array => \@newarray,
    );
    $data{lc($_)} = $self->get($_) foreach qw(FILL MAX AvFLAGS);
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::GV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($m) = my @args = @_;

    my %data = (
        $self->next::method(@args),
    );
    $data{lc($_)} = $self->get($_) foreach qw(NAME SAFENAME STASH);
    unshift @{ $data{isa} }, __PACKAGE__;

    my $stash = $self->get('STASH');
    if (defined $stash) {
          $m->add_object($stash);
          $data{stash} = $m->key($$stash);
    };

    return %data;
};


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
