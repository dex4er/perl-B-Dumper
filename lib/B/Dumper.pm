#!/usr/bin/perl -c

package B::Dumper;

=head1 NAME

B::Dumper - Dump all B objects at once

=head1 SYNOPSIS

  $ perl -MO=-qq,Dumper -e '$scalar, @array, %hash'

  $ perl -MB::Dumper -e 'print B::Dumper::JSON->dump(\%INC)'

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
    my ($class) = @_;

    return bless +{} => $class;
};

sub add_object {
    my ($self, $what) = @_;

    my $bobj = eval { $what->isa('B::OBJECT') || $what->isa('B::MAGIC') }
        ? $what
        : B::svref_2object(ref $what ? $what : \$what);
    my $addr = $$bobj;

    return if exists $self->{$addr};

    $self->{$addr} = 1;  # prevent endless recursing # TODO undef? empty string?
    $self->{$addr} = {
        addr => $addr,
        addr_hex => sprintf("0x%x", $addr),
        $bobj->dump($self),
    };

    return { $addr => $self->{addr} };
};

sub array {
    my ($self) = @_;
    return %$self;
};


package B::Dumper::Base;

sub get_objects {
    my ($class) = shift;
    my @args = @_;

    my $memory = B::Dumper::Memory->new;

    $memory->add_object($_) foreach @args;

    my %hash = %$memory;
    return \%hash;
};



package B::Dumper::YAML;

use YAML::XS;   # YAML::Tiny does not encode properly keys

our @ISA = qw(B::Dumper::Base);

sub dump {
    my ($self, @args) = @_;
    return Dump $self->get_objects(@args);
};


package B::Dumper::JSON;

use JSON;

our @ISA = qw(B::Dumper::Base);

sub dump {
    my ($self, @args) = @_;
    return JSON->new->ascii(1)->encode($self->get_objects(@args));
};


package B::Dumper::Perl;

use Data::Dumper;

our @ISA = qw(B::Dumper::Base);

sub dump {
    my ($self, @args) = @_;
    return Dumper $self->get_objects(@args);
};


package B::BASE;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;

    my %data = (
        class => B::class($self),
    );
    unshift @{ $data{isa} }, __PACKAGE__; # TODO remove it

    return %data;
};


package B::MAGIC;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;

    my %data = (
        $self->B::BASE::dump(@args),
    );
    $data{lc($_)} = eval { no warnings; $self->$_ } foreach qw();
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::OBJECT;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;

    my %data = (
        $self->B::BASE::dump(@args),
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::SPECIAL;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;

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
    my ($memory) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_sv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    $data{lc($_)} = eval { no warnings; $self->$_ } foreach qw(REFCNT FLAGS);
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::RV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;

    my $rv = eval { $self->RV };
    $memory->add_object($rv) if defined $rv;

    my %data = (
        $self->next::method(@args),
        rv => ref $rv ? $$rv : $rv,
        base_rv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::IV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;

    my $rv = eval { no warnings; $self->RV };
    $memory->add_object($rv) if defined $rv;

    my %data = (
        $self->next::method(@args),
        rv => ref $rv ? $$rv : $rv,
        base_iv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    $data{lc($_)} = eval { no warnings; $self->$_ } foreach qw(IV IVX UVX int_value needs64bits packiv);
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::NV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;

    my %data = (
        $self->next::method(@args),
        base_nv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    $data{lc($_)} = eval { no warnings; $self->$_ } foreach qw(NV NVX);
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::PV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;
    
    my $rv = eval { no warnings; $self->RV };
    $memory->add_object($rv) if defined $rv;

    my %data = (
        $self->next::method(@args),
        rv => ref $rv ? $$rv : $rv,
        base_pv => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    $data{lc($_)} = eval { no warnings; $self->$_ } foreach qw(PV PVX);
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::PVIV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;

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
    my ($memory) = my @args = @_;

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
    my ($memory) = my @args = @_;

    my $svstash = eval { no warnings; $self->SvSTASH };
    $memory->add_object($svstash) if defined $svstash;

    my $magic = eval { no warnings; $self->MAGIC };
    $memory->add_object($magic) if defined $magic;

    my %data = (
        $self->next::method(@args),
        svstash => $$svstash,
        magic   => ref $magic ? $$magic : $magic,
        base_pvmg => do { no strict 'refs'; [ @{*{__PACKAGE__.'::ISA'}} ] },
    );
    unshift @{ $data{isa} }, __PACKAGE__;


    return %data;
};


package B::HV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;

    my %array = $self->ARRAY;
    my %newarray;

    while (my ($key, $val) = each %array) {
        $memory->add_object($val);
        $newarray{$key} = $$val;
    };

    my %data = (
        $self->next::method(@args),
        array => \%newarray,
    );
    $data{lc($_)} = eval { no warnings; $self->$_ } foreach qw(FILL MAX KEYS RITER NAME PMROOT);
    unshift @{ $data{isa} }, __PACKAGE__;

    return %data;
};


package B::AV;

use mro 'c3';

sub dump {
    my ($self) = shift;
    my ($memory) = my @args = @_;

    my @array = $self->ARRAY;
    my @newarray;

    foreach my $val (@array) {
        $memory->add_object($val);
        push @newarray, $$val;
    };

    my %data = (
        $self->next::method(@args),
        array => \@newarray,
    );
    $data{lc($_)} = eval { no warnings; $self->$_ } foreach qw(FILL MAX AvFLAGS);
    unshift @{ $data{isa} }, __PACKAGE__;

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
