package Rex::Inline::Test;
use Moose;
use Rex -feature => ['1.0'];

extends 'Rex::Inline::Base';

sub func {
  my $self = shift;

  return sub {
    my $output = run "uptime";
    say $output;
    say $self->input;
  }
}

__PACKAGE__->meta->make_immutable;
