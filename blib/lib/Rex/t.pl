#!/usr/bin/env perl
use strict;
use warnings;
use Smart::Comments;

BEGIN { unshift @INC, './lib' }
use Rex -feature => ['1.0'];
use Rex::Inline;
use Rex::Inline::Test;

my $rex = Rex::Inline->new;
my $user = Rex::Inline::Test->new(
  user => 'root',
  password => 'Root123',
  server => ['127.0.0.1'],
  input => 'test',
);

my $tasks2 = {
  name => 'id',
  user => 'root',
  password => 'Root123',
  server => ['127.0.0.1'],
  func => sub {
    say run "ls";
  }
};

$rex->add_task($user);
$rex->add_task($tasks2);

$rex->execute;

### r: $rex->reports
