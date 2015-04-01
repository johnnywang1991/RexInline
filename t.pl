#!/usr/bin/env perl
use strict;
use warnings;
use Smart::Comments;

BEGIN { unshift @INC, './lib' }
use Rex::Inline;
use Rex::Inline::Test;

my $rex = Rex::Inline->new;
my $user = Rex::Inline::Test->new(
  user => 'root',
  password => 'Root123',
  server => ['127.0.0.1'],
  input => 'test',
);

$rex->add_task($user);

$rex->execute;

### r: $rex->reports
