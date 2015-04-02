#!/usr/bin/env perl
use strict;
use warnings;
use Smart::Comments;

BEGIN { unshift @INC, './lib' }
use Rex -feature => ['1.0'];

use Rex::Commands::User;

use Rex::Inline;
use Rex::Inline::Test;

my $rex = Rex::Inline->new;

$rex->add_auth({
  user => 'root',
  password => 'Root123',
});

my $user = Rex::Inline::Test->new(
  server => ['127.0.0.1'],
  input => 'test',
);

my $tasks2 = {
  name => 'id',
  server => ['127.0.0.1'],
  func => sub {
    create_user 'test';
  }
};

$rex->add_task($user);
$rex->add_task($tasks2);

$rex->execute;

$rex->report_as_yaml;
$rex->report_as_json;
