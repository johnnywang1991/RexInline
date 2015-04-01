#
# (c) Johnny Wang <johnnywang1991@msn.com>
#
# vim: set ts=2
# vim: set sw=2
# vim: set tw=0
# vim: set expandtab

=encoding UTF-8

=head1 NAME

Rex::Inline - write Rex in perl

=head1 DESCRIPTION

Rex::Inline is an API of I<Rex> module write with Moose.

=head1 GETTING HELP
 
=over 3
 
=item * Web Site: L<http://rexify.org/>
 
=item * IRC: irc.freenode.net #rex
 
=item * Bug Tracker: L<https://github.com/RexOps/Rex/issues>
 
=back

=head1 SYNOPSIS

  use strict;
  use warnings;
  use Rex::Inline;
  use Rex::Inline::Test;

  my $rex = Rex::Inline->new(use_debug => 0);
  my $task1 = Rex::Inline::Test->new(user => 'root', password => 'test', server => ['127.0.0.1']);

  $rex->add_task($task1);
  $rex->execute;
  $rex->reports;

=cut
package Rex::Inline;

use strict;
use warnings;

use utf8;
use FindBin;
use POSIX 'strftime';

our $VERSION = '0.0.1'; # VERSION

use Moose;
use MooseX::AttributeShortcuts;

use File::Temp 'mkdtemp';
use File::Path::Tiny;
use File::Spec::Functions;

use YAML::XS 'LoadFile';
use Parallel::ForkManager;

use Rex -feature => 0.31;
use Rex::Config;
use Rex::Group;
use Rex::TaskList;

use namespace::autoclean;

=head1 ATTRIBUTES

=over 7

=item use_debug

set/get debug option (Bool)

Print or not debug level log 

see B<rex -d> option

default is 0 (disabled)
=cut
has use_debug => (is => 'rw', default => 0);

=item use_cache

set/get use_cache option (Bool)

Use or not B<rex -c> option

default is 1 (enable)
=cut
has use_cache => (is => 'rw', default => 1);

=item use_report

set/get use_report option (Bool)

show rex report result

default is 1 (enable)
=cut
has use_report => (is => 'rw', default => 1);

=item log_dir

set/get log dir (String)

default is C<"./rexlogs/">
=cut
has log_dir => (is => 'rw', default => './rexlogs/');

=item parallelism

set/get parallelism nums (Int)

see B<rex -t> option

default is 5
=cut
has parallelism => (is => 'rw', default => 5);

=item log_paths

get log paths (ArrayRef)

format is C<[{task_id = log_path}, ...]>

I<readonly>
=cut
has log_paths => (
  is => 'ro',
  default => sub{[]},
  traits => ['Array'],
  handles => {add_log_paths => 'push'},
);
=item reports

get rex process reports (ArrayRef)

format is C<[{report = $report_ref, task_id = $task_id, date = $date, hostname = $hostname}, ...]>

I<readonly>
=cut
has reports => (
  is => 'ro',
  default => sub{[]},
  traits => ['Array'],
  handles => {add_reports => 'push'},
);
=back
=cut

has date => (is => 'ro', lazy => 1, builder => 1); # date: format is YYmmdd
has prefix => (is => 'ro', lazy => 1, builder => 1); # log prefix dir
has tasklist => (is => 'ro', lazy => 1, builder => 1); # rex tasklist base object, use private
has pm => (is => 'ro', lazy => 1, builder => 1); # parallel forkmanager object, use private

=head1 METHODS

=over 2

=item add_task

add I<Rex::Inline::Base> Object to TaskList

=cut

has task => (
  is => 'ro',
  default => sub{[]},
  traits => ['Array'],
  handles => {add_task => 'push'},
);

=item execute

Execute all loaded Task in parallel

=cut
sub execute {
  my $self = shift;

  ### setup parallel forkmanager
  $self->pm->run_on_finish(sub {
    my ($pid, $exit_code, $ident, $exit_signal, $core_dump, $data_structure_reference) = @_;
    # retrieve data structure from child
    if ($data_structure_reference) {  # children are not forced to send anything
      my @reports = @$data_structure_reference;  # child passed a string reference
      $self->add_reports( @reports ) if @reports;
    }
  });

  ### run task list
  for my $task_in_list ($self->tasklist->get_tasks) {
    $self->pm->start and next;

    my @reports;
    if ( $self->tasklist->is_task($task_in_list) ) {
      my $task_id = $self->tasklist->get_task($task_in_list)->desc;
      ### set logging path
      logging to_file =>
        catfile( $self->prefix, "${task_id}.log" );
      ### set report path
      my $report_path = mkdtemp( sprintf("%s/reports_XXXXXX", $self->prefix) );
      set report_path => $report_path;
      ### run
      $self->tasklist->run($task_in_list);
      ### fetch reports
      @reports = $self->_fetch_reports($task_in_list, $report_path, $task_id) if $self->use_report;
    }

    $self->pm->finish(0, [@reports]);
  }

  ### wait parallel task
  $self->pm->wait_all_children;
  ### over
}

=back
=cut

sub _fetch_reports {
  my $self = shift;
  my ($task_name, $report_path, $task_id) = @_;

  my @reports;

  ### read report path
  for my $server ( @{ $self->tasklist->get_task($task_name)->server } ) {
    my $report;

    for my $report_file ( glob catfile( $report_path, $server, '*.yml' ) ) {
      my $report_content = eval { LoadFile($report_file) };
      $report = {
        report => $report_content,
        group => $task_id,
        date => $self->date,
        host => $server->name
      };
    }
    rmdir catdir( $report_path, $server );

    unless ($report) {
      ### log failed
      $report = {
        report => {
          task => {
            failed => '1',
            message => sprintf(
              'Wrong username/password or wrong key on %s. Or root is not permitted to login over SSH.',
              $server->name
            )
          }
        },
        group => $task_id,
        date => $self->date,
        host => $server->name
      };
    }

    ### push report
    push @reports, $report;
  }
  rmdir $report_path;
}

sub _build_tasklist {
  my $self = shift;
  
  ### set log debug level
  if ($self->use_debug) {
    $Rex::Logger::debug = $self->debug_bool;
    $Rex::Logger::silent = 0;
  }

  ### set parallelism
  parallelism($self->parallelism);
  ### set use cache
  Rex::Config->set_use_cache($self->use_cache);
  ### set report
  Rex::Config->set_do_reporting($self->use_report);
  Rex::Config->set_report_type('YAML');

  ### initial task list
  for my $task (@{$self->task}) {
    ### setup new connection group
    group $task->id => @{$task->server};
    ### setup auth for group
    auth for => $task->id => %{$task->task_auth};
    ### initial task
    desc $task->id;
    ### last param overwrite the caller module name Rex Commands line 284-286
    task $task->name, group => $task->id, $task->func, { class => "Rex::CLI" };
  }

  return Rex::TaskList->create;
}
sub _build_date { strftime "%Y%m%d", localtime(time) }
sub _build_prefix {
  my $self = shift;
  my $prefix = catdir($self->log_dir, $self->date);

  File::Path::Tiny::mk($prefix) unless -d $prefix;

  return $prefix;
}
sub _build_pm { Parallel::ForkManager->new(10) }

__PACKAGE__->meta->make_immutable;
