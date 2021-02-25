#!/usr/bin/env perl
$|++;

use lib qw(./lib);
use Getopt::Long;
use Web::Solid::Auth;
use String::Escape;
use Log::Any::Adapter;

Log::Any::Adapter->set('Log4perl');

Log::Log4perl::init('log4perl.conf');

my $cmd = shift;

if ($cmd eq 'authenticate') {
    cmd_authenticate(@ARGV);
}
elsif ($cmd eq 'headers') {
    cmd_headers(@ARGV);
}
elsif ($cmd eq 'curl') {
    cmd_curl(@ARGV);
}
elsif ($cmd eq 'refresh') {
    cmd_refresh(@ARGV);
}
else {
    usage();
}

sub usage {
    print STDERR <<EOF;
usage: $0 authenticate URL
usage: $0 headers METHOD URL
usage: $0 curl METHOD URL
EOF
    exit 1
}

sub cmd_authenticate {
    my $url = shift;

    usage() unless $url;

    my $host = $url;

    $host =~ s{(http(s)://[^\/]+)(.*)}{$1}i;

    my $auth = Web::Solid::Auth->new(host => $host);

    $auth->make_clean;

    my $auth_url = $auth->make_authorization_request;

    print "Please visit this URL and login:\n\n$auth_url\n\n";

    print "Starting callback server...\n";

    $auth->listen();
}

sub cmd_headers {
    my ($method,$url) = @_;

    my $headers = _headers($method,$url);

    print "$headers\n";
}

sub cmd_curl {
    my ($method,$url,@rest) = @_;

    usage() unless $method && $url;

    if (@rest) {
        @rest = map { String::Escape::quote($_) } @rest;
    }
    my $headers = _headers($method,$url);
    my $opts    = join(" ",@rest);
    system("curl $opts $headers $url");
}

sub cmd_refresh {
    my $url = shift;

    usage() unless $url;

    my $host = $url;

    $host =~ s{(http(s)://[^\/]+)(.*)}{$1}i;

    my $auth = Web::Solid::Auth->new(host => $host);

    my $data = $auth->make_refresh_token;

    if ($data) {
        print "Refresh ok\n";
    }
    else {
        print "Refresh failed\n";
    }
}

sub _headers {
    my ($method,$url) = @_;
    my $host = $url;

    $host =~ s{(http(s)://[^\/]+)(.*)}{$1}i;

    my $auth = Web::Solid::Auth->new(host => $host);

    my $headers = $auth->make_authentication_headers($url,$method);

    unless ($headers) {
        print STDERR "No access tokens found for $host. Maybe you need to authenticate first?\n";
        exit 2;
    }

    my @headers = ();
    for (keys %$headers) {
        push @headers , "-H \"" . $_ . ":" . $headers->{$_} ."\"";
    }

    return join(" ",@headers);
}

__END__

=head1 NAME

solid_auth.pl - A solid authentication tool

=head1 SYNOPSIS

      # Authentication to a pod
      solid_auth.pl authenticate https://hochstenbach.solidcommunity.net

      # Get the http headers for a authenticated request
      solid_auth.pl headers GET https://hochstenbach.solidcommunity.net/inbox

      # Act like a curl command and fetch authenticated content
      solid_auth.pl curl GET https://hochstenbach.solidcommunity.net/inbox

      # Add some data
      solid_auth.pl curl POST https://hochstenbach.solidcommunity.net/public/ \
            -H "Content-Type: text/plain" \
            -d "abc"

=cut
