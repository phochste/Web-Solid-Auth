#!/usr/bin/env perl
$|++;

use lib qw(./lib);
use Getopt::Long;
use Web::Solid::Auth;
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
