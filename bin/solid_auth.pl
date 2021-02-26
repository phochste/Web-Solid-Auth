#!/usr/bin/env perl
$|++;

use lib qw(./lib);
use Getopt::Long qw(:config pass_through);
use Web::Solid::Auth;
use Path::Tiny;
use String::Escape;
use Log::Any::Adapter;

Log::Any::Adapter->set('Log4perl');
Log::Log4perl::init('log4perl.conf');

my $webid;

GetOptions("webid|w=s" => \$webid);

my $cmd = shift;

unless ($webid) {
    $webid = _get_cache();
}

if (0) {}
elsif ($cmd eq 'set') {
    cmd_set(@ARGV);
}
elsif ($cmd eq 'get') {
    cmd_get(@ARGV);
}
elsif ($cmd eq 'authenticate') {
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
usage: $0 set webid
usage: $0 get
usage: $0 [options] authenticate
usage: $0 [options] headers METHOD URL
usage: $0 [options] curl <...>

options:
    --webid|w webid

EOF
    exit 1
}

sub cmd_set {
    my $webid = shift;

    usage() unless $webid;

    _set_cache($webid);
}

sub cmd_get {
    print _get_cache() , "\n";
}

sub cmd_authenticate {
    usage() unless $webid;

    my $auth = Web::Solid::Auth->new(webid => $webid);

    $auth->make_clean;

    my $auth_url = $auth->make_authorization_request;

    print "Please visit this URL and login:\n\n$auth_url\n\n";

    print "Starting callback server...\n";

    $auth->listen;
}

sub cmd_headers {
    my ($method,$url) = @_;

    usage() unless $method && $url;
    
    my $headers = _headers($method,$url);

    print "$headers\n";
}

sub cmd_curl {
    my (@rest) = @_;

    usage() unless @rest;

    my $method = 'GET';
    my $url = $rest[-1];

    if (@rest) {
        for (my $i = 0 ; $i < @rest ; $i++) {
            if ($rest[$i] eq '-X') {
                $method = $rest[$i+1];
            }
        }
        @rest = map { String::Escape::quote($_) } @rest;
    }

    my $headers = _headers($method,$url);
    my $opts    = join(" ",@rest);
    system("curl $headers $opts") == 0;
}

sub cmd_refresh {
    usage() unless $webid;

    my $auth = Web::Solid::Auth->new(webid => $webid);

    my $data = $auth->make_refresh_token;

    if ($data) {
        print "Refresh ok\n";
    }
    else {
        print "Refresh failed\n";
    }
}

sub _get_cache {
    my $auth = Web::Solid::Auth->new(webid => 'urn:nobody');
    my $cache = $auth->cache;
    path("$cache")->child("default")->slurp;
}

sub _set_cache {
    my $webid = shift;

    my $auth = Web::Solid::Auth->new(webid => 'urn:nobody');
    my $cache = $auth->cache;
    path("$cache")->child("default")->spew($webid);
}

sub _headers {
    my ($method,$url) = @_;

    $webid    //= $url;

    my $auth    = Web::Solid::Auth->new(webid => $webid);

    my $headers = $auth->make_authentication_headers($url,$method);

    unless ($headers) {
        print STDERR "No access tokens found for $webid. Maybe you need to authenticate first?\n";
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

      # Set your default webid
      solid_auth.pl set https://hochstenbach.solidcommunity.net/profile/card#me%

      # Authentication to a pod
      solid_auth.pl authenticate

      # Get the http headers for a authenticated request
      solid_auth.pl headers GET https://hochstenbach.solidcommunity.net/inbox

      # Act like a curl command and fetch authenticated content
      solid_auth.pl curl -X GET https://hochstenbach.solidcommunity.net/inbox

      # Add some data
      solid_auth.pl curl -X POST \
            -H "Content-Type: text/plain" \
            -d "abc" \
            https://hochstenbach.solidcommunity.net/public/

=cut
