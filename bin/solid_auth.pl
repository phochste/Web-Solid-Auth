#!/usr/bin/env perl
$|++;

use lib qw(./lib);
use Getopt::Long qw(:config pass_through);
use Web::Solid::Auth;
use Web::Solid::Auth::Agent;
use Web::Solid::Auth::Util;
use HTTP::Date;
use MIME::Base64;
use JSON;
use Path::Tiny;
use String::Escape;
use Log::Any::Adapter;

Log::Any::Adapter->set('Log4perl');
Log::Log4perl::init('log4perl.conf');

my $webid    = $ENV{SOLID_WEBID};
my $webbase  = $ENV{SOLID_REMOTE_BASE};
my $clientid = $ENV{SOLID_CLIENT_ID};
my $opt_recursive = undef;
my $opt_skip      = undef;

GetOptions(
    "clientid|c=s" => \$clientid ,
    "webid|w=s"    => \$webid ,
    "base|b=s"     => \$webbase ,
    "r"            => \$opt_recursive ,
    "skip"         => \$opt_skip ,
);

my $cmd = shift;

unless ($webid)  {
    print STDERR "Need a webid or SOLID_WEBID environment variable\n\n";
    usage();
}

my $auth = Web::Solid::Auth->new(webid => $webid);
my $agent = Web::Solid::Auth::Agent->new(auth => $auth);

my $ret;

if (0) {}
elsif ($cmd eq 'list') {
    $ret = cmd_list(@ARGV);
}
elsif ($cmd eq 'get') {
    $ret = cmd_get(@ARGV);
}
elsif ($cmd eq 'put') {
    $ret = cmd_put(@ARGV);
}
elsif ($cmd eq 'post') {
    $ret = cmd_post(@ARGV);
}
elsif ($cmd eq 'delete') {
    $ret = cmd_delete(@ARGV);
}
elsif ($cmd eq 'head') {
    $ret = cmd_head(@ARGV);
}
elsif ($cmd eq 'options') {
    $ret = cmd_options(@ARGV);
}
elsif ($cmd eq 'mirror') {
    $ret = cmd_mirror(@ARGV);
}
elsif ($cmd eq 'authenticate') {
    $ret = cmd_authenticate(@ARGV);
}
elsif ($cmd eq 'headers') {
    $ret = cmd_headers(@ARGV);
}
elsif ($cmd eq 'curl') {
    $ret = cmd_curl(@ARGV);
}
elsif ($cmd eq 'id_token') {
    $ret = cmd_id_token(@ARGV);
}
elsif ($cmd eq 'access_token') {
    $ret = cmd_access_token(@ARGV);
}
else {
    usage();
}

exit($ret);

sub usage {
    print STDERR <<EOF;
Usage
-=-=-=

# Login
usage: $0 [options] authenticate

# Curl like interaction
usage: $0 [options] headers METHOD URL
usage: $0 [options] curl <...>

# Interpret LDP responses
usage: $0 [options] list /path/ | url        # folder listing
usage: $0 [options] mirror /path directory   # mirror a container/resource , use [-r] for recursice mirror

# Simple HTTP interaction
usage: $0 [options] get /path | url
usage: $0 [options] put (/path/ | url)       # create a folder 
usage: $0 [options] put (/path | url) file mimeType
usage: $0 [options] post (/path | url) file mimeType
usage: $0 [options] head /path | url
usage: $0 [options] options /path | url
usage: $0 [options] delete /path | url

# Check the credentials
usage: $0 access_token
usage: $0 id_token

options:
    --webid|w webid          - your webid
    --clientid|c clientid    - optional the client-id
    --base|b base            - optional the base url for all requests

EOF
    exit 1
}

sub cmd_list {
    my ($url) = @_;

    my $files = _cmd_list($url);

    return $files if $files && ref($files) eq '';

    for my $file (sort keys %$files) {
        my $type = $files->{$file};

        printf "%s $file\n" , $type eq 'container' ? "d" : "-";
    }

    return 0;
}

sub _cmd_list {
    my ($url) = @_;

    unless ($url) {
        print STDERR "Need a url\n";
        return 1;
    }

    unless ($url =~ /\/$/) {
        print STDERR "$url doesn't look like a container\n";
        return 1;
    }

    my $iri = _make_url($url);

    my $response = $agent->get($iri);

    unless ($response->is_success) {
        printf STDERR "%s - failed to $url\n" , $response->code;
        printf STDERR "%s\n" , $response->message;
        return 2;
    }

    my $util  = Web::Solid::Auth::Util->new;
    my $model = $util->parse_turtle($response->decoded_content);

    my $sparql =<<EOF;
prefix ldp: <http://www.w3.org/ns/ldp#> 

SELECT ?folder ?type {
    ?folder a ?type .
    FILTER (?type IN (ldp:BasicContainer, 
                      ldp:Container,
                      ldp:Resource,
                      ldp:NonRDFSource
                      ) 
            )
}
EOF

    my %FILES;

    $util->sparql($model, $sparql, sub {
        my $res = shift;
        my $name = $res->value('folder')->as_string; 
        $name =~ s/^\///; 
        my $type = $res->value('type')->as_string;

        $FILES{$url . $name} = $type =~ /Container/ ? "container" : "resource";
    });

    return \%FILES;
}

sub cmd_get {
    my ($url) = @_; 

    my $response = _cmd_get($url);

    return $response if $response && ref($response) eq '';

    print $response->decoded_content;

    return 0;
}

sub _cmd_get {
    my ($url,%headers) = @_;

    unless ($url) {
        print STDERR "Need a url\n";
        return 1;
    }

    my $iri = _make_url($url);

    my $response = $agent->get($iri,%headers);

    unless ($response->is_success) {
        printf STDERR "%s - failed to $url\n" , $response->code;
        printf STDERR "%s\n" , $response->message;
        return 2;
    }

    $response;
}

sub cmd_head {
    my ($url) = @_;

    unless ($url) {
        print STDERR "Need a url\n";
        return 1;
    }

    my $iri = _make_url($url);

    my $response = $agent->head($iri);

    unless ($response->is_success) {
        printf STDERR "%s - failed to $url\n" , $response->code;
        printf STDERR "%s\n" , $response->message;
        return 2;
    }

    for my $header ($response->header_field_names) {
        printf "%s: %s\n" , $header , $response->header($header);
    }

    return 0;
}

sub cmd_options {
    my ($url) = @_;

    unless ($url) {
        print STDERR "Need a url\n";
        return 1;
    }

    my $iri = _make_url($url);

    my $response = $agent->options($iri);

    unless ($response->is_success) {
        printf STDERR "%s - failed to $url\n" , $response->code;
        printf STDERR "%s\n" , $response->message;
        return 2;
    }

    for my $header ($response->header_field_names) {
        printf "%s: %s\n" , $header , $response->header($header);
    }

    return 0;
}

sub cmd_put {
    my ($url, $file, $mimeType) = @_;

    unless ($url) {
        print STDERR "Need a url\n";
        return 1;
    }

    if ($url =~ /\/$/ && ($file || $mimeType)) {
        print STDERR "Folder names can't have file uploads\n\n";
        usage();
    }
    elsif ($url !~ /\/$/ && ! ($file || $mimeType)) {
        print STDERR "Need url file and mimeType\n";
        usage();
    }

    my $data;
    
    if ($file) {
        $data = path($file)->slurp_raw;
    }

    my $iri = _make_url($url);

    my $response;

    if ($file) {
        $response = $agent->put($iri, $data, 'Content-Type' => $mimeType);
    }
    else {
        $response = $agent->put($iri);
    }

    unless ($response->is_success) {
        printf STDERR "%s - failed to $url\n" , $response->code;
        printf STDERR "%s\n" , $response->message;
        return 2;
    }

    print STDERR $response->decoded_content , "\n";

    return 0;
}

sub cmd_post {
    my ($url, $file, $mimeType) = @_;

    unless ($url && $file && -r $file && $mimeType) {
        print STDERR "Need url file and mimeType\n";
        return 1;
    }

    my $data = path($file)->slurp_raw;

    my $iri = _make_url($url);

    my $response = $agent->post($iri, $data, 'Content-Type' => $mimeType);

    unless ($response->is_success) {
        printf STDERR "%s - failed to $url\n" , $response->code;
        printf STDERR "%s\n" , $response->message;
        return 2;
    }

    print STDERR $response->decoded_content , "\n";

    print $response->header('Location') , "\n";

    return 0;
}

sub cmd_delete {
    my ($url) = @_;

    unless ($url) {
        print STDERR "Need a url\n";
        return 1;
    }

    my $iri = _make_url($url);

    my $response = $agent->delete($iri);

    unless ($response->is_success) {
        printf STDERR "%s - failed to $url\n" , $response->code;
        printf STDERR "%s\n" , $response->message;
        return 2;
    }

    print STDERR $response->decoded_content , "\n";

    return 0;
}

sub cmd_mirror {
    my ($url,$directory) = @_;

    unless ($directory && -d $directory) {
        print STDERR "Need a directory\n";
        return 2;
    }

    if ($url =~ /\/$/) {
        # ok we are a container
    }
    else {
        return _cmd_mirror($url,$directory);
    }

    my $files = _cmd_list($url);

    return $files if $files && ref($files) eq '';

    for my $file (sort keys %$files) {
        my $type = $files->{$file};
        my $base = substr($file,length($url));
        $base =~ s{\/$}{};
        if ($type eq 'container') {
            if ($file ne $url && $base !~ /^\./ && $opt_recursive) {
                path("$directory/$base")->mkpath;
                cmd_mirror($file,"$directory/$base");
            }
        }
        else {
            _cmd_mirror($file,$directory);
        }
    }
}

sub _cmd_mirror {
    my ($url,$directory) = @_;

    my $path = $url;
    $path =~ s{.*\/}{};

    print "$url -> $directory/$path\n";

    my %headers = ();

    if ($opt_skip && -e "$directory/$path" ) {
        print STDERR "skipping $directory/$path - already exists\n";
        return 0;
    }

    if (-e "$directory/$path") {
        my ($mtime) = ( stat("$directory/$path") )[9];
        $headers{'If-Modified-Since'} = HTTP::Date::time2str($mtime);
    }

    my $response = _cmd_get($url,%headers);

    return $response unless $response && ref($response) ne '';

    path("$directory/$path")->spew_raw($response->decoded_content);

    return 0;
}

sub cmd_authenticate {
    $auth->make_clean;

    my $auth_url = $auth->make_authorization_request;

    print "Please visit this URL and login:\n\n$auth_url\n\n";

    print "Starting callback server...\n";

    $auth->listen;

    return 0;
}

sub cmd_headers {
    my ($method,$url) = @_;

    usage() unless $method && $url;

    my $headers = _headers($method,$url);

    print "$headers\n";

    return 0;
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

sub cmd_access_token {
    my $access = $auth->get_access_token;

    unless ($access && $access->{access_token}) {
        print STDERR "No access_token found. You are not logged in yet?\n";
        return 2;
    }

    my $token = $access->{access_token};

    my ($header,$payload,$signature) = split(/\./,$token,3);

    unless ($header && $payload, $signature) {
        printf STDERR "Token is not a jwt token\n";
    }

    my $json = JSON->new->pretty;

    $header  = JSON::decode_json(MIME::Base64::decode_base64url($header));
    $payload = JSON::decode_json(MIME::Base64::decode_base64url($payload));

    printf "Header: %s\n" , $json->encode($header);
    printf "Payload: %s\n" , $json->encode($payload);
    printf "Signature: (binary data)\n", MIME::Base64::decode_base64url($signature);

    return 0;
}

sub cmd_id_token {
    my $access = $auth->get_access_token;

    unless ($access && $access->{id_token}) {
        print STDERR "No access_token found. You are not logged in yet?\n";
        return 2;
    }

    my $token = $access->{id_token};

    my ($header,$payload,$signature) = split(/\./,$token,3);

    unless ($header && $payload, $signature) {
        printf STDERR "Token is not a jwt token\n";
    }

    my $json = JSON->new->pretty;

    $header  = JSON::decode_json(MIME::Base64::decode_base64url($header));
    $payload = JSON::decode_json(MIME::Base64::decode_base64url($payload));

    printf "Header: %s\n" , $json->encode($header);
    printf "Payload: %s\n" , $json->encode($payload);
    printf "Signature: (binary data)\n", MIME::Base64::decode_base64url($signature);

    return 0;
}

sub _make_url {
    my $url = shift;

    return $url unless defined($webbase);

    return $url unless $url =~ /^\.?(\/.*)?/;

    return "$webbase$1";
}

sub _headers {
    my ($method,$url) = @_;

    $webid //= $url;

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
      export SOLID_WEBID=https://hochstenbach.inrupt.net/profile/card#me

      # Authentication to a pod
      solid_auth.pl authenticate

      # Get the http headers for a authenticated request
      solid_auth.pl headers GET https://hochstenbach.inrupt.net/inbox/

      # Act like a curl command and fetch authenticated content
      solid_auth.pl curl -X GET https://hochstenbach.inrupt.net/inbox/

      # Add some data
      solid_auth.pl curl -X POST \
            -H "Content-Type: text/plain" \
            -d "abc" \
            https://hochstenbach.inrupt.net/public/
    
      # Add a file
      solid_auth.pl curl -X PUT \
            -H "Content-Type: application/ld+json" \
            -d "@myfile.jsonld" \
            https://hochstenbach.inrupt.net/public/myfile.jsonld 

      # Set a solid base url
      export SOLID_REMOTE_BASE=https://hochstenbach.inrupt.net

      # List all resources on some Pod path
      solid_auth.pl list /public/

      # Get some data
      solid_auth.pl get /inbox/

      # Post some data
      solid_auth.pl post /inbox/ myfile.jsonld "application/ld+json"

      # Put some data
      solid_auth.pl put /public/myfile.txt myfile.txt "text/plain"

      # Create a folder
      solid_auth.pl put /public/mytestfolder/

      # Delete some data
      solid_auth.pl delete /public/myfile.txt

      # Mirror a resource, container or tree
      mkdir /data/my_copy
      solid_auth.pl -r mirror /public/ /data/my_copy

=head1 ENVIRONMENT

=over

=item SOLID_WEBID

Your WebId 

=item SOLID_REMOTE_BASE

The Base URL that is used for all delete, get, head, options post, put, patch requests

=item SOLID_CLIENT_ID

The URL to a static client configuration. See C<etc/web-solid-auth.jsonld> for an example.
This file, edited for your own environment, needs to be published on some public accessible
webserver.

=back

=head1 INSPIRATION

This was very much inspired by the Python solid-flask code by
Rai L<http://agentydragon.com> at L<https://gitlab.com/agentydragon/solid-flask>,
and Jeff Zucker's <https://github.com/jeff-zucker> Solid-Shell at L<https://www.npmjs.com/package/solid-shell>.

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2021 by Patrick Hochstenbach.

This is free software; you can redistribute it and/or modify it under the same terms as the Perl 5 programming language system itself.

=encoding utf8

=cut
