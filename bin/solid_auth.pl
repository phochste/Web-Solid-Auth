#!/usr/bin/env perl
$|++;

use lib qw(./lib);
use Getopt::Long qw(:config pass_through);
use Web::Solid::Auth;
use Web::Solid::Auth::Agent;
use Web::Solid::Auth::Util;
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

GetOptions(
    "clientid|c=s" => \$clientid ,
    "webid|w=s"    => \$webid ,
    "base|b=s"     => \$webbase ,
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
# Login
usage: $0 [options] authenticate

# Curl like interaction
usage: $0 [options] headers METHOD URL
usage: $0 [options] curl <...>

# Interpret LDP responses
usage: $0 [options] list /path/ | url    # folder listing

# Simple HTTP interaction
usage: $0 [options] get /path | url
usage: $0 [options] put (/path/ | url)   # create a folder 
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

    unless ($url) {
        print STDERR "Need a url\n\n";
        usage();
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
        my $type = $res->value('type')->as_string;
        
        $FILES{$url . $name} = $type =~ /Container/ ? "container" : "resource";
    });

    for my $file (sort keys %FILES) {
        my $type = $FILES{$file};

        printf "%s $file\n" , $type eq 'container' ? "d" : "-";
    }
}

sub cmd_get {
    my ($url) = @_;

    unless ($url) {
        print STDERR "Need a url\n\n";
        usage();
    }

    my $iri = _make_url($url);

    my $response = $agent->get($iri);

    unless ($response->is_success) {
        printf STDERR "%s - failed to $url\n" , $response->code;
        printf STDERR "%s\n" , $response->message;
        return 2;
    }

    print $response->decoded_content;

    return 0;
}

sub cmd_head {
    my ($url) = @_;

    unless ($url) {
        print STDERR "Need a url\n\n";
        usage();
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
        print STDERR "Need a url\n\n";
        usage();
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
        print STDERR "Need a url\n\n";
        usage();
    }

    if ($url =~ /\/$/ && ($file || $mimeType)) {
        print STDERR "Folder names can't have file uploads\n\n";
        usage();
    }
    elsif ($url !~ /\/$/ && ! ($file || $mimeType)) {
        print STDERR "Need url file and mimeType\n\n";
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
        print STDERR "Need url file and mimeType\n\n";
        usage();
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
        print STDERR "Need a url\n\n";
        usage();
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

=cut
