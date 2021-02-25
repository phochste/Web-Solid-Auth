package Web::Solid::Auth;

use Moo;
use Crypt::JWT;
use Data::UUID;
use Digest::SHA;
use Log::Any ();
use LWP::UserAgent;
use JSON;
use MIME::Base64;
use Path::Tiny;
use Digest::SHA;
use URI::Escape;
use HTTP::Server::PSGI;
use Data::Dumper;

our $VERSION = "0.1";

has host => (
    is => 'ro' ,
    required => 1
);
has client_id => (
    is => 'ro' ,
    requires => 1
);
has redirect_uri => (
    is => 'ro' ,
    default => sub {
        "http://localhost:3000/"
    }
);
has shorten => (
    is => 'ro'
);
has cache => (
    is => 'ro' ,
    default => sub { $ENV{HOME} . "/.solid"}
);
has log => (
    is => 'ro',
    default => sub { Log::Any->get_logger },
);
has agent => (
    is => 'lazy'
);

sub _build_agent {
    my $ua     = new LWP::UserAgent;
    my $agent  = "Web::Solid::Auth/$VERSION " . $ua->agent;
    $ua;
}

sub _build_pk {
    my $pk = Crypt::PK::ECC->new();
    $pk->generate_key('secp256r1');
    $pk;
}

sub has_access_token {
    my $self = shift;
    my $cache_dir = $self->get_cache_dir;
    my $access = path($cache_dir)->child("access.json");
    $access->exists;
}

sub make_clean {
    my $self = shift;
    my $cache_dir = $self->get_cache_dir;

    $self->log->info("cleaning cache directory $cache_dir");

    my $openid = path($cache_dir)->child("openid.json");
    $openid->remove if $openid->exists;

    my $client = path($cache_dir)->child("client.json");
    $client->remove if $client->exists;

    my $access = path($cache_dir)->child("access.json");
    $access->remove if $access->exists;

    $self;
}

sub make_client {
    my $self = shift;
    my $client_registration = $self->get_client_configuration;
    return undef unless $client_registration;
    $self->{client_id} = $client_registration->{client_id};
    $self;
}

sub make_authorization_request {
    my $self = shift;

    my $redirect_uri      = $self->redirect_uri;

    my $registration_conf = $self->get_client_configuration;
    my $openid_conf       = $self->get_openid_configuration;

    my $authorization_endpoint = $openid_conf->{authorization_endpoint};
    my $client_id              = $registration_conf->{client_id};

    my $code_verifier  = $self->make_random_string;
    my $code_challenge = MIME::Base64::encode_base64url(Digest::SHA::sha256($code_verifier),'');
    $code_challenge  =~ s{=}{};
    my $state          = $self->make_random_string;

    my $url = $self->make_url(
      $authorization_endpoint, {
        code_challenge          => $code_challenge ,
        code_challenge_method   => 'S256' ,
        state                   => $state ,
        scope                   => 'openid profile offline_access' ,
        client_id               => $client_id ,
        response_type           => 'code' ,
        redirect_uri            => $redirect_uri ,
    });

    $self->{state}         = $state;
    $self->{code_verifier} = $code_verifier;

    $self->log->info("generating authorization request: $url");

    return $url;
}

sub make_access_token {
    my ($self,$code) = @_;

    die "need code" unless $code;

    my $redirect_uri      = $self->redirect_uri;

    my $openid_conf       = $self->get_openid_configuration;
    my $registration_conf = $self->get_client_configuration;

    my $token_endpoint    = $openid_conf->{token_endpoint};
    my $client_id         = $registration_conf->{client_id};

    my $dpop_token = $self->make_token_for($token_endpoint,'POST');

    $self->log->info("requesting access token at $token_endpoint");

    my $data = $self->post_json($token_endpoint, {
        grant_type    => 'authorization_code' ,
        client_id     => $client_id ,
        redirect_uri  => $redirect_uri ,
        code          => $code ,
        code_verifier => $self->{code_verifier}
    }, DPoP => $dpop_token);

    return undef unless $data;

    my $cache_dir = $self->get_cache_dir;
    path($cache_dir)->mkpath unless -d $cache_dir;

    my $cache_file = path($cache_dir)->child("access.json")->stringify;
    path($cache_file)->spew(encode_json($data));

    return $data;
}

sub make_refresh_token {
    my ($self) = @_;

    my $access            = $self->get_access_token;

    return undef unless $access->{refresh_token};

    my $openid_conf       = $self->get_openid_configuration;
    my $registration_conf = $self->get_client_configuration;

    my $token_endpoint    = $openid_conf->{token_endpoint};
    my $client_id         = $registration_conf->{client_id};

    my $dpop_token = $self->make_token_for($token_endpoint,'POST');

    $self->log->info("requesting refresh token at $token_endpoint");

    my $data = $self->post($token_endpoint, {
        grant_type    => 'refresh_token' ,
        refresh_token => $access->{refresh_token} ,
        client_id     => $client_id ,
    }, DPoP => $dpop_token);

    return undef unless $data;

    my $cache_dir = $self->get_cache_dir;
    path($cache_dir)->mkpath unless -d $cache_dir;

    my $cache_file = path($cache_dir)->child("access.json")->stringify;
    path($cache_file)->spew(encode_json($data));

    return $data;
}

sub make_authentication_headers {
    my ($self, $uri, $method) = @_;

    my $access  = $self->get_access_token;

    return undef unless $access;

    my $headers =  {
        Authorization => 'DPoP ' . $access->{access_token} ,
        DPoP          => $self->make_token_for($uri,$method)
    };

    return $headers;
}

sub listen {
    my $self = shift;

    $self->log->info("starting callback server on port 3000");

    my $server = HTTP::Server::PSGI->new(
        host => "127.0.0.1",
        port => 3000,
        timeout => 120,
    );

    $server->run(
      sub {
        my $env = shift;

        my $state          = $self->{state};
        my $request_method = $env->{REQUEST_METHOD};
        my $query_string   = $env->{QUERY_STRING};

        $self->log->debug("received: $request_method -> $query_string");

        unless ($request_method eq 'GET' && index($query_string,"state=$state") != -1 ) {
            return [
                  404,
                  [ 'Content-Type' => 'text/plain' ],
                  [ "Failed to get an access_token" ],
            ];
        }

        my %param;
        foreach my $pair (split(/&/,$query_string)){
            my ($name, $value) = split(/=/, $pair, 2);
            $param{$name} = URI::Escape::uri_unescape($value);
        }

        my $data = $self->make_access_token($param{code});

        if ($data) {
            print "Ok stored you can close this program\n";
            return [
                  200,
                  [ 'Content-Type' => 'text/plain' ],
                  [ "Done" ],
            ];
        }
        else {
            return [
                  404,
                  [ 'Content-Type' => 'text/plain' ],
                  [ "Failed to get an access_token" ],
            ];
        }
      }
    );
}

sub get_cache_dir {
    my $self = shift;
    my $host       = $self->host;
    my $host_sha   = Digest::SHA::sha1_hex($host);
    my $cache_dir  = sprintf "%s/%s"
                            , $self->cache
                            , Digest::SHA::sha1_hex($host);
    return $cache_dir;
}

sub get_access_token {
    my $self = shift;

    my $cache_dir = $self->get_cache_dir;

    return undef unless path($cache_dir)->child("access.json")->exists;

    my $cache_file = path($cache_dir)->child("access.json")->stringify;

    $self->log->debug("reading $cache_file");

    my $json = path("$cache_file")->slurp;

    return undef unless $json;

    return decode_json($json);
}

sub get_client_configuration {
    my $self = shift;

    my $cache_dir = $self->get_cache_dir;
    path($cache_dir)->mkpath unless -d $cache_dir;

    my $openid_conf           = $self->get_openid_configuration;
    my $redirect_uri          = $self->redirect_uri;
    my $registration_endpoint = $openid_conf->{registration_endpoint};

    my $cache_file = path($cache_dir)->child("client.json")->stringify;

    unless (-f $cache_file) {
        $self->log->info("registering client at $registration_endpoint");

        # Get the well known openid
        my $data = $self->post_json($registration_endpoint, {
            grant_types      => ["authorization_code"],
            redirect_uris    => [ $redirect_uri ] ,
            response_types   => ["id_token token"],
            scope            => "openid profile offline_access",
            application_type => "web"
        });

        return undef unless $data;

        $self->log->debug("generating $cache_file");

        path("$cache_file")->spew(encode_json($data));
    }

    $self->log->debug("reading $cache_file");

    my $json = path("$cache_file")->slurp;

    return undef unless $json;

    return decode_json($json);
}

sub get_openid_configuration {
    my ($self) = @_;

    my $host      = $self->host;

    my $cache_dir = $self->get_cache_dir;
    path($cache_dir)->mkpath unless -d $cache_dir;

    my $cache_file = path($cache_dir)->child("openid.json")->stringify;

    unless (-f $cache_file) {
        my $url = "$host/.well-known/openid-configuration";

        $self->log->info("reading openid configruation from $url");

        # Get the well known openid
        my $data = $self->get_json($url);

        return undef unless $data;

        $self->log->debug("generating $cache_file");

        path($cache_file)->spew(encode_json($data));
    }

    $self->log->debug("reading $cache_file");

    my $json = path($cache_file)->slurp;

    return undef unless $json;

    return decode_json($json);
}

sub get_key_configuration {
    my ($self) = @_;

    my $cache_dir = $self->get_cache_dir;
    path($cache_dir)->mkpath unless -d $cache_dir;

    my $cache_file = path($cache_dir)->child("key.json")->stringify;

    unless (-f $cache_file) {
        # Get the well known openid
        my $pk = Crypt::PK::ECC->new();
        $pk->generate_key('secp256r1');

        $self->log->debug("generating $cache_file");

        path($cache_file)->spew(encode_json({
          public  => $pk->export_key_jwk('public') ,
          private => $pk->export_key_jwk('private')
        }));
    }

    $self->log->debug("reading $cache_file");

    my $json = path($cache_file)->slurp;

    return undef unless $json;

    my $pk   = Crypt::PK::ECC->new();
    my $priv = decode_json($json)->{private};
    $pk->import_key(\$priv);

    return $pk;
}

## Networking

sub get {
    my ($self, $url, %opts) = @_;

    my $response = $self->agent->get($url, %opts);

    unless ($response->is_success) {
        $self->log->errorf("failed to GET($url): %s" , $response);
        return undef;
    }

    return $response->decoded_content;
}

sub get_json {
    my ($self, $url, %opts) = @_;
    return decode_json($self->get($url, %opts));
}

sub post {
    my ($self, $url, $data, %opts) = @_;

    my $response = $self->agent->post($url,$data,%opts);

    unless ($response->is_success) {
        $self->log->errorf("failed to POST($url): %s",$response);
        return undef;
    }

    return $response->decoded_content;
}

sub post_json {
    my ($self, $url, $data, %opts) = @_;

    $opts{'Content-Type'} //= 'application/json';

    my $response = $self->agent->post($url,
        %opts ,
        Content => encode_json($data)
    );

    unless ($response->is_success) {
        $self->log->errorf("failed to POST($url): %s",$response);
        return undef;
    }

    return decode_json($response->decoded_content);
}

sub make_url {
    my ($self, $url,$params) = @_;

    my @qparam = ();

    for my $key (keys %{$params // {} }) {
        my $value = URI::Escape::uri_escape($params->{$key});
        push @qparam , "$key=$value";
    }

    if (@qparam) {
        $url .= "?" . join("&", @qparam);
    }

    $url;
}

# Crypto

sub make_random_string {
    my $self = shift;
    my $str = MIME::Base64::encode_base64url(Data::UUID->new->create());
    $str;
}

sub make_token_for {
    my ($self, $uri, $method) = @_;

    my $pk = $self->get_key_configuration;

    my $header = {
          typ => 'dpop+jwt' ,
          alg => 'ES256' ,
          jwk => JSON::decode_json($pk->export_key_jwk('public')) ,
    };

    $self->log->debugf("DPoP(header) %s" , $header);

    my $payload = {
          jti => $self->make_random_string,
          htm => $method ,
          htu => $uri ,
          iat => time ,
    };

    $self->log->debugf("DPoP(payload) %s" , $payload);

    my $token = Crypt::JWT::encode_jwt(
          payload => $payload ,
          key => $pk ,
          alg => 'ES256' ,
          extra_headers => $header
    );

    return $token;
}


1;
