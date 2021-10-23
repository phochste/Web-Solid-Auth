package Web::Solid::Auth;

use Moo;
use Crypt::JWT;
use Data::Dumper;
use Data::UUID;
use Digest::SHA;
use HTTP::Link;
use HTTP::Request;
use HTTP::Server::PSGI;
use Log::Any ();
use LWP::UserAgent;
use JSON;
use MIME::Base64;
use Path::Tiny;
use URI::Escape;
use Plack::Request;
use Plack::Response;
use Web::Solid::Auth::Listener;
use Web::Solid::Auth::Util;

our $VERSION = "0.91";

has webid => (
    is => 'ro' ,
    required => 1
);
has redirect_uri => (
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
has listener => (
    is => 'lazy'
);
has issuer => (
    is => 'lazy'
);
has client_id => (
    is => 'ro',
);

sub _build_agent {
    my $ua = LWP::UserAgent->new(agent => "Web::Solid::Auth/$VERSION");
    $ua;
}

sub _build_listener {
    Web::Solid::Auth::Listener->new;
}

sub _build_issuer {
    shift->get_openid_provider();
}

sub BUILD {
    my $self = shift;
    $self->{redirect_uri} //= $self->listener->redirect_uri;
}

sub listen {
    my $self = shift;
    $self->listener->run($self);
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
    my $token_endpoint_auth_methods_supported = $openid_conf->{token_endpoint_auth_methods_supported} // [];

    # Make an array out of an string...
    $token_endpoint_auth_methods_supported = 
            ref($token_endpoint_auth_methods_supported) eq 'ARRAY' ?
                $token_endpoint_auth_methods_supported :
                [$token_endpoint_auth_methods_supported];

    my $client_id         = $registration_conf->{client_id};
    my $client_secret     = $registration_conf->{client_secret};

    my $dpop_token = $self->make_token_for($token_endpoint,'POST');

    $self->log->info("requesting access token at $token_endpoint");

    my $token_request  = {
        grant_type    => 'authorization_code' ,
        client_id     => $client_id ,
        redirect_uri  => $redirect_uri ,
        code          => $code ,
        code_verifier => $self->{code_verifier}
    };

    my %headers = (
        'Content-Type' => 'application/x-www-form-urlencoded' ,
        DPoP => $dpop_token
    );

    if (grep(/^client_secret_basic/, @$token_endpoint_auth_methods_supported)) {
        $self->log->info('using client_secret_basic');
        $headers{'Authorization'} = 'Basic ' . MIME::Base64::encode_base64url("$client_id:$client_secret");
    }
    elsif (grep(/^client_secret_post/, @$token_endpoint_auth_methods_supported)) {
        $self->log->info('using client_secret_post');
        $token_request->{client_secret} = $client_secret;
    }

    my $data = $self->post( $token_endpoint, $token_request , %headers );

    return undef unless $data;

    $data = decode_json($data);

    $self->log->infof("received: %s", $data);

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

sub get_cache_dir {
    my $self = shift;
    my $webid      = $self->webid;

    die "No webid set" unless $webid;

    my $webid_sha  = Digest::SHA::sha1_hex($webid);
    my $cache_dir  = sprintf "%s/%s"
                            , $self->cache
                            , Digest::SHA::sha1_hex($webid);
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

sub get_openid_provider {
    my ($self, $webid) = @_;
    $webid //= $self->webid;

    # First try to find the OIDC issuer in the WebID profile
    my $issuer = $self->get_webid_openid_provider($webid);

    return $issuer if $issuer;

    # If nothing is found there, try the OPTIONS header Links

    my $res = $self->options($webid);

    return undef unless $res;

    my $link = $res->header('Link');

    my @links = HTTP::Link->parse($link);

    for (@links) {
      if ($_->{relation} eq 'http://openid.net/specs/connect/1.0/issuer') {
          $issuer = $_->{iri};
      }
    }

    return $issuer;
}

sub get_webid_openid_provider {
    my ($self, $webid) = @_;
    $webid //= $self->webid;

    # Lets try plain JSON parsing for fun..
    my $res = $self->get($webid, 'Accept' => 'text/turtle');

    return undef unless $res;

    my $util  = Web::Solid::Auth::Util->new;
    my $model = $util->parse_turtle($res);

    my $sparql =<<EOF;
SELECT ?oidcIssuer {
    ?subject <http://www.w3.org/ns/solid/terms#oidcIssuer> ?oidcIssuer .
}
EOF

    my $issuer;
    $util->sparql($model, $sparql, sub {
        my $res = shift;
        $issuer = $res->value('oidcIssuer')->as_string;
    });

    return $issuer;
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
        if ($self->client_id) {
            $self->log->info("using client document at " . $self->client_id);

            my $data = $self->get_json($self->client_id);
            $self->log->debug("generating $cache_file");

            path("$cache_file")->spew(encode_json($data));
        }
        else {
            $self->log->info("registering client at $registration_endpoint");

            # Dynamic register the client. We request the openid and profile
            # scopes that are default for OpenID. The offline_access is
            # to be able to request refresh_tokens (not yet implemented).
            # The only safe response type is 'code' all other options send
            # sensitive data over the front channel and shouldn't be used.
            my $data = $self->post_json($registration_endpoint, {
                grant_types      => ["authorization_code", "refresh_token"],
                redirect_uris    => [ $redirect_uri ] ,
                scope            => "openid profile offline_access" ,
                response_types   => ["code"]
            });

            return undef unless $data;

            $self->log->infof("received %s", $data);

            $self->log->debug("generating $cache_file");

            path("$cache_file")->spew(encode_json($data));
        }
    }

    $self->log->debug("reading $cache_file");

    my $json = path("$cache_file")->slurp;

    return undef unless $json;

    return decode_json($json);
}

sub get_openid_configuration {
    my ($self) = @_;

    my $issuer    = $self->issuer;
    
    # remove trailing slash (we will add it)
    $issuer =~ s{\/$}{};

    my $cache_dir = $self->get_cache_dir;
    path($cache_dir)->mkpath unless -d $cache_dir;

    my $cache_file = path($cache_dir)->child("openid.json")->stringify;

    unless (-f $cache_file) {
        my $url = "$issuer/.well-known/openid-configuration";

        $self->log->info("reading openid configruation from $url");

        # Get the well known openid
        my $data = $self->get_json($url);

        return undef unless $data;

        $self->log->infof("received %s", $data);

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
        # Create an P-256 elliptic curve key we will use in DPoP
        # headers.
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

    my $response = $self->agent->post($url,
          %opts,
          Content => $data
    );

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

sub options {
    my ($self, $url) = @_;

    my $response = $self->agent->request(
        HTTP::Request->new(OPTIONS => $url)
    );

    unless ($response->is_success) {
        $self->log->errorf("failed to OPTIONS($url): %s" , $response);
        return undef;
    }

    return $response;
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
    my $str = MIME::Base64::encode_base64url(
                    Data::UUID->new->create() .
                    Data::UUID->new->create() .
                    Data::UUID->new->create() 
            );
    $str;
}

sub make_token_for {
    my ($self, $uri, $method) = @_;

    # With DPoP headers access_tokens can be protected. When requesting
    # an access_token from a token_endpoint a DPoP headers is included
    # which contains our public key (inside the signed token header).
    # Our public key will then be part of the returned access_token.
    #
    # When later on you will send the access_token to a resource provider
    # it can check the signed DPoP header in combination with our public
    # key in the access_token that you are in posession of the private key
    # that matches the public key in the access_token.
    #
    # In this way, when some evil resource provider steals your access_token
    # it can't be reused without your private key.

    my $pk = $self->get_key_configuration;

    my $header = {
          typ => 'dpop+jwt' ,
          alg => 'ES256' ,
          jwk => JSON::decode_json($pk->export_key_jwk('public')) ,
    };

    $self->log->debugf("DPoP(header) %s" , $header);

    my $payload = {
          # A jti is a random string that protects the token_endpoint server
          # against replay attacks
          jti => $self->make_random_string,
          # Limits the DPoP token only to this method
          htm => $method ,
          # Limits the DPop token only to this uri
          htu => $uri ,
          # The time this token was issued
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

__END__

=head1 NAME

Web::Solid::Auth - A Perl Solid Web Client

=head1 SYNOPSIS

    # On the command line

    # Set your default webid
    export SOLID_WEBID=https://timbl.inrupt.net/profile/card#me

    # Authentication to a pod
    solid_auth.pl authenticate

    # Get the http headers for a authenticated request
    solid_auth.pl headers GET https://timbl.inrupt.net/inbox/

    # Act like a curl command and fetch authenticated content
    solid_auth.pl curl -X GET https://timbl.inrupt.net/inbox/

    # Add some data
    solid_auth.pl curl -X POST \
            -H "Content-Type: text/plain" \
            -d "abc" \
            https://timbl.inrupt.net/public/
    
    # Add a file
    solid_auth.pl curl -X PUT \
            -H "Content-Type: application/ld+json" \
            -d "@myfile.jsonld" \
            https://timbl.inrupt.net/public/myfile.jsonld 

    # Set a solid base url
    export SOLID_REMOTE_BASE=https://timbl.inrupt.net

    # List all resources on some Pod path
    solid_auth.pl list /public/

    # Get some data
    solid_auth.pl get /inbox/

    # Post some data
    solid_auth.pl post /inbox/ myfile.jsonld 

    # Put some data
    solid_auth.pl put /public/myfile.txt myfile.txt 

    # Create a folder
    solid_auth.pl put /public/mytestfolder/

    # Delete some data
    solid_auth.pl delete /public/myfile.txt

    # Mirror a resource, container or tree
    solid_auth.pl mirror /public/ ./my_copy

    # Upload a directory to the pod
    #  Add the -x option to do it for real (only a test without this option)
    solid_auth.pl -r upload /data/my_copy /public/

    # Clean all files in a container
    #  Add the -x option to do it for real (only a test without this option)
    solid_auth.pl --keep clean /demo/

    # Clean a complete container 
    #  Add the -x option to do it for real (only a test without this option)
    solid_auth.pl -r clean /demo/

    # In a perl program
    use Web::Solid::Auth;
    use Web::Solid::Auth::Listener;

    # Create a new authenticator for a pod
    my $auth = Web::Solid::Auth->new(webid => $webid);

    # Or tune a listerner
    my $auth = Web::Solid::Auth->new(
          webid     => $webid ,
          listener => Web::Solid::Auth::Listener->new(
                scheme => 'https'
                host   => 'my.server.org'
                port   => '443' ,
                path   => '/mycallback'
          )
    );

    # Or, in case you have your own callback server
    my $auth = Web::Solid::Auth->new(
          webid         => $webid,
          redirect_uri => 'https://my.server.org/mycallback'
    );

    # Generate a url for the user to authenticate
    my $auth_url = $auth->make_authorization_request;

    # Listen for the oauth server to return tokens
    # the built-in listener for feedback from the openid provider
    # Check the code of Web::Solid::Auth::Listener how to
    # do this inside your own Plack application
    $auth->listen;

    ####

    # If you already have access_tokens from previous step
    if ($auth->has_access_token) {
        # Fetch the Authentication and DPoP HTTP headers for a
        # request to an authorized resource
        my $headers = $auth->make_authentication_headers($resource_url,$http_method);

        #..do you curl..lwp::agent..or what ever with the headers
    }

=head1 INSTALLATION

See the L<https://metacpan.org/dist/Web-Solid-Auth/source/INSTALL> file in the 
distribution.

=head1 DESCRIPTION

This is a Solid-OIDC implementation of a connection class for the Solid
server. Use the C<bin/solid_auth.pl> command as a command line implementation.
Check out the C<example> directory for a demo web application.

=head1 CONFIGURATION

=over

=item webid

The Solid Webid to authenticate.

=item cache

The location of the cache directory with connection parameters.

=back

=head1 METHODS

=over

=item has_access_token()

Returns a true value when a cache contains an access token for the C<webid>.

=item make_clean()

Clear the cache directory.

=item make_authorization_request()

Return an authorization URL that the use should open to authenticate this
application.

=item make_access_token($code)

When on the redirect url you get a C<code> from the authentication server you
can use this method to get an access_token for the code.

=item listen()

Create a small built-in web server to listen for token responses from the
authentication server.

=item get_access_token()

Return the cached access_token.

=back

=head1 SEE ALSO

L<solid_auth.pl>

=head1 INSPIRATION

This was very much inspired by the Python solid-flask code by
Rai L<http://agentydragon.com> at L<https://gitlab.com/agentydragon/solid-flask>,
and Jeff Zucker's <https://github.com/jeff-zucker> Solid-Shell at L<https://www.npmjs.com/package/solid-shell>.

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2021 by Patrick Hochstenbach.

This is free software; you can redistribute it and/or modify it under the same terms as the Perl 5 programming language system itself.

=encoding utf8

=cut
