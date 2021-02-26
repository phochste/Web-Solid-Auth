package Web::Solid::Auth::Listener;

use Moo;
use Log::Any ();
use Plack::Request;
use Plack::Response;
use HTTP::Server::PSGI;

our $VERSION = "0.1";

has host => (
    is => 'ro' ,
    required => 1
);
has port => (
    is => 'ro' ,
    required => 1
);
has auth => (
    is => 'ro' ,
    required => 1
);
has path => (
    is => 'ro',
    default => sub { '/' }
);
has log => (
    is => 'ro',
    default => sub { Log::Any->get_logger },
);

sub run {
    my $self = shift;

    my $host = $self->host;
    my $port = $self->port;
    my $path = $self->path;

    $self->log->info("starting callback server on $host:$port$path");

    my $server = HTTP::Server::PSGI->new(
        host => $host,
        port => $port,
        timeout => 120,
    );

    $server->run(
      sub {
        my $env = shift;

        my $req    = Plack::Request->new($env);
        my $param  = $req->parameters;
        my $state  = $self->auth->{state};

        $self->log->debugf("received: %s (%s) -> %s", $req->method, $req->path, $req->query_string);

        # Check if we got the correct path
        unless ($req->path eq $path) {
            my $res = Plack::Response->new(404);
            $res->content_type("text/plain");
            $res->body("No such path");
            return $res->finalize;
        }

        # Check if we got the correct state
        unless ($req->method eq 'GET' && $param->{code} && $param->{state} eq $state ) {
            my $res = Plack::Response->new(404);
            $res->content_type("text/plain");
            $res->body("Failed to get an access_token");
            return $res->finalize;
        }

        my $data = $self->auth->make_access_token($param->{code});

        if ($data) {
            print "Ok stored you can close this program\n";
            my $res = Plack::Response->new(200);
            $res->content_type("text/plain");
            $res->body("You al logged in :)");
            return $res->finalize;
        }
        else {
            my $res = Plack::Response->new(404);
            $res->content_type("text/plain");
            $res->body("Failed to get an access_token");
            return $res->finalize;
        }
      }
    );
}

1;
