package Web::Solid::Auth::Agent;

use Moo;

extends 'LWP::UserAgent';

has auth => (
    is => 'ro' ,
    required => 1
);

sub get {
    my ($self, $url , %opts ) = @_;
    my $dpop = $self->auth->make_token_for($url,'GET');
    $opts{DPoP} = $dpop if $dpop;
    return $self->SUPER::get($url,%opts);
}

sub head {
    my ($self, $url , %opts ) = @_;
    my $dpop = $self->auth->make_token_for($url,'HEAD');
    $opts{DPoP} = $dpop if $dpop;
    return $self->SUPER::head($url,%opts);
}

sub delete {
    my ($self, $url , %opts ) = @_;
    my $dpop = $self->auth->make_token_for($url,'DELETE');
    $opts{DPoP} = $dpop if $dpop;
    return $self->SUPER::delete($url,%opts);
}

sub post {
    my ($self, $url ,$data, %opts ) = @_;
    my $dpop = $self->auth->make_token_for($url,'POST');
    $opts{DPoP} = $dpop if $dpop;
    return $self->SUPER::post($url,$data,%opts);
}

sub put {
    my ($self, $url ,$data, %opts ) = @_;
    my $dpop = $self->auth->make_token_for($url,'PUT');
    $opts{DPoP} = $dpop if $dpop;
    return $self->SUPER::put($url,$data,%opts);
}

sub patch {
    my ($self, $url ,$data, %opts ) = @_;
    my $dpop = $self->auth->make_token_for($url,'PATCH');
    $opts{DPoP} = $dpop if $dpop;
    return $self->SUPER::patch($url,$data,%opts);
}

1;