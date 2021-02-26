# NAME

Web::Solid::Auth - A Perl Sold Web Client

# SYNOPSIS

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

# DESCRIPTION

This is a Solid-OIDC implementation of a connection class for the Solid
server.

# CONFIGURATION

- webid

    The Solid Webid to authenticate.

- cache

    The location of the cache directory with connection parameters.

# METHODS

- has\_access\_token()

    Returns a true value when a cache contains an access token for the `webid`.

- make\_clean()

    Clear the cache directory.

- make\_authorization\_request()

    Return an authorization URL that the use should open to authenticate this
    application.

- make\_access\_token($code)

    When on the redirect url you get a `code` from the authentication server you
    can use this method to get an access\_token for the code.

- listen()

    Create a small built-in web server to listen for token responses from the
    authentication server.

- get\_access\_token()

    Return the cached access\_token.

# CONTRIBUTORS

Patrick Hochstenbach, `patrick.hochstenbach at ugent.be`

# COPYRIGHT AND LICENSE

This software is copyright (c) 2021 by Patrick Hochstenbach.

This is free software; you can redistribute it and/or modify it under the same terms as the Perl 5 programming language system itself.
