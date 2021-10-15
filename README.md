# NAME

Web::Solid::Auth - A Perl Solid Web Client

# SYNOPSIS

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

# INSTALLATION

See the [https://metacpan.org/dist/Web-Solid-Auth/source/INSTALL](https://metacpan.org/dist/Web-Solid-Auth/source/INSTALL) file in the 
distribution.

# DESCRIPTION

This is a Solid-OIDC implementation of a connection class for the Solid
server. Use the `bin/solid_auth.pl` command as a command line implementation.
Check out the `example` directory for a demo web application.

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

# SEE ALSO

[solid\_auth.pl](https://metacpan.org/pod/solid_auth.pl)

# INSPIRATION

This was very much inspired by the Python solid-flask code by
Rai [http://agentydragon.com](http://agentydragon.com) at [https://gitlab.com/agentydragon/solid-flask](https://gitlab.com/agentydragon/solid-flask),
and Jeff Zucker's &lt;https://github.com/jeff-zucker> Solid-Shell at [https://www.npmjs.com/package/solid-shell](https://www.npmjs.com/package/solid-shell).

# COPYRIGHT AND LICENSE

This software is copyright (c) 2021 by Patrick Hochstenbach.

This is free software; you can redistribute it and/or modify it under the same terms as the Perl 5 programming language system itself.
