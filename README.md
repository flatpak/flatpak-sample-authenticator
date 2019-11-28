# flatpak-sample-authenticator

This is a sample implementation of a flatpak authenticator, it expects to find a url to an API server
in the configuration of the remote, and all authentication calls are proxied to that.

Normally the authenticator would be installed and dbus activated, but to avoid installation complexities 
when testing it's easiest to just manually run it from the tree like this:

```
$ ./flatpak-sample-authenticator -v --replace --no-idle-exit
```

You then set up this for use like this:
```
$ flatpak remote-add --user \
   --authenticator-name=org.flatpak.Authenticator.Sample \
   --authenticator-options='{"url": <"http://url.to.api.server.com">}' \
   test-sample-auth http://url.to.repo.com
```

For this to be useful there needs to be an implementation of the API to point at. 
There is a minimal implementation [here](https://github.com/alexlarsson/flat-auth) which you can use for testing.

There are some more details docs in the Wiki if you just want to [try it out](https://github.com/flatpak/flatpak/wiki/TestingPurchases).

## Design

For identification the autheticator uses a token allowing it to do authenticated API calls to the api server. 
This is just a JWT token signed by the API server that contains a valid-until timestamp and a unique id for the user. 

The first time the authenticator needs to do something it must start by doing a login webflow (see below) to get such a token.
Once this is done we save it locally and can reuse it until it is not valid anymore and we have to get a new one.

Once we have a token the main call is the `get_tokens` API call where you pass in a list of refs and get back a list 
of tokens to use for the ref the user should have access to, and a list of refs the user doesn't have access to.

If the user doesn't have access to a requested ref, then there is a `begin_purchase` API call which you can use to
trigger a webflow to purchase it. On success the authenticator does a new call to `get_tokens` to get the new token.

## Webflows

Webflows are different from regular REST API calls, they are meant to be interactive and shown by a real web-browser. 

They are initiated by the authenticator telling flatpak (or whatever app uses libflatpak) to show a uri to the user.
The uri contains a redirect_uri argument, and eventually the web interaction ends with a redirect to this uri, which
points back to the authenticator via its `http://localhost:XYZW/` form. This tells the authenticator that the webflow is
done (and what the result was).

This is modeled on how OAuth2 works, and in fact you can easily do the login operation by just chaining to some OAuth2 
service of your choice (flat-auth uses google).

## HTTP API

`/api/login`: This is not really a REST api, but a standard location where you can initiate a webflow to log in. 

|url args | description |
|-----|-------------|
|redirect_uri| At the end of the webflow this uri will be redirected to|
|state| This will be passed back as an argument in the redirected uri|

In the final redirected uri, on success the argument `token` will be set to a token you can use for further API calls.

`/api/v1/get_tokens`:

This is a non-interactive call that takes a json object with arguments, it requires a valid bearer token identifying the user.

Get bearer tokens for a list of app ids (like `org.gnome.eog`).

|args | description |
|-----|-------------|
|ids| A list of all the app ids we need tokens to download. |

On success this returns a json object:

|field | description |
|-----|-------------|
|tokens| a dict with keys being ids and the values being tokens for the id. |
|denied| a list of ids that the user doesn't have access too|


`/api/v1/begin_purchase`:

This is a non-interactive call that takes a json object with arguments, it requires a valid bearer token identifying the user.

Initializes a purchase operation of a particular app id.

|args | description |
|-----|-------------|
|id| The app id that the user want to purchase. |

|field | description |
|-----|-------------|
|start_uri| A url where you can initiate a webflow, accepts standard `redirect_uri` and `state` args. |

When the purchase webflow is successful it will redirect to the `redirect_uri` that was specified, with 
the passed in `state` as an argument. Additionally it will have a new `redirect_uri` argument that the
authenticator will follow for the final display after telling flatpak that the webflow is done. 
This can be used to display a "thanks for purchasing $app final landing page".
