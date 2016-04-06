JWT.erl
=======

An Erlang implementation of `JSON Web Token draft 01 <http://self-issued.info/docs/draft-jones-json-web-token-01.html>`_

Usage
-----

::

    {ok, Jwt} = jwt:encode(Algorithm, [{name, <<"bob">>}, {age, 29}], <<"secret">>)

Additional headers may also be specified::

    {ok, Jwt} = jwt:encode(Algorithm, [{name, <<"bob">>}, {age, 29}], <<"secret">>, [{jti, <<"myid">>}])

where algorithm is one of the atoms:

* hs256
* hs384
* hs512

Note the resulting JWT will not be encrypted, but verifiable with a secret key::

    {ok, Decoded} = jwt:decode(Jwt, <<"secret">>)

Decoded is a record defined in include/jwt.hrl, you may be interested in
the body field which contains the raw decoded body.

Algorithms
----------

The JWT spec supports several algorithms for cryptographic signing. This library
currently supports:

* HS256 - HMAC using SHA-256 hash algorithm
* HS384 - HMAC using SHA-384 hash algorithm
* HS512 - HMAC using SHA-512 hash algorithm

Tests
-----

::

    make tests

When changing dependencies
--------------------------

::

    make rebar.config

License
-------

MIT
