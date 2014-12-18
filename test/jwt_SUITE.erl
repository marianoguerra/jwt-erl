-module(jwt_SUITE).
-compile(export_all).

-include("include/jwt.hrl").

all() ->
    [encode_decode, decode_with_bad_secret, decode_empty_token,
     decode_bad_token, decode_bad_token_3_parts, decode_good,
     decode_expired].

init_per_suite(Config) -> 
    Config.

check_encode_decode(Algorithm) ->
    {ok, Jwt} = jwt:encode(Algorithm, [{name, <<"bob">>}, {age, 29}], <<"secret">>),
    {ok, Decoded} = jwt:decode(Jwt, <<"secret">>),
    Body = jsx:decode(Decoded#jwt.body),
    Name = proplists:get_value(<<"name">>, Body),
    Age = proplists:get_value(<<"age">>, Body),
    <<"JWT">> = Decoded#jwt.typ,
    Algorithm = Decoded#jwt.alg,
    29 = Age,
    <<"bob">> = Name.

encode_decode(_) ->
    check_encode_decode(hs256),
    check_encode_decode(hs384),
    check_encode_decode(hs512).

decode_with_bad_secret(_) ->
    {ok, Jwt} = jwt:encode(hs256, [{name, <<"bob">>}, {age, 29}], <<"secret">>),
    {error, {badsig, _Decoded}} = jwt:decode(Jwt, <<"notsecret">>).

decode_good(_) ->
    {ok, Jwt} = jwt:decode(<<"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1IjoiYWRtaW4ifQ.KS4+DGuMMuJTcsDApSmmB11TR+O1FkeUu8ByL2qVUlk">>, <<"changeme">>),
    Body = jsx:decode(Jwt#jwt.body),
    <<"admin">> = proplists:get_value(<<"u">>, Body).

decode_empty_token(_) ->
    {error, badtoken} = jwt:decode(<<"">>, <<"secret">>).

decode_bad_token(_) ->
    {error, badtoken} = jwt:decode(<<"asd">>, <<"secret">>).

decode_bad_token_3_parts(_) ->
    {error, badarg} = jwt:decode(<<"asd.dsa.lala">>, <<"secret">>),
    {error, {badmatch, false}} = jwt:decode(<<"a.b.c">>, <<"secret">>).

decode_expired(_) ->
    Expiration = jwt:now_secs() - 10,
    {ok, Jwt} = jwt:encode(hs256, [{name, <<"bob">>}, {age, 29}],
                           <<"secret">>, [{exp, Expiration}]),
    {error, {expired, Expiration}} = jwt:decode(Jwt, <<"secret">>).
