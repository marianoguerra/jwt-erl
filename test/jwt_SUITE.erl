-module(jwt_SUITE).
-compile(export_all).

-include("include/jwt.hrl").

all() ->
    [encode_decode, decode_with_bad_secret].

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
    {error, badsig, _Decoded} = jwt:decode(Jwt, <<"notsecret">>).
