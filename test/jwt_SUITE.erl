-module(jwt_SUITE).
-compile(export_all).

-include("jwt.hrl").

all() ->
    [encode_decode, decode_with_bad_secret, decode_empty_token,
     decode_bad_token, decode_bad_token_3_parts, decode_bad_sig,
     decode_expired].

init_per_suite(Config) ->
    Config.

end_per_suite(Config) ->
    Config.


check_encode_decode(Algorithm) ->
    {ok, Jwt} = jwt:encode(Algorithm, [{name, <<"bob">>}, {age, 29}], <<"secret">>),
    {ok, Decoded} = jwt:decode(Jwt, <<"secret">>),
    Body = jsx:decode(Decoded#jwt.body, [{return_maps, true}]),
    Name = maps:get(<<"name">>, Body, undefined),
    Age = maps:get(<<"age">>, Body, undefined),
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

decode_bad_sig(_) ->
    Encoded = <<"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
                "eyJ1IjoiYWRtaW4ifQ."
                "KS4+DGuMMuJTcsDApSmmB11TR+O1FkeUu8ByL2qVUlk">>,
    Signature = <<41,46,62,12,107,140,50,226,83,114,192,192,165,41,
                  166,7,93,83,71,227,181,22,71,148,187,192,114,47,
                  106,149,82,89>>,
    ActualSignature = <<210,21,116,4,249,201,17,92,117,190,215,176,
                        22,187,0,69,214,249,100,119,220,25,108,132,
                        138,80,4,37,248,30,15,80>>,
    {error,
     {badsig,
      #jwt{typ = <<"JWT">>,
           body = <<"{\"u\":\"admin\"}">>,
           alg = hs256,
           sig = Signature,
           actual_sig = ActualSignature}}} = jwt:decode(Encoded,
                                                        <<"changeme">>).

decode_empty_token(_) ->
    {error, badtoken} = jwt:decode(<<"">>, <<"secret">>).

decode_bad_token(_) ->
    {error, badtoken} = jwt:decode(<<"asd">>, <<"secret">>).

decode_bad_token_3_parts(_) ->
    {error, badarg} = jwt:decode(<<"asd.dsa.lala">>, <<"secret">>),
    {error, function_clause} = jwt:decode(<<"a.b.c">>, <<"secret">>).

decode_expired(_) ->
    Expiration = jwt:now_secs() - 10,
    {ok, Jwt} = jwt:encode(hs256, [{name, <<"bob">>}, {age, 29}],
                           <<"secret">>, [{exp, Expiration}]),
    {error, {expired, Expiration}} = jwt:decode(Jwt, <<"secret">>).
