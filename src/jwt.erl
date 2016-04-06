-module(jwt).
-export([encode/3, encode/4, decode/2, now_secs/0]).

-include("jwt.hrl").

encode(Algorithm, Payload, Secret) ->
    encode(Algorithm, Payload, Secret, []).

encode(Algorithm, Payload, Secret, HeaderExtra) ->
    AlgorithmName = atom_to_algorithm(Algorithm),
    Header = jsx:encode([{typ, <<"JWT">>}, {alg, AlgorithmName}|HeaderExtra]),
    PayloadJson = jsx:encode(Payload),
    Signature = get_signature(Algorithm, PayloadJson, Secret),
    Parts = [Header, PayloadJson, Signature],
    EncodedParts = [base64url:encode(Item) || Item <- Parts],
    JwtData = bin_join(EncodedParts, <<".">>),
    {ok, JwtData}.

decode(Data, Secret) when is_binary(Data) ->
    Parts = binary:split(Data, [<<".">>], [global]),
    try
        DecodedParts = [base64url:decode(Item) || Item <- Parts],

        if
            length(DecodedParts) < 3 ->
                {error, badtoken};
            true ->
                [HeaderJson,BodyRaw,Signature|_Tail] = DecodedParts,
                Header = jsx:decode(HeaderJson),
                AlgorithmStr = proplists:get_value(<<"alg">>, Header),
                Expiration = proplists:get_value(<<"exp">>, Header, noexp),
                Algorithm = algorithm_to_atom(AlgorithmStr),

                Type = proplists:get_value(<<"typ">>, Header),

                ActualSignature = get_signature(Algorithm, BodyRaw, Secret),

                Jwt = #jwt{typ=Type, body=BodyRaw, alg=Algorithm,
                           sig=Signature, actual_sig=ActualSignature},

                if
                    Signature =:= ActualSignature ->
                        % TODO: leeway
                        NowSecs = now_secs(),
                        if Expiration == noexp orelse Expiration > NowSecs ->
                            {ok, Jwt};
                           true ->
                               {error, {expired, Expiration}}
                        end;

                    true ->
                        {error, {badsig, Jwt}}
                end
        end
    catch error:E ->
              {error, E}
    end.

%% private

bin_join(Items, Sep) ->
    lists:foldl(fun (Val, <<>>) -> Val;
                    (Val, Accum) ->
                        <<Accum/binary, Sep/binary, Val/binary>>
                end, <<>>, Items).

algorithm_to_atom(<<"HS256">>) -> hs256;
algorithm_to_atom(<<"HS384">>) -> hs384;
algorithm_to_atom(<<"HS512">>) -> hs512.

atom_to_algorithm(hs256) -> <<"HS256">>;
atom_to_algorithm(hs384) -> <<"HS384">>;
atom_to_algorithm(hs512) -> <<"HS512">>.

algorithm_to_crypto_algorithm(hs256) -> sha256;
algorithm_to_crypto_algorithm(hs384) -> sha384;
algorithm_to_crypto_algorithm(hs512) -> sha512.

get_signature(Algorithm, Data, Secret) ->
    CryptoAlg = algorithm_to_crypto_algorithm(Algorithm),
    crypto:hmac(CryptoAlg, Data, Secret).

now_secs() ->
    {MegaSecs, Secs, _MicroSecs} = os:timestamp(),
    (MegaSecs * 1000000 + Secs).
