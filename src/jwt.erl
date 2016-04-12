-module(jwt).
-export([encode/3, encode/4, decode/2, now_secs/0]).

-include("jwt.hrl").

%%%------------------------------------------------------------------------
%%% External interface functions
%%%------------------------------------------------------------------------

encode(Algorithm, Payload, Secret) ->
    encode(Algorithm, Payload, Secret, []).

encode(Algorithm, Payload, Secret, HeaderExtra) ->
    AlgorithmName = atom_to_algorithm(Algorithm),
    Header = jsx:encode([{typ, <<"JWT">>},
                         {alg, AlgorithmName} | HeaderExtra]),
    HeaderEncoded = base64url:encode(Header),
    PayloadEncoded = base64url:encode(jsx:encode(Payload)),
    DataEncoded = <<HeaderEncoded/binary, $., PayloadEncoded/binary>>,
    Signature = get_signature(Algorithm, DataEncoded, Secret),
    SignatureEncoded = base64url:encode(Signature),
    {ok, <<DataEncoded/binary, $., SignatureEncoded/binary>>}.

decode(Data, Secret) when is_binary(Data) ->
    try
        case binary:split(Data, [<<".">>], [global]) of
            [HeaderEncoded, PayloadEncoded, SignatureEncoded] ->
                Header = jsx:decode(base64url:decode(HeaderEncoded)),
                Type = proplists:get_value(<<"typ">>, Header),
                AlgorithmStr = proplists:get_value(<<"alg">>, Header),
                Expiration = proplists:get_value(<<"exp">>, Header, noexp),
                Algorithm = algorithm_to_atom(AlgorithmStr),
                DataEncoded = <<HeaderEncoded/binary, $.,
                                PayloadEncoded/binary>>,
                ActualSignature = get_signature(Algorithm, DataEncoded, Secret),
                Signature = base64url:decode(SignatureEncoded),
                Payload = base64url:decode(PayloadEncoded),
                Jwt = #jwt{typ=Type, body=Payload, alg=Algorithm,
                           sig=Signature, actual_sig=ActualSignature},
                if
                    Signature =:= ActualSignature ->
                        % TODO: leeway
                        NowSecs = now_secs(),
                        if
                            Expiration == noexp orelse Expiration > NowSecs ->
                                {ok, Jwt};
                            true ->
                                {error, {expired, Expiration}}
                        end;
                    true ->
                        {error, {badsig, Jwt}}
                end;
            _ ->
                {error, badtoken}
        end
    catch
        error:E ->
            {error, E}
    end.

%%%------------------------------------------------------------------------
%%% Private functions
%%%------------------------------------------------------------------------

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
    crypto:hmac(CryptoAlg, Secret, Data).

now_secs() ->
    {MegaSecs, Secs, _MicroSecs} = os:timestamp(),
    (MegaSecs * 1000000 + Secs).
