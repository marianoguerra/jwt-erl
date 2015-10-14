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
    EncodedParts = [base64_encode_no_padding(Item) || Item <- Parts],
    JwtData = bin_join(EncodedParts, <<".">>),
    {ok, JwtData}.

decode(Data, Secret) when is_binary(Data) ->
    Parts = binary:split(Data, [<<".">>], [global]),
    try
        DecodedParts = [base64_decode_no_padding(Item) || Item <- Parts],

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

base64_decode_no_padding(Base64) when byte_size(Base64) rem 4 == 3 ->
        base64:decode(<<Base64/bytes, "=">>);
base64_decode_no_padding(Base64) when byte_size(Base64) rem 4 == 2 ->
        base64:decode(<<Base64/bytes, "==">>);
base64_decode_no_padding(Base64) ->
        base64:decode(Base64).

b64e(X) ->
    element(X+1,
	    {$A, $B, $C, $D, $E, $F, $G, $H, $I, $J, $K, $L, $M, $N,
	     $O, $P, $Q, $R, $S, $T, $U, $V, $W, $X, $Y, $Z,
	     $a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k, $l, $m, $n,
	     $o, $p, $q, $r, $s, $t, $u, $v, $w, $x, $y, $z,
	     $0, $1, $2, $3, $4, $5, $6, $7, $8, $9, $+, $/}).

base64_encode_no_padding(Bin) ->
    Split = 3*(byte_size(Bin) div 3),
    <<Main0:Split/binary,Rest/binary>> = Bin,
    Main = << <<(b64e(C)):8>> || <<C:6>> <= Main0 >>,
    case Rest of
        <<A:6,B:6,C:4>> ->
            <<Main/binary,(b64e(A)):8,(b64e(B)):8,(b64e(C bsl 2)):8>>;
        <<A:6,B:2>> ->
            <<Main/binary,(b64e(A)):8,(b64e(B bsl 4)):8>>;
        <<>> ->
            Main
    end.

now_secs() ->
    {MegaSecs, Secs, _MicroSecs} = os:timestamp(),
    (MegaSecs * 1000000 + Secs).
