-record(jwt, {exp, % Expiration Time
              nbf, % Not Before
              iat, % Issued At
              iss, % Issuer
              aud, % Audience
              prn, % Principal
              jti, % JWT ID
              typ, % Type
              enc, % encryption method
              body, % RawBody
              alg, % Algorithm
              sig, % signature got from JWT
              actual_sig % signature calculated during decoding, should differ
                          % if {error, badsig, _} is returned
             }).
