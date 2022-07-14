#!/bin/sh
SDJWT_ARGS="-d DEBUG --replace-examples-in main.md --nonce XZOUco1u_gEPknxS78sWWg --iat 1516239022 --exp 1516247022 --no-randomness"

for file in sd_jwt/examples/*.yml
do
    sd_jwt $file $SDJWT_ARGS 
done
