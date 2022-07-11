#!/bin/sh
SDJWT_ARGS="--replace-examples-in main.md --nonce XZOUco1u_gEPknxS78sWWg --iat 1516239022 --exp 1516247022 --no-randomness"

sd_jwt sd_jwt/examples/simple.yml $SDJWT_ARGS && \
sd_jwt sd_jwt/examples/simple_structured.yml $SDJWT_ARGS && \
sd_jwt sd_jwt/examples/complex.yml $SDJWT_ARGS
