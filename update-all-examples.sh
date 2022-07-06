#!/bin/sh
SDJWT_ARGS="--replace-examples-in main.md --nonce XZOUco1u_gEPknxS78sWWg --iat 1516239022 --exp 1516247022 --no-randomness"

sd_jwt --example simple $SDJWT_ARGS && \
sd_jwt --example structured $SDJWT_ARGS && \
sd_jwt --example complex $SDJWT_ARGS
