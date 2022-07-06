#!/bin/sh
SDJWT_ARGS="--nonce XZOUco1u_gEPknxS78sWWg --iat 1516239022 --exp 1516247022 --no-randomness"

sd_jwt --example simple --replace-examples-in main.md $SDJWT_ARGS && \
sd_jwt --example structured --replace-examples-in main.md $SDJWT_ARGS && \
sd_jwt --example complex --replace-examples-in main.md $SDJWT_ARGS
