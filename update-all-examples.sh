#!/bin/sh

# abort on errors
set -e

OUTPUT_DIR="./examples"
SDJWT_ARGS="--output-dir $OUTPUT_DIR --nonce XZOUco1u_gEPknxS78sWWg --iat 1516239022 --exp 1735689661 --no-randomness"

rm -r $OUTPUT_DIR/* || true

for file in sd_jwt/examples/*.yml
do
    echo "Processing $file"
    sd_jwt $file $SDJWT_ARGS
done
echo "Remember to add updated examples to git repository:"
echo "git add $OUTPUT_DIR"