# Selective Disclosure for JWTs (SD-JWT)

This document specifies conventions for creating JSON Web Token (JWT)
documents that support selective disclosure of claim values. 

Written in markdown for the [mmark processor](https://github.com/mmarkdown/mmark).

## Updating Examples

All examples in the document are created from [actual running code](demo.py). To run this code, install jwcrypto library, e.g., like so:
```
pip3 install jwcrypto
```

On Debian/Ubuntu systems, you can instead use the packaged version:
```
sudo apt install python3-jwcrypto
```

You can then run the code (from the root of this repository):
```
python3 -m demo.simple
```

To update the examples in [main.md](main.md), use the switch `--replace`:
```
python3 -m demo.simple --replace
```

The code creates a backup before modifying [main.md](main.md) in [main.md.bak](main.md.bak).

## Compiling

### Using Docker (recommended)
From the root of this repository, run
```bash
docker run -v `pwd`:/data danielfett/markdown2rfc main.md
```
(see https://github.com/oauthstuff/markdown2rfc)

### without Docker
compile using mmark and xml2rfc: `mmark main.md > draft.xml; xml2rfc --html draft.xml`
