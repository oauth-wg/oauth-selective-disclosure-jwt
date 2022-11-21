import json
import logging
from textwrap import fill, wrap
from pathlib import Path

logger = logging.getLogger("sd_jwt")

EXAMPLE_INDENT = 2
EXAMPLE_MAX_WIDTH = 68

#######################################################################
# Helper functions to format examples
#######################################################################


def textwrap_json(data, width=EXAMPLE_MAX_WIDTH):
    text = json.dumps(data, indent=EXAMPLE_INDENT)
    output = []
    for line in text.splitlines():
        if len(line) <= width:
            output.append(line)
        else:
            # Check if line is of the form "key": "value"
            if not line.strip().startswith('"') or ":" not in line:
                print("WARNING: unexpected line " + line)
                output.append(line)
                continue
            # Determine number of spaces before the value
            ##spaces = line.index(":") + 2
            spaces = line.index('"') + EXAMPLE_INDENT
            # Wrap the value
            wrapped = wrap(
                line[spaces:],
                width=width - spaces,
                break_on_hyphens=False,
                replace_whitespace=False,
            )
            # Add the wrapped value to the output
            output.append(line[:spaces] + wrapped[0])
            for line in wrapped[1:]:
                output.append(" " * spaces + line)
    output = "\n".join(text for text in output)

    return output

def textwrap_text(text, width=EXAMPLE_MAX_WIDTH):
    return fill(
        text,
        width=width,
        break_on_hyphens=False,
    )
