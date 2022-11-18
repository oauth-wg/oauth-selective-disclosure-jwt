import json
import logging
import re
from textwrap import fill, wrap
from pathlib import Path

logger = logging.getLogger("sd_jwt")

EXAMPLE_INDENT = 2
EXAMPLE_MAX_WIDTH = 68

#######################################################################
# Helper functions to replace the examples in the markdown file
#######################################################################


def textwrap_json(text, width):
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


def replace_code_in_markdown_source(file_contents, placeholder_id, new_code):
    """
    the markdown contains code blocks that look like this:
    {#placeholder-id}
    ```
    some-code
    ```

    This function replaces the code block with the replacement
    """

    def replacement(match):
        return match.group(1) + new_code + "\n```"

    new_string, count = re.subn(
        r"({#" + placeholder_id + r"}\n```[a-z-_]*\n)(?:[\s\S]*?)\n```",
        replacement,
        file_contents,
        flags=re.MULTILINE,
    )
    if count == 0:
        raise ValueError

    return new_string


def format_example(data):
    if isinstance(data, dict):
        return textwrap_json(
            json.dumps(data, indent=EXAMPLE_INDENT),
            width=EXAMPLE_MAX_WIDTH,
        )

    else:
        return fill(
            data,
            width=EXAMPLE_MAX_WIDTH,
            break_on_hyphens=False,
        )


def replace_all_in_file(
    file: Path,
    replacements: dict,
    prefix: str,
    ignore_missing_placeholders: bool = False,
):
    """
    Replaces all the placeholders in the draft-ietf-oauth-selective-disclosure-jwt.md file
    """

    file_contents = file.read_text()

    # create backup
    file.with_suffix(".bak").write_text(file_contents)

    for key, (data, _) in replacements.items():
        new_code = format_example(data)

        placeholder_id = prefix + key

        try:
            file_contents = replace_code_in_markdown_source(
                file_contents, placeholder_id, new_code
            )
            logger.info(f"Found and replace contents for placeholder {placeholder_id}")
        except ValueError:

            if not ignore_missing_placeholders:
                raise
            else:
                logger.warning(f"Could not find placeholder with id {placeholder_id}")

    file.write_text(file_contents)
