import logging
import re
from textwrap import fill

logger = logging.getLogger("sd_jwt")

EXAMPLE_INDENT = 2
EXAMPLE_MAX_WIDTH = 70

#######################################################################
# Helper functions to replace the examples in the markdown file
#######################################################################


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


def replace_all_in_main(fname: str, replacements, ignore_missing_placeholders=False):
    """
    Replaces all the placeholders in the main.md file
    """
    with open(fname, "r") as f:
        file_contents = f.read()

    # create backup
    with open(f"{fname}.bak", "w") as f:
        f.write(file_contents)

    for placeholder_id, new_code in replacements.items():
        try:
            file_contents = replace_code_in_markdown_source(
                file_contents, placeholder_id, new_code
            )
        except ValueError:
            if not ignore_missing_placeholders:
                logger.error(f"Could not find placeholder with id {placeholder_id}")
                raise
            else:
                logger.info(
                    f"Found and replace contents for placeholder {placeholder_id}"
                )

    with open(fname, "w") as f:
        f.write(file_contents)
