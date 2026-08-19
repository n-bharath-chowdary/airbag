"""Allow `python -m airbag`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
