"""Makes `python -m ax9` work: Python runs this file when a package is executed.

sys.exit() turns main()'s return value into the process exit code (0/1/2).
"""
import sys

from .cli import main

sys.exit(main())
