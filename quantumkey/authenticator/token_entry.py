"""Process entry point for the virtual token.

Native libraries and wrappers (liboqs-python prints a banner on import) may
write to stdout, which would corrupt the framed protocol. Keep the real stdout
for frames only and point file descriptor 1 at stderr *before* importing
anything else.
"""

import os
import sys

_frames_out = os.fdopen(os.dup(1), "wb")
os.dup2(2, 1)

from quantumkey.authenticator.token import serve  # noqa: E402

if __name__ == "__main__":
    serve(sys.stdin.buffer, _frames_out)
