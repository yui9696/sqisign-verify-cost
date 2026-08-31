"""sqisign-verify-cost: a verification-cost / DoS-surface profiler for SQIsign.

Measures how much CPU an attacker can make a SQIsign *verifier* spend by
choosing public, structural signature bytes. Ships no cryptography; drives an
external verify-timing adapter. See the README for the mandatory "what this is
and is not" framing.
"""

__version__ = "0.1.0"

from .adapter import Adapter, Answer, Query
from .fields import LEVELS, layout

__all__ = ["Adapter", "Answer", "Query", "LEVELS", "layout", "__version__"]
