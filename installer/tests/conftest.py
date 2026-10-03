import sys
from pathlib import Path

# Make `sentinelcore_installer` importable no matter where pytest is started from.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
