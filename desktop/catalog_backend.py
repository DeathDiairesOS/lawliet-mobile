"""Compatibility entry point for the shared metadata-only case catalog."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lawliet_mobile.case_catalog import *

if __name__ == '__main__':
    main()
