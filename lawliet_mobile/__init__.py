"""Lawliet Mobile: local evidence triage."""
__version__ = "0.1.0"

# The old directory is an alias for running sessions; preserve module identity too.
if __name__ == "ancalor_mobile":
    from lawliet_mobile._legacy_alias import install
    install()
