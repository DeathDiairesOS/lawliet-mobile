"""Keep legacy imports bound to the same modules during the LAWLIET migration."""
import importlib
import importlib.abc
import importlib.util
import sys


class _LegacyLoader(importlib.abc.Loader):
    def __init__(self, canonical):
        self.canonical = canonical

    def create_module(self, spec):
        return importlib.import_module(self.canonical)

    def exec_module(self, module):
        pass

    def get_code(self, fullname):
        # Also support older sessions invoking python -m ancalor_mobile.<worker>.
        spec = importlib.util.find_spec(self.canonical)
        return spec.loader.get_code(self.canonical)


class _LegacyFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if not fullname.startswith('ancalor_mobile.'):
            return None
        canonical = 'lawliet_mobile.' + fullname[len('ancalor_mobile.'):]
        original = importlib.util.find_spec(canonical)
        if original is None:
            return None
        return importlib.util.spec_from_loader(fullname, _LegacyLoader(canonical),
                                              is_package=original.submodule_search_locations is not None)


def install():
    if not any(isinstance(finder, _LegacyFinder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _LegacyFinder())
    sys.modules['ancalor_mobile'] = importlib.import_module('lawliet_mobile')
