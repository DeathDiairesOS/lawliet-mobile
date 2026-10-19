"""Full raw retrieval must not admit coerced/unbounded/unspecified scope."""
import inspect
import unittest
from unittest.mock import patch

try:
    from mulder.server.tools import core
except ModuleNotFoundError:
    core = None


@unittest.skipUnless(core, 'Requires patched Mulder runtime')
class RawRetrievalBoundaryTests(unittest.TestCase):
    def test_unsafe_bounds_refused_before_context_read(self):
        fn=inspect.unwrap(core.get_raw_output)
        cases=[{'source_name':x} for x in ('','   ',None,True)]
        for name,values in [('after_id',[True,-1,1.0,'1',2**63]),('limit',[True,-1,0,501,1.0,'1'])]:
            cases += [{name:v} for v in values]
        with patch.object(core,'get_ctx',side_effect=AssertionError('Source read before validation')):
            for values in cases:
                with self.subTest(values=values),self.assertRaises(ValueError):
                    fn(**{'source_name':'phone.control',**values})
