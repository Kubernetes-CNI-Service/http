"""Independent native borrow admission: a real startup graph cannot become native."""
import unittest
from unittest.mock import patch
from test_cases import test_ibsw3_scp_scope_request_content as REQUEST

driver=REQUEST.driver

class NativeBorrowPhaseBoundaryTests(unittest.TestCase):
    def test_original_startup_parent_and_child_cannot_open_a_native_borrow(self):
        method=getattr(driver._PreparedRunScope,'fork_native_component_scope',None)
        self.assertTrue(callable(method),'MISSING_FIXED_NATIVE_BORROW_PHASE_API_NOT_AN_EXPLOIT')
        fixture=REQUEST.ScpScopeRequestContentTests()
        with fixture.original_graph() as (parent,child,leaf,owner,package,stage,held):
            self.assertFalse(parent._native_schedule_started)
            self.assertFalse(child._native_schedule_started)
            original_borrowers=tuple(parent._package_source_borrowers)
            self.assertIn(child,original_borrowers)
            before={name:(obj,obj.fd,obj.payload) for name,obj in held.items()}
            for label,receiver in (('parent',parent),('startup-child',child)):
                error=None
                unexpected=None
                try:
                    with patch.object(driver.os,'open',
                            side_effect=AssertionError('wrong phase must not open another original FD')):
                        unexpected=method(receiver,REQUEST.BASE.HOST,'os')
                except Exception as caught:
                    error=caught
                finally:
                    if unexpected is not None:
                        # Only an actual returned, original scope object is managed.
                        # Never retry or close a numeric descriptor.
                        unexpected.close()
                with self.subTest(receiver=label):
                    self.assertIs(type(error),driver.SharedUpgradeHold)
                    self.assertIsNone(unexpected)
                parent.verify();child.verify();owner.verify()
                self.assertEqual(set(original_borrowers),parent._package_source_borrowers)
                self.assertIs(owner,parent._package_source_owner)
                self.assertIs(owner,child._package_source_owner)
                for name,(obj,fd,payload) in before.items():
                    self.assertIs(obj,child._hold(stage,name))
                    self.assertEqual((fd,payload),(obj.fd,obj.payload))
                self.assertFalse((stage.path/'scp-source-request.json').exists())
                self.assertFalse((stage.path/'component-dispatch.json').exists())
                self.assertFalse((stage.path/'download-ack').exists())
