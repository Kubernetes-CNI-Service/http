"""D34-O8: replace only the new master factory in pre-existing main fixtures.

These scenarios already model the old OOB public-key probe and transport. Keep
their business/credential/typed-argv assertions unchanged. Actual multiplexing
and rebuild behaviour is independently tested by test_initial_setup_jump_sessions;
this adapter must never create a directory or launch SSH.
"""


def legacy_jump_sessions_factory(app):
    class ExistingTransportFixture:
        def __init__(self, *, local_keys=(), timeout=10):
            self.timeout = timeout

        def probe_jump_key(self, jump, user):
            return app.probe_ethernet_key(jump, user, self.timeout)

        def open_jump_master(self, jump, user, responder, **kwargs):
            return jump.login_ip

        def jump_control_path(self, jump):
            return None

        def close_jump_masters(self):
            pass

    return ExistingTransportFixture
