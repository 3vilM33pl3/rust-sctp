use super::*;

#[test]
fn native_conformance_never_uses_the_default_fallback() {
    assert_eq!(native_config().policy, SctpTransportPolicy::NativeOnly);
}

#[test]
fn no_kernel_probe_is_honest_when_running_under_the_test_shim() {
    if std::env::var_os("SCTP_TEST_NO_KERNEL").is_some() {
        assert!(!native_sctp_supported());
        assert_eq!(RequestedTransportProfile::Auto.resolve(), RuntimeTransportProfile::UdpEncap);
    }
}
