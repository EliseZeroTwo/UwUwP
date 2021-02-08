fn main() {
    windows::build!(
        windows::win32::com::{CoAllowSetForegroundWindow},
        windows::win32::security::{ACL, ConvertStringSidToSidA, EXPLICIT_ACCESS_A, GetNamedSecurityInfoA, SetEntriesInAclA, SetNamedSecurityInfoA, SECURITY_DESCRIPTOR, SID},
        windows::win32::system_services::{LocalFree},
        windows::win32::shell::{ApplicationActivationManager, IApplicationActivationManager},
    );
}
