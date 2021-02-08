use std::ffi::c_void;

use detour::static_detour;

use crate::wrappe::get_module_symbol_address;

type FnCreateFileW = unsafe extern "system" fn(
    *const u16,
    u32,
    u32,
    *mut c_void,
    u32,
    u32,
    *mut c_void
  ) -> *mut c_void;

static_detour! {
    pub static CreateFileW: unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *mut c_void,
        u32,
        u32,
        *mut c_void
      ) -> *mut c_void;
}

fn createfilew_detour(
    lp_file_name: *const u16,
    dw_desired_access: u32,
    dw_share_mode: u32,
    lp_security_attr: *mut c_void,
    dw_creation_disposition: u32,
    dw_flags_and_attr: u32,
    h_template_file: *mut c_void) -> *mut c_void {
    unsafe {
        CreateFileW.call(lp_file_name, dw_desired_access, dw_share_mode, lp_security_attr, dw_creation_disposition, dw_flags_and_attr, h_template_file)
    }
}


pub fn apply_static_detours() {
    unsafe {
        let create_file_target: FnCreateFileW = std::mem::transmute(get_module_symbol_address("Kernel32.dll", "CreateFileW").expect("Could not find CreateFileW in Kernel32.dll"));
        CreateFileW.initialize(create_file_target, createfilew_detour).unwrap();
    }
}