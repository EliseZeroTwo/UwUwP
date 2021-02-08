use core::panic;
use std::{
    ffi::{c_void, CStr, CString},
    ptr::{null, null_mut},
    string::FromUtf16Error,
};

use windows::BOOL;

use crate::{bindings::windows::{win32::*, ErrorCode}};

pub fn get_acl(
    path: String,
) -> Result<(*mut security::ACL, *mut security::SECURITY_DESCRIPTOR), i32> {
    let out;
    let cstr = &CString::new(path).expect("Invalid Path") as &CStr;
    unsafe {
        let mut acl_ptr: *mut security::ACL = std::mem::zeroed();
        let mut security_desc_ptr: *mut c_void = null_mut();
        let res = security::GetNamedSecurityInfoA(
            cstr.as_ptr(),
            security::SE_OBJECT_TYPE::SE_FILE_OBJECT,
            4,
            null_mut(),
            null_mut(),
            &mut acl_ptr,
            null_mut(),
            &mut security_desc_ptr,
        );
        let security_desc_ptr: *mut security::SECURITY_DESCRIPTOR = security_desc_ptr as *mut _;
        if res == 0 && !acl_ptr.is_null() {
            out = Ok((acl_ptr, security_desc_ptr));
        } else {
            out = Err(res as i32);
        }
    }
    out
}

pub fn set_acl_from_string_sid(path: String, sid: String) -> Result<(), String> {
    let (old_acl, _) = match get_acl(path.clone()) {
        Ok(acl) => acl,
        Err(res) => return Err(format!("GetNamedSecurityInfoA returned {}", res)),
    };

    unsafe {
        let mut sid_ptr: *mut c_void = std::mem::zeroed();
        let sid_cstring = CString::new(sid).expect("Invalid SID");
        let path_cstring = CString::new(path).expect("Invalid Path");

        let sid_cstring_raw = sid_cstring.into_raw();
        security::ConvertStringSidToSidA(sid_cstring_raw, &mut sid_ptr);
        CString::from_raw(sid_cstring_raw);

        if sid_ptr.is_null() {
            return Err(format!("ConvertStringSidToSidA gave null psID pointer"));
        }

        let mut ea: security::EXPLICIT_ACCESS_A = std::mem::zeroed();
        ea.grf_access_permissions = (1 << 31) | (1 << 29); // R-X
        ea.grf_access_mode = security::ACCESS_MODE::SET_ACCESS;
        ea.grf_inheritance = 3; // SUB_CONTAINERS_AND_OBJECTS_INHERIT
        ea.trustee.trustee_form = security::TRUSTEE_FORM::TRUSTEE_IS_SID;
        ea.trustee.trustee_type = security::TRUSTEE_TYPE::TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.trustee.ptstr_name = sid_ptr as *mut _;

        let mut acl_ptr: *mut security::ACL = std::mem::zeroed();
        let res = security::SetEntriesInAclA(1, &mut ea, old_acl, &mut acl_ptr);
        if res != 0 {
            if !acl_ptr.is_null() {
                system_services::LocalFree(acl_ptr as isize);
            }

            return Err(format!("SetEntriesInAclA returned {}", res));
        }

        let path_cstring_raw = path_cstring.into_raw();
        let res = security::SetNamedSecurityInfoA(
            path_cstring_raw,
            security::SE_OBJECT_TYPE::SE_FILE_OBJECT,
            4,
            null_mut(),
            null_mut(),
            acl_ptr,
            null_mut(),
        );
        CString::from_raw(path_cstring_raw);

        if !acl_ptr.is_null() {
            system_services::LocalFree(acl_ptr as isize);
        }

        if res != 0 {
            return Err(format!("SetNamedSecurityInfoA returned {}", res));
        }
    }

    Ok(())
}

pub fn pcwstr_to_string(pwstr: &mut *const u16) -> Result<String, FromUtf16Error> {
    let mut out_vec = Vec::<u16>::new();
    unsafe {
        while !pwstr.is_null() && **pwstr != 0 {
            out_vec.push(**pwstr);
            *pwstr = pwstr.add(1);
        }
    }
    String::from_utf16(&out_vec)
}

pub fn string_to_wchar_vec(val: &String) -> Vec<u16> {
    let mut out_vec = val
        .chars()
        .map(|x| {
            if x as u32 > 0xD7FF {
                panic!("Invalid pkg name");
            }

            x as u16
        })
        .collect::<Vec<u16>>();
    out_vec.push(0);
    out_vec
}

#[link(name = "kernel32")]
extern "stdcall" {
    pub fn FindPackagesByPackageFamily(
        package_family_name: *const u16,
        package_filters: u32,
        count: *mut u32,
        pkg_full_names: *mut *mut u16,
        buffer_length: *mut u32,
        buffer: *mut u16,
        package_properties: *mut u32,
    ) -> i32;
    pub fn OpenPackageInfoByFullName(
        pkg_full_name: *const u16,
        res: u32,
        pkg_info_reference: *mut *mut c_void,
    ) -> i32;
    pub fn GetPackageApplicationIds(
        pkg_info_reference: *mut c_void,
        buffer_length: *mut u32,
        buffer: *mut u8,
        count: *mut u32,
    ) -> i32;
    pub fn ClosePackageInfo(pkg_info_reference: *mut c_void) -> i32;
}

pub fn pkg_family_name_to_package_full_names(family_name: &String) -> Result<Vec<String>, i32> {
    let mut out_vec = Vec::<String>::new();
    let family_name_cstr = string_to_wchar_vec(family_name);
    let family_name_ptr = family_name_cstr.as_ptr();

    unsafe {
        let mut count = 0u32;
        let mut length = 0u32;
        let status = FindPackagesByPackageFamily(
            family_name_ptr,
            0x10,
            &mut count,
            null_mut(),
            &mut length,
            null_mut(),
            null_mut(),
        );
        if status == 0 {
            return Ok(vec![family_name.clone()]);
        } else if status != 122 {
            return Err(status);
        }

        let mut full_names = vec![null_mut() as *mut u16; count as usize];
        let mut buffer = vec![0u16; length as usize];
        let mut properties = 0u32;

        let status = FindPackagesByPackageFamily(
            family_name_ptr,
            0x10,
            &mut count,
            full_names.as_mut_ptr(),
            &mut length,
            buffer.as_mut_ptr(),
            &mut properties,
        );
        if status != 0 {
            return Err(status);
        }

        for name_ptr in full_names {
            if name_ptr.is_null() {
                break;
            }

            if let Ok(out_str) = pcwstr_to_string(&mut (name_ptr as *const u16)) {
                out_vec.push(out_str);
            }
        }

        assert_eq!(out_vec.len(), count as usize);
    }

    Ok(out_vec)
}

pub fn app_id_vec_from_pkg_full_name(full_name: &String) -> Result<Vec<String>, String> {
    let mut out_vec = Vec::new();
    let pkg_name_wstr = string_to_wchar_vec(full_name);
    let pkg_name_ptr = pkg_name_wstr.as_ptr();

    unsafe {
        let mut pkg_info_reference: *mut c_void = std::mem::zeroed();
        let res = OpenPackageInfoByFullName(pkg_name_ptr, 0, &mut pkg_info_reference);
        if res != 0 {
            return Err(format!("OpenPackageInfoByFullName returned {}", res));
        }

        let mut count = 0u32;
        let mut length = 0u32;
        let res = GetPackageApplicationIds(pkg_info_reference, &mut length, null_mut(), &mut count);
        if res != 122 {
            ClosePackageInfo(pkg_info_reference);
            return Err(format!(
                "GetPackageApplicationIds returned {} instead of 122",
                res
            ));
        }

        let mut buffer = vec![0 as u8; length as usize];
        let res = GetPackageApplicationIds(
            pkg_info_reference,
            &mut length,
            buffer.as_mut_ptr(),
            &mut count,
        );

        if res != 0 {
            ClosePackageInfo(pkg_info_reference);
            return Err(format!("GetPackageApplicationIds returned {}", res));
        }

        let app_ids: *const *const u16 = buffer.as_ptr() as *const _;

        for x in 0..count {
            let mut cur_val = *(app_ids.add(x as usize));
            if cur_val.is_null() {
                break;
            }

            match pcwstr_to_string(&mut cur_val) {
                Ok(val) => out_vec.push(val),
                Err(why) => return Err(why.to_string()),
            };
        }
    }

    Ok(out_vec)
}

pub fn launch_uwp_app(pkg_full_name: &String) -> Result<u32, ErrorCode> {
    let mut pid_out = 0u32;
    println!("Launching {}", pkg_full_name);
    let am: shell::IApplicationActivationManager =
        windows::create_instance(&shell::ApplicationActivationManager)
            .expect("Unable to create ApplicationActivationManager");
    let am_ref = &am;
    let pkg_full_name_wchar = string_to_wchar_vec(&pkg_full_name);
    unsafe {
        let _ = com::CoAllowSetForegroundWindow(Some(am_ref.into()), null_mut());
        let res = am_ref.ActivateApplication(
            pkg_full_name_wchar.as_ptr(),
            null(),
            shell::ACTIVATEOPTIONS::AO_NONE,
            &mut pid_out,
        );

        if res != ErrorCode::S_OK {
            return Err(res);
        }
    }
    Ok(pid_out)
}

// Adapted from https://github.com/darfink/detour-rs/blob/master/examples/messageboxw_detour.rs#L47
pub fn get_module_symbol_address(module: &str, symbol: &str) -> Option<usize> {
    let module = string_to_wchar_vec(&module.to_string()); 
    let symbol = CString::new(symbol).unwrap();
    unsafe {
        let handle = system_services::GetModuleHandleW(module.as_ptr());
        match system_services::GetProcAddress(handle, symbol.as_ptr()) {
            Some(n) => Some(n as usize),
            None => None,
        }
    }
}

pub fn do_dll_injection(pid: u32, dlls: Vec<String>) -> Result<(), String> {
    let load_library_addr = get_module_symbol_address("kernel32.dll", "LoadLibraryA").expect("Failed to find LoadLibraryA in kernel32.dll");
    unsafe {
        let proc_handle = system_services::OpenProcess(0x1F0FFF, BOOL::from(false), pid);
        if proc_handle.0 == 0 {
            return Err("Process Handle is NULL".to_string());
        }
        
        let remote_proc_mem_addr = system_services::VirtualAllocEx(proc_handle, null_mut(), 260 , 0x2000 | 0x1000, 0x40);
        if remote_proc_mem_addr.is_null() {
            windows_programming::CloseHandle(proc_handle);
            return Err("Memory Allocation in Remote Process Failed".to_string());
        }
        for dll in dlls {
            println!("Injecting {}", &dll);
            crate::set_dll_perms(dll.clone());

            let cstr = CString::new(dll.clone()).expect("Failed to turn DLL path into CString").into_raw();
            let res = debug::WriteProcessMemory(proc_handle, remote_proc_mem_addr, cstr as *mut _, dll.len(), null_mut());
            let _ = CString::from_raw(cstr);
            if res.as_bool() == false {
                system_services::VirtualFreeEx(proc_handle, remote_proc_mem_addr, 0, 0x8000);
                windows_programming::CloseHandle(proc_handle);
                return Err("Failed to Write Remote Process Memory".to_string());
            }
    
            let load_library_addr = std::mem::transmute(load_library_addr);
            let thread = system_services::CreateRemoteThread(proc_handle, null_mut(), 0, Some(load_library_addr), remote_proc_mem_addr, 0, null_mut());
            std::thread::sleep(std::time::Duration::from_millis(50)); // Race Condition
            system_services::VirtualFreeEx(proc_handle, remote_proc_mem_addr, 0, 0x8000);
            
            if thread.0 == 0 {
                windows_programming::CloseHandle(proc_handle);
                return Err("Failed to Create Thread in Remote Process".to_string());
            } 
            windows_programming::CloseHandle(thread);
        }
        windows_programming::CloseHandle(proc_handle);
    }
    Ok(())
}