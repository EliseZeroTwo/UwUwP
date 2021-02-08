#[allow(dead_code)]
mod bindings {
    ::windows::include_bindings!();
}

extern crate argh;
#[macro_use]
extern crate lazy_static;

lazy_static! {
    pub static ref WIN_APPS_PATH: String = format!(
        r"{}\WindowsApps",
        env::vars()
            .find(|(key, _)| key == &"PROGRAMFILES".to_string())
            .expect("Missing PROGRAMFILES environment variable")
            .1
    );
    pub static ref APP_DATA_PATH: String = format!(
        r"{}\Packages",
        env::vars()
            .find(|(key, _)| key == &"LOCALAPPDATA".to_string())
            .expect("Missing LOCALAPPDATA environment variable")
            .1
    );
}

mod detou;
mod wrappe;

use argh::FromArgs;
use detou::apply_static_detours;
use std::env;
use wrappe::{app_id_vec_from_pkg_full_name, do_dll_injection, launch_uwp_app, pkg_family_name_to_package_full_names, set_acl_from_string_sid};



pub fn set_dll_perms(path: String) {
    set_acl_from_string_sid(path.clone(), "S-1-15-2-1".to_string())
        .expect(format!("Unable to set permissions for {}", path).as_str());
}

fn launch_app_from_family_name(family_name: &String) -> Result<u32, String> {
    let full_names =
        pkg_family_name_to_package_full_names(&family_name).expect("Cannot find calculator");
    if full_names.len() == 0 {
        return Err("No Full Pkg Name Found".to_string());
    }

    let full_name = &full_names[0];
    let app_ids =
        app_id_vec_from_pkg_full_name(full_name).expect("Unable to get app user model id");
    if app_ids.len() == 0 {
        return Err("No Full Pkg Name Found".to_string());
    }

    let app_id = &app_ids[0];
    launch_uwp_app(app_id).map_err(|err| format!("Failed to launch UWP app, Got {:?}", err))
}

#[derive(FromArgs)]
/// Mod Loader
struct UwUwPArgs {
    #[argh(option, short='d')]
    /// directory of DLLs to inject in alphabetical order
    dll_dir: Option<String>,

    #[argh(positional)]
    /// app family name
    family_name: String,
}

fn main() {
    let args: UwUwPArgs = argh::from_env();
    let dlls = if let Some(dll_dir) = &args.dll_dir {
        match std::fs::read_dir(dll_dir) {
            Ok(paths) => Some(paths.filter_map(|x| {
                if let Ok(dirent) = x {
                    let path = std::fs::canonicalize(dirent.path()).unwrap().to_str().unwrap().to_string();
                    if path.to_lowercase().ends_with(".dll") {
                        return Some(path)
                    } 
                }
                None
            }).collect::<Vec<String>>()),
            Err(_) => {
                println!("{} is not a valid directory", dll_dir);
                std::process::exit(-1);
            },
        }
    } else {
        None
    };

    windows::initialize_mta().expect("Unable to initialize MTA");
    
    apply_static_detours();
    
    let pid = launch_app_from_family_name(&args.family_name).expect("Failed to launch app");
    if let Some(dll_list) = dlls {
        do_dll_injection(pid, dll_list).expect("Unable to DLL inject");
    }
}
