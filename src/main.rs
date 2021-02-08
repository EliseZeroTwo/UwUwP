#[allow(dead_code)]
mod bindings {
    ::windows::include_bindings!();
}

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

mod wrappe;

use std::env;
use wrappe::{
    app_id_vec_from_pkg_full_name, launch_uwp_app, pkg_family_name_to_package_full_names,
    set_acl_from_string_sid,
};

fn set_dll_perms(path: String) {
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

fn main() {
    windows::initialize_mta().expect("Unable to initialize MTA");
    let mut args = env::args();
    let proc_name = args.next().unwrap();
    let family_name = args
        .next()
        .expect(format!("{} <APP_FAMILY_NAME>", proc_name).as_str());

    launch_app_from_family_name(&family_name).expect("Failed to launch app");
}
