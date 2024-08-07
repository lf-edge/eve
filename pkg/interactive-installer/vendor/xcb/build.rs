
extern crate libc;

use std::io;
use std::env;
use std::cmp;
use std::path::{Path, PathBuf};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::process::Command;


fn visit_xml<F>(xml_dir: &Path, cb: F) -> io::Result<()>
        where F: Fn(&Path) -> io::Result<()> {
    if try!(fs::metadata(xml_dir)).is_dir() {
        for entry in try!(fs::read_dir(xml_dir)) {
            let path = try!(entry).path();
            if try!(fs::metadata(&path)).is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "xml" { try!(cb(&path)); }
                }
            }
        }
    }
    Ok(())
}


fn xml_to_rs (rs_dir: &Path, xml_file: &Path) -> PathBuf {
    let mut path = PathBuf::from(&rs_dir);
    path.push(xml_file.file_stem().unwrap());
    path.set_extension("rs");
    path
}

fn optional_mtime (path: &Path, default: i64) -> i64 {
    if let Ok(md) = fs::metadata(&path) {
        md.mtime()
    } else {
        default
    }
}

fn main() {
    let root = env::var("CARGO_MANIFEST_DIR").unwrap();
    let r_client = Path::new(&root).join("rs_client.py");
    let build_rs = Path::new(&root).join("build.rs");
    let xml_dir = Path::new(&root).join("xml");
    let src_dir = Path::new(&root).join("src");
    let src_ffi_dir = Path::new(&src_dir).join("ffi");

    let r_client_mtime = fs::metadata(&r_client).unwrap().mtime();
    let build_rs_mtime = fs::metadata(&build_rs).unwrap().mtime();
    let ref_mtime = cmp::max(r_client_mtime, build_rs_mtime);

    visit_xml(&xml_dir, |xml_file: &Path| -> io::Result<()> {
        let src_file = xml_to_rs(&src_dir, &xml_file);
        let ffi_file = xml_to_rs(&src_ffi_dir, &xml_file);
        let xml_file_mtime = try!(fs::metadata(&xml_file)).mtime();
        let src_file_mtime = optional_mtime(&src_file, 0);
        let ffi_file_mtime = optional_mtime(&ffi_file, 0);

        let ref_mtime = cmp::max(ref_mtime, xml_file_mtime);

        if ref_mtime > src_file_mtime || ref_mtime > ffi_file_mtime {

            let status = Command::new("python3")
                    .arg(&r_client)
                    .arg("-o").arg(&src_dir)
                    .arg(&xml_file)
                    .env("PYTHONHASHSEED", "0")
                    .status()
                    .expect("Unable to find build dependency python3");
            if !status.success() {
                panic!("processing of {} returned non-zero ({})",
                    xml_file.display(), status.code().unwrap());
            }
        }
        Ok(())
    }).unwrap();


    let xcbgen_dir = Path::new(&root).join("xcbgen");

    println!("cargo:rerun-if-changed={}", &build_rs.display());
    println!("cargo:rerun-if-changed={}", &r_client.display());
    println!("cargo:rerun-if-changed={}", &xml_dir.display());
    println!("cargo:rerun-if-changed={}", &xcbgen_dir.display());

}
