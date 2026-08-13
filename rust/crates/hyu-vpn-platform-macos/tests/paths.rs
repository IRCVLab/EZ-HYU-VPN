use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use hyu_vpn_platform_macos::{MacPaths, PlatformError};
use tempfile::TempDir;

fn uid() -> u32 {
    fs::metadata(".").unwrap().uid()
}

fn make_private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn production_uses_canonical_application_support_and_helper_paths() {
    let home = Path::new("/Users/alice");
    let paths = MacPaths::production(home).unwrap();

    assert_eq!(
        paths.state_dir,
        Path::new("/Users/alice/Library/Application Support/hyu-openconnect")
    );
    assert_eq!(
        paths.credential_key,
        Path::new("/Users/alice/Library/Application Support/hyu-openconnect/credentials.key")
    );
    assert_eq!(
        paths.credentials,
        Path::new("/Users/alice/Library/Application Support/hyu-openconnect/credentials.enc")
    );
    assert_eq!(
        paths.socket,
        Path::new("/Users/alice/Library/Application Support/hyu-openconnect/daemon.sock")
    );
    assert_eq!(
        paths.status,
        Path::new("/Users/alice/Library/Application Support/hyu-openconnect/status.json")
    );
    assert_eq!(
        paths.automatic_reconnect,
        Path::new("/Users/alice/Library/Application Support/hyu-openconnect/automatic-reconnect")
    );
    assert_eq!(
        paths.totp_counter,
        Path::new("/Users/alice/Library/Application Support/hyu-openconnect/totp-counter")
    );
    assert_eq!(
        paths.helper,
        Path::new("/Library/PrivilegedHelperTools/com.hyu.vpn.helper")
    );
}

#[test]
fn production_rejects_non_absolute_or_relative_component_home() {
    assert!(matches!(
        MacPaths::production(Path::new("relative/home")),
        Err(PlatformError::InvalidPath)
    ));
    assert!(matches!(
        MacPaths::production(Path::new("/Users/alice/../bob")),
        Err(PlatformError::InvalidPath)
    ));
}

#[test]
fn under_builds_bounded_absolute_paths() {
    let root = TempDir::new().unwrap();
    let paths = MacPaths::under(root.path(), 501);

    assert_eq!(
        paths.state_dir,
        root.path()
            .join("501/Library/Application Support/hyu-openconnect")
    );
    assert_eq!(
        paths.credential_key,
        paths.state_dir.join("credentials.key")
    );
    assert_eq!(paths.credentials, paths.state_dir.join("credentials.enc"));
    assert_eq!(paths.socket, paths.state_dir.join("daemon.sock"));
    assert_eq!(paths.status, paths.state_dir.join("status.json"));
    assert_eq!(
        paths.automatic_reconnect,
        paths.state_dir.join("automatic-reconnect")
    );
    assert_eq!(paths.totp_counter, paths.state_dir.join("totp-counter"));
    assert_eq!(
        paths.helper,
        root.path()
            .join("Library/PrivilegedHelperTools/com.hyu.vpn.helper")
    );

    for path in [
        &paths.state_dir,
        &paths.credential_key,
        &paths.credentials,
        &paths.socket,
        &paths.status,
        &paths.automatic_reconnect,
        &paths.totp_counter,
        &paths.helper,
    ] {
        assert!(path.is_absolute(), "{} is not absolute", path.display());
        assert!(
            !path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        );
    }
}

#[test]
#[should_panic(expected = "MacPaths::under root must be absolute and normalized")]
fn under_rejects_relative_roots_so_paths_stay_absolute() {
    let _ = MacPaths::under(Path::new("relative-root"), 501);
}

#[test]
fn state_dir_requires_exact_0700_without_missing_write_or_special_bits() {
    let temp = TempDir::new().unwrap();
    let state_dir = temp.path().join("state");
    make_private_dir(&state_dir);
    let actual_uid = fs::symlink_metadata(&state_dir).unwrap().uid();

    for insecure_mode in [0o500, 0o1700, 0o2700, 0o4700] {
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(insecure_mode)).unwrap();
        assert!(
            matches!(
                MacPaths::validate_state_dir_for_owner(&state_dir, actual_uid),
                Err(PlatformError::InsecureStateDirectory)
            ),
            "mode {insecure_mode:o} should be rejected"
        );
    }

    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
    MacPaths::validate_state_dir_for_owner(&state_dir, actual_uid).unwrap();
}

#[test]
fn production_rejects_symlink_world_accessible_and_wrong_owner_state_dirs() {
    let temp = TempDir::new().unwrap();
    let home = temp.path().join("home");
    let state_dir = home.join("Library/Application Support/hyu-openconnect");
    make_private_dir(&state_dir);
    assert!(MacPaths::production(&home).is_ok());

    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        MacPaths::production(&home),
        Err(PlatformError::InsecureStateDirectory)
    ));

    fs::remove_dir_all(&state_dir).unwrap();
    let target = temp.path().join("target");
    make_private_dir(&target);
    symlink(&target, &state_dir).unwrap();
    assert!(matches!(
        MacPaths::production(&home),
        Err(PlatformError::InsecureStateDirectory)
    ));
    fs::remove_dir_all(&state_dir).unwrap();
    symlink(temp.path().join("missing-target"), &state_dir).unwrap();
    assert!(matches!(
        MacPaths::production(&home),
        Err(PlatformError::InsecureStateDirectory)
    ));

    fs::remove_file(&state_dir).unwrap();
    make_private_dir(&state_dir);
    let actual_uid = fs::symlink_metadata(&state_dir).unwrap().uid();
    assert_eq!(actual_uid, uid());
    assert!(matches!(
        MacPaths::validate_state_dir_for_owner(&state_dir, actual_uid.saturating_add(1)),
        Err(PlatformError::InsecureStateDirectory)
    ));
}
