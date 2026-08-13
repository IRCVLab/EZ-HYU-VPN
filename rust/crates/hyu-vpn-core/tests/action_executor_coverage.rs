use std::path::Path;

const EXECUTOR_SOURCES: &[(&str, &str)] = &[
    (
        "LinuxActionExecutor",
        "rust/apps/hyu-vpn-linux-service/src/lib.rs",
    ),
    (
        "MacActionExecutor",
        "rust/apps/hyu-vpn-macos-service/src/lib.rs",
    ),
    (
        "WindowsActionExecutor",
        "rust/apps/hyu-vpn-windows-service/src/runtime.rs",
    ),
];

#[test]
fn platform_action_executors_explicitly_handle_publish_error() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");

    for (executor, relative_path) in EXECUTOR_SOURCES {
        let source = std::fs::read_to_string(repo_root.join(relative_path))
            .unwrap_or_else(|err| panic!("failed to read {relative_path}: {err}"));
        let impl_marker = format!("ActionExecutor for {executor}");
        let impl_start = source
            .find(&impl_marker)
            .unwrap_or_else(|| panic!("missing {impl_marker} in {relative_path}"));
        let executor_impl = &source[impl_start..];

        assert!(
            executor_impl.contains("EngineAction::PublishError(_)")
                || executor_impl.contains("EngineAction::PublishError(error_code)"),
            "{executor} in {relative_path} must explicitly handle EngineAction::PublishError so shared enum additions do not break target platform builds"
        );
    }
}
