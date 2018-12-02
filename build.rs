extern crate git_version;

fn main() {
    git_version::set_env_with_name("PKG_GIT_VERSION");
}
