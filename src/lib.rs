mod application;
pub mod domain;
pub mod infrastructure;
pub mod interface;
pub fn run() -> anyhow::Result<()> {
    application::run()
}
