use anyhow::Context as _;

fn main() -> anyhow::Result<()> {
    keepassxcr::cli::run().context("keepassxcr failed")
}
