use anyhow::Context as _;
use keepassxcr::error::AppError;

/// Exit code when a database's unlock agent expired, so scripts can tell it apart.
const EXIT_LOCKED: i32 = 3;

fn main() -> anyhow::Result<()> {
    let result = keepassxcr::cli::run();
    if let Err(err) = &result {
        match err
            .chain()
            .find_map(|cause| cause.downcast_ref::<AppError>())
        {
            Some(locked @ AppError::Locked(_)) => {
                eprintln!("keepassxcr: {locked}");
                std::process::exit(EXIT_LOCKED);
            }
            Some(AppError::Reported) => std::process::exit(1),
            _ => {}
        }
    }
    result.context("keepassxcr failed")
}
