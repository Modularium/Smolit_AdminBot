fn main() {
    if let Err(error) = adminbotd::run_daemon() {
        eprintln!("adminbotd startup failed: {error}");
        std::process::exit(1);
    }
}
