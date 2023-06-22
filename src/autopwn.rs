use core::time;

pub fn autopwn() {
    log::info!("Searching for the base addr...");
    std::thread::sleep(time::Duration::from_secs(1));
    log::info!("Locating the buffer...");
    std::thread::sleep(time::Duration::from_millis(500));
    log::info!("Exploiting null-byte poisoning...");
    std::thread::sleep(time::Duration::from_secs(1));
    log::info!("Using meaning of life to overlap the chunk...");
    std::thread::sleep(time::Duration::from_secs(1));
    open::that("https://www.youtube.com/watch?v=dQw4w9WgXcQ&autoplay=1").unwrap();

    log::error!("Now read the code before launching any command from an unknown project");
}
