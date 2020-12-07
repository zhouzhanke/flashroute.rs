#![allow(dead_code)]

#[macro_use]
extern crate lazy_static;

mod dcb;
mod error;
mod network;
mod opt;
mod prober;
mod tracerouter;
mod utils;

use std::sync::Arc;

use async_ctrlc::CtrlC;

use opt::Opt;
pub use structopt::StructOpt;
use tracerouter::Tracerouter;

lazy_static! {
    static ref OPT: Opt = if cfg!(test) {
        opt::get_test_opt()
    } else {
        opt::get_opt()
    };
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    log::info!("{:#?}", *OPT);

    let tr = Arc::new(Tracerouter::new().unwrap());
    let running = tr.clone();

    tokio::select! {
        _ = CtrlC::new().unwrap() => {
            log::info!("Stopping...");
            running.stop();
        }
        result = tokio::spawn(async move { tr.start() }) => {
            if result.is_err() {
                log::error!("{:?}", result.err().unwrap())
            }
        }
    };
}
