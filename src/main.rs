#![allow(dead_code)]

#[macro_use]
extern crate lazy_static;

mod dcb;
mod error;
mod network;
mod opt;
mod prober;
mod topo;
mod tracerouter;
mod utils;

use std::sync::Arc;

use error::Result;
use opt::Opt;
use topo::Topo;
use tracerouter::Tracerouter;

// 给静态变量延迟赋值的宏
lazy_static! {
    static ref OPT: Opt = if cfg!(test) {
        opt::get_test_opt()
    } else {
        opt::get_opt()
    };
}

fn init() {
    // log 设定级别
    env_logger::builder()
        .filter_level(if OPT.debug {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .parse_default_env()
        .init();

    #[cfg(unix)]
    // 检查超级管理员权限
    utils::ensure_su();

    log::info!("{:?}", *OPT);

    // 纠错模式
    #[cfg(debug_assertions)]
    log::warn!(
        "{} is built in DEBUG mode, thus may perform quite poorly.",
        env!("CARGO_PKG_NAME")
    );
}

// 程序入口
#[tokio::main]
async fn main() -> Result<()> {
    // 初始化
    init();

    // 初始化traceroute
    let tr = Arc::new(Tracerouter::new()?);

    // 复制traceroute实例
    let running = tr.clone();

    // 运行异步监听命令行强制中断指令
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        running.stop();
    });

    // 运行traceroute并把传出结果
    let topo = tr.run().await?;
    // 绘图
    // 会调用系统命令行dot工具
    Topo::process_graph(topo).await?;

    // 如果是window系统就运行
    #[cfg(windows)]
    std::process::exit(0);

    // 未处理异常
    Ok(())
}
