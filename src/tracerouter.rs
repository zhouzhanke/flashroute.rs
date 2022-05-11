use std::{
    io::Write,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

use hashbrown::{hash_map::HashMap, hash_set::HashSet};
use ipnet::IpAdd;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::sync::{mpsc, oneshot};
use Ordering::SeqCst;

use crate::{
    dcb::DstCtrlBlock,
    error::*,
    network::NetworkManager,
    opt::Targets,
    prober::ProbePhase,
    prober::ProbeResult,
    prober::Prober,
    topo::{Topo, TopoGraph, TopoReq},
    utils::GlobalIpv4Ext,
    OPT,
};

type MpscTx<T> = mpsc::UnboundedSender<T>;
type MpscRx<T> = mpsc::UnboundedReceiver<T>;

type AddrKey = i64;
type DcbMap = HashMap<AddrKey, DstCtrlBlock>;

#[derive(Debug, Default)]
pub struct Tracerouter {
    targets: Arc<DcbMap>,
    stopped: Arc<AtomicBool>,

    // stats
    sent_preprobes: AtomicU64,
    sent_probes: AtomicU64,
    recv_responses_pre: AtomicU64,
    recv_responses_main: AtomicU64,

    backward_count: AtomicU64,
    forward_count: AtomicU64,
    total_count: AtomicU64,
}

impl Tracerouter {
    pub fn new() -> Result<Self> {
        log::info!(
            "Using interface `{}` ({})",
            OPT.interface.name,
            crate::utils::get_interface_ipv4_addr(&OPT.interface).unwrap()
        );

        log::info!("Initializing targets...");
        let targets = Self::generate_targets()?;

        if let Some(path) = OPT.dump_targets.clone() {
            log::info!("Dumping targets...");
            Self::dump_targets(&targets, &path)?;
        }

        Ok(Self {
            targets: Arc::new(targets),
            ..Self::default()
        })
    }

    fn addr_to_key(addr: Ipv4Addr) -> AddrKey {
        let u: u32 = addr.into();
        (u >> (OPT.grain)) as AddrKey
    }

    fn generate_targets() -> Result<DcbMap> {
        match OPT.targets.clone() {
            // 从命令行导入目标地址
            Targets::Net(net) => {
                // 检查扫描跨度是否超过扫描地址长度
                if OPT.grain > (net.max_prefix_len() - net.prefix_len()) {
                    return Err(Error::BadGrainOrNet(OPT.grain, net));
                }

                // 读取随机数种子
                let mut rng = StdRng::seed_from_u64(OPT.seed);
                // 根据参数分割子网段
                let subnets = net.subnets(net.max_prefix_len() - OPT.grain).unwrap();

                // 随机选取子网段地址
                let iter = subnets
                    .map(move |net| net.addr().saturating_add(rng.gen_range(0, 1 << OPT.grain)))
                    .filter(|addr| {
                        if OPT.global_only && OPT.allow_private {
                            addr.is_bz_global() || addr.is_private()
                        } else if OPT.global_only {
                            addr.is_bz_global()
                        } else {
                            true
                        }
                    });

                // 总扫描目标数量
                let all_count = 1 << ((net.max_prefix_len() - net.prefix_len()) - OPT.grain);
                // 根据iter和all_count创建hash map
                let mut generated_targets = DcbMap::with_capacity(all_count);
                for addr in iter {
                    generated_targets.insert(
                        Self::addr_to_key(addr),
                        DstCtrlBlock::new(addr, OPT.split_ttl),
                    );
                }
                // 输出结果
                let filtered_count = generated_targets.len();
                log::info!(
                    "Generated {} targets, {} removed",
                    filtered_count,
                    all_count - filtered_count
                );

                Ok(generated_targets)
            }

            // 从文件导入目标地址
            Targets::List(path) => {
                let mut generated_targets = DcbMap::new();

                let content = std::fs::read_to_string(path)?;
                for line in content.lines() {
                    if line.is_empty() {
                        continue;
                    }
                    let addr = line
                        .parse()
                        .or(Err(Error::InvalidIpv4Addr(line.to_owned())))?;
                    generated_targets.insert(
                        Self::addr_to_key(addr),
                        DstCtrlBlock::new(addr, OPT.split_ttl),
                    );
                }
                log::info!("Imported {} targets from file", generated_targets.len());

                Ok(generated_targets)
            }
        }
    }

    fn dump_targets(targets: &DcbMap, path: &PathBuf) -> Result<()> {
        let mut file = std::fs::File::create(path)?;
        for DstCtrlBlock { addr, .. } in targets.values() {
            file.write_fmt(format_args!("{}\n", addr.to_string()))?;
        }

        Ok(())
    }
}

impl Tracerouter {
    pub async fn run(&self) -> Result<TopoGraph> {
        // 记录初始时间
        let start_time = SystemTime::now();

        // 启动预探测
        let _ = self.run_preprobing_task().await?;
        // 启动主探测
        let topo = self.run_probing_task().await?;

        // 记录结束时间
        let end_time = SystemTime::now();

        // 输出结果
        log::info!(
            "[Summary] Pre: sent {:?}, recv {:?};  Main: sent {:?}, recv {:?}",
            self.sent_preprobes,
            self.recv_responses_pre,
            self.sent_probes,
            self.recv_responses_main
        );
        log::info!(
            "[Summary] Elapsed: {} secs",
            end_time.duration_since(start_time).unwrap().as_secs()
        );
        log::info!(
            "[Summary] Interfaces: forward {}, backward {}, total {}",
            self.forward_count.load(SeqCst),
            self.backward_count.load(SeqCst),
            self.total_count.load(SeqCst),
        );

        Ok(topo)
    }

    pub fn stop(&self) {
        self.stopped.store(true, SeqCst);
    }

    fn stopped(&self) -> bool {
        self.stopped.load(SeqCst)
    }
}

impl Tracerouter {
    async fn run_preprobing_task(&self) -> Result<()> {
        // 生成预探测探针
        let prober = Prober::new(ProbePhase::Pre);
        // 开启<数据包分析模块>的消息队列
        let (recv_tx, mut recv_rx) = mpsc::unbounded_channel();
        // 开启网络
        let mut nm = NetworkManager::new(prober, recv_tx)?;
        // 开启<数据包分析模块>的停止信号消息队列
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

        // 异步接收探针
        let targets = self.targets.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // 接收
                    Some(result) = recv_rx.recv() => {
                        Self::preprobing_callback(&targets, result);
                    }
                    // 停止
                    _ = &mut stop_rx => {
                        return;
                    }
                };
            }
        });

        // WORKER BEGIN
        // 进度条
        let mut pb = pbr::ProgressBar::new(self.targets.len() as u64);
        // 进度条刷新率
        pb.set_max_refresh_rate(Some(Duration::from_millis(100)));
        //
        for target in self.targets.values() {
            // 进度条递增
            pb.inc();
            // 停止
            if self.stopped() {
                break;
            }
            // 发送探针
            nm.schedule_probe((target.addr, OPT.preprobing_ttl)).await;
        }
        // 进度条完成
        pb.finish();
        // WORKER END

        // 等待3秒时间
        if !self.stopped() {
            log::info!("[Pre] Waiting for 3 secs...");
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        // 停止网络
        nm.stop();
        // 给接收进程发送停止信号
        let _ = stop_tx.send(());

        // 预发送计数
        let preprobed_count = {
            let mut c = 0u64;
            for _ in self
                .targets
                .values()
                .filter(|dcb| dcb.preprobed.load(SeqCst))
            {
                c += 1;
            }
            c
        };
        // 输出结果
        log::info!("Preprobed: {}", preprobed_count);

        // 记录数据,预探测阶段的发送和接收
        self.sent_preprobes.fetch_add(nm.sent_packets(), SeqCst);
        self.recv_responses_pre.fetch_add(nm.recv_packets(), SeqCst);

        Ok(())
    }

    fn preprobing_callback(targets: &DcbMap, result: ProbeResult) {
        // 检查回应地址是否是探测地址
        if !result.from_destination {
            return;
        }
        // 输出结果
        log::trace!("[Pre] CALLBACK: {}", result.destination);

        // 更新分割跳数
        let key = Self::addr_to_key(result.destination);
        if let Some(dcb) = targets.get(&key) {
            // 更新目标地址分割跳数
            dcb.update_split_ttl(result.distance, true);

            // 更新目标地址临近的地址分割跳数
            // proximity
            let lo = 0.max(key - OPT.proximity_span as AddrKey);
            let hi = key + OPT.proximity_span as AddrKey;
            for n_key in lo..=hi {
                if n_key == key {
                    continue;
                }
                if let Some(dcb) = targets.get(&n_key) {
                    dcb.update_split_ttl(result.distance, false);
                }
            }
        }
    }
}

impl Tracerouter {
    async fn run_probing_task(&self) -> Result<TopoGraph> {
        let prober = Prober::new(ProbePhase::Main);
        // <数据分析>的消息队列
        let (recv_tx, mut recv_rx) = mpsc::unbounded_channel();
        // 开启网络
        let mut nm = NetworkManager::new(prober, recv_tx)?;
        // <数据分析>和<绘图信息>的停止信号消息队列
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

        let targets = self.targets.clone();
        // 正向探测储存单元
        let mut backward_stop_set = HashSet::<Ipv4Addr>::with_capacity(1_100_000);
        // 反向探测储存单元
        let mut forward_discovery_set = HashSet::<Ipv4Addr>::with_capacity(200_000);

        // <绘图信息>的消息队列
        let (topo_tx, topo_rx) = mpsc::unbounded_channel();
        let cb_topo_tx = topo_tx.clone();

        // 开启绘图模块
        // <绘图信息>消息队列接收方
        let topo_task = tokio::spawn(async move { Topo::new(topo_rx).run() });

        // 数据分析模块
        // <数据分析>消息队列接收方
        // <绘图信息>消息队列发送方
        let callback_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(result) = recv_rx.recv() => {
                        // 数据分析
                        Self::probing_callback(&targets, &mut backward_stop_set, &mut forward_discovery_set, &result);
                        // <绘图信息>消息队列发送方
                        let _ = cb_topo_tx.send(TopoReq::Result(result));
                    }
                    // 停止信号
                    _ = &mut stop_rx => {
                        // <绘图信息>消息队列发送方
                        let _ = cb_topo_tx.send(TopoReq::Stop);
                        break;
                    }
                };
            }
            return (backward_stop_set, forward_discovery_set);
        });

        // WORKER BEGIN
        // 从链表中获得所有凭证
        let mut keys: Vec<_> = self.targets.keys().cloned().collect();
        // 记录时间
        let mut last_seen = SystemTime::now();
        let one_sec = Duration::from_secs(1);

        let mut round = 0usize;
        while !keys.is_empty() {
            round += 1;

            let total_count = keys.len();
            let mut new_keys = Vec::with_capacity(total_count);

            log::trace!("[Main] loop");
            let mut pb = pbr::ProgressBar::new(total_count as u64);
            pb.set_max_refresh_rate(Some(Duration::from_millis(100)));
            for key in keys {
                pb.inc();
                if self.stopped() {
                    break;
                }
                // 使用array中的凭证获得链表中的信息
                let dcb = self.targets.get(&key).unwrap();

                let mut ok = true;
                // 反向探测
                if let Some(t) = dcb.pull_backward_task() {
                    nm.schedule_probe((dcb.addr, t)).await;
                    ok = false;
                }
                // 正向探测
                if let Some(t) = dcb.pull_forward_task() {
                    nm.schedule_probe((dcb.addr, t)).await;
                    ok = false;
                }
                // 如果没有完成探测任务则加入下一轮探测
                if !ok {
                    new_keys.push(key);
                }
            }
            pb.finish();
            keys = new_keys;

            // 间隔时间控制
            let duration = SystemTime::now().duration_since(last_seen).unwrap();
            let min_round_duration = one_sec.min(Duration::from_millis(keys.len() as u64 * 20));
            if duration < min_round_duration {
                tokio::time::sleep(min_round_duration - duration).await;
            }
            // 记录时间
            last_seen = SystemTime::now();

            // 计算剩余待发探针数量
            let remain_count = keys.len();
            // 输出结果
            log::info!(
                "round {:3}: total {:8}, complete {:8}, remain {:8};  sent {:8}, recv {:8}",
                round,
                total_count,
                total_count - remain_count,
                remain_count,
                nm.sent_packets(),
                nm.recv_packets(),
            );
        }
        // WORKER END

        // 等待5秒时间接收探针
        if !self.stopped() {
            log::info!("[Main] Waiting for 5 secs...");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        // 停止网络
        nm.stop();
        // 发送停止信号
        let _ = stop_tx.send(());

        log::info!("Generating statistics and topology...");
        let (mut backward_set, forward_set) = callback_task.await.unwrap();

        // stats
        self.backward_count.store(backward_set.len() as u64, SeqCst);
        self.forward_count.store(forward_set.len() as u64, SeqCst);
        backward_set.extend(forward_set.iter());
        self.total_count.store(backward_set.len() as u64, SeqCst);

        self.sent_probes.fetch_add(nm.sent_packets(), SeqCst);
        self.recv_responses_main
            .fetch_add(nm.recv_packets(), SeqCst);

        // 返回绘图数据
        Ok(topo_task.await.unwrap().await)
    }

    fn probing_callback(
        targets: &DcbMap,
        backward_stop_set: &mut HashSet<Ipv4Addr>,
        forward_discovery_set: &mut HashSet<Ipv4Addr>,
        result: &ProbeResult,
    ) {
        log::trace!("[Main] CALLBACK: {}", result.destination);

        let key = Self::addr_to_key(result.destination);
        if let Some(dcb) = targets.get(&key) {
            if !result.from_destination {
                // hosts on the path
                if result.distance > dcb.initial_ttl() {
                    // o-o-o-S-o-X-o-D
                    forward_discovery_set.insert(result.responder);
                } else {
                    // o-X-o-S-o-o-o-D
                    let new = backward_stop_set.insert(result.responder);
                    if !new && OPT.redundancy_removal {
                        log::trace!("STOP for {}", dcb.addr);
                        dcb.stop_backward();
                    }
                }
                if result.distance <= dcb.last_forward_task() {
                    // reasonable distance, update horizon
                    dcb.set_forward_horizon((result.distance + OPT.gap).min(OPT.max_ttl));
                }
            } else {
                // from destination
                if !OPT.router_only {
                    backward_stop_set.insert(result.responder);
                }
                dcb.stop_forward();
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generation() {
        let tr = Tracerouter::new().unwrap();
        if let Targets::Net(targets) = OPT.targets {
            assert_eq!(
                tr.targets.len(),
                1 << (32 - targets.prefix_len() - OPT.grain)
            );
            assert!(tr.targets.values().all(|dcb| targets.contains(&dcb.addr)));
        } else {
            panic!();
        }
    }
}
