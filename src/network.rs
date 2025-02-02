use std::{
    net::IpAddr,
    sync::atomic::Ordering,
    sync::{
        atomic::{AtomicBool, AtomicU64},
        Arc,
    },
    time::Duration,
    time::SystemTime,
};

use crate::{
    error::*,
    prober::{ProbeResult, ProbeUnit, Prober},
    OPT,
};
use pnet::{
    packet::{
        ip::IpNextHeaderProtocols::{Icmp, Udp},
        ipv4::Ipv4Packet,
        Packet,
    },
    transport::{transport_channel, TransportChannelType::Layer3},
};
use tokio::sync::{mpsc, oneshot};
use Ordering::SeqCst;

type MpscTx<T> = mpsc::UnboundedSender<T>;
type MpscRx<T> = mpsc::UnboundedReceiver<T>;

type BMpscTx<T> = mpsc::Sender<T>;
type BMpscRx<T> = mpsc::Receiver<T>;

type OneshotTx<T> = oneshot::Sender<T>;
type OneshotRx<T> = oneshot::Receiver<T>;

pub struct NetworkManager {
    sent_packets: Arc<AtomicU64>,
    recv_packets: Arc<AtomicU64>,
    send_tx: BMpscTx<ProbeUnit>,
    stopped: Arc<AtomicBool>,
    stop_txs: Vec<OneshotTx<()>>,
}

impl NetworkManager {
    pub fn new(prober: Prober, recv_tx: MpscTx<ProbeResult>) -> Result<Self> {
        // 开启<监听探针发送>的消息队列
        let (send_tx, send_rx) = mpsc::channel(OPT.probing_rate.min(400_000).max(1_000) as usize);

        let prober = Arc::new(prober);
        let sent_packets = Arc::new(AtomicU64::new(0));
        let recv_packets = Arc::new(AtomicU64::new(0));
        let mut stop_txs = Vec::new();

        // 开启<监听探针发送>的停止信号消息队列
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        // <监听探针发送>停止信号消息队列的发送方集合
        stop_txs.push(stop_tx);
        // 开启发送进程
        // send_rx<监听探针发送>接收方
        // stop_rx<监听探针发送>停止信号接收方
        Self::start_sending_task(prober.clone(), send_rx, stop_rx, sent_packets.clone())?;

        let stopped = Arc::new(AtomicBool::new(false));
        Self::start_recving_task(
            prober.clone(),
            stopped.clone(),
            recv_packets.clone(),
            recv_tx,
        )?;

        Ok(Self {
            sent_packets,
            recv_packets,
            // <监听探针发送>消息队列的发送方
            send_tx,
            stopped,
            // <监听探针发送>停止信号消息队列的发送方集合
            stop_txs,
        })
    }

    fn start_sending_task(
        prober: Arc<Prober>,
        mut rx: BMpscRx<ProbeUnit>,
        mut stop_rx: OneshotRx<()>,
        sent_packets: Arc<AtomicU64>,
    ) -> Result<()> {
        // 使用UDP数据包
        let protocol = Layer3(Udp);
        // 开启网络
        let (mut sender, _) = transport_channel(0, protocol)?;
        // IPv4
        let local_ip = OPT.local_addr;

        // 开启<网络发送模块>的消息队列
        let (net_send_tx, mut net_send_rx) = mpsc::channel::<Ipv4Packet>(10000);

        tokio::spawn(async move {
            loop {
                if let Some(packet) = net_send_rx.recv().await {
                    if !OPT.dry_run {
                        let dst = packet.get_destination();
                        // 发送
                        let _ = sender.send_to(packet, IpAddr::V4(dst));
                    }
                } else {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            log::info!("[{:?}] sending task started", prober.phase);

            let mut sent_this_sec = 0u64;
            let mut last_seen = SystemTime::now();
            let one_sec = Duration::from_secs(1);

            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        break;
                    }
                    Some(dst_unit) = rx.recv() => {
                        // Probing rate control
                        if sent_this_sec % 128 == 0 {
                            let now = SystemTime::now();
                            let time_elapsed = now.duration_since(last_seen).unwrap();
                            if time_elapsed >= one_sec {
                                sent_this_sec = 0;
                                last_seen = now;
                            }
                            if sent_this_sec > OPT.probing_rate {
                                tokio::time::sleep(one_sec - time_elapsed).await;
                            }
                        }

                        let mut buf = vec![0u8; Prober::PACK_BUFFER_LENGTH];
                        // 生成数据包
                        let len = prober.pack(dst_unit, local_ip, &mut buf);
                        buf.resize(len, 0);
                        let packet = Ipv4Packet::owned(buf).unwrap();
                        // 使用消息队列传递数据包并最终发送数据包
                        let _ = net_send_tx.send(packet).await;

                        log::trace!("PROBE: {:?}", dst_unit);

                        // 发送包计数
                        sent_packets.fetch_add(1, SeqCst);
                        sent_this_sec += 1;
                    }
                }
            }

            log::info!("[{:?}] sending task stopped", prober.phase);
        });

        Ok(())
    }

    const RECV_BUF_SIZE: usize = 400 * 1024;

    fn start_recving_task(
        prober: Arc<Prober>,
        stopped: Arc<AtomicBool>,
        recv_packets: Arc<AtomicU64>,
        recv_tx: MpscTx<ProbeResult>,
    ) -> Result<()> {
        // 接收ICMP数据包
        let protocol = Layer3(Icmp);
        // 开启接收网络
        let (_, mut receiver) = transport_channel(Self::RECV_BUF_SIZE, protocol)?;

        #[cfg(unix)]
        tokio::task::spawn_blocking(move || {
            // pnet io is synchronous, must be spawned with blocking
            log::info!("[{:?}] receiving task started", prober.phase);

            // 定义超时时间
            let io_timeout = Duration::from_millis(10);
            // 接收循环器
            let mut iter = pnet::transport::ipv4_packet_iter(&mut receiver);

            loop {
                if stopped.load(SeqCst) {
                    break;
                }

                if let Ok(Some((ip_packet, _addr))) = iter.next_with_timeout(io_timeout) {
                    // 匹配探针并对结果进行分类操作
                    match prober.parse(ip_packet.packet(), false) {
                        Ok(result) => {
                            log::debug!("[{:?}] RECV: {:?}", prober.phase, result);
                            // 使用消息队列把接收到的数据包传给分析模块
                            let _ = recv_tx.send(result);
                            // 计数
                            recv_packets.fetch_add(1, SeqCst);
                        }
                        Err(e @ Error::ParseError(_)) => {
                            log::warn!("error occurred while parsing: {}", e);
                        }
                        Err(e) => {
                            log::debug!("error occurred while parsing: {}", e);
                        }
                    }
                }
            }

            log::info!("[{:?}] receiving task stopped", prober.phase);
        });

        #[cfg(windows)]
        {
            let fd = receiver.socket.fd;

            tokio::task::spawn_blocking(move || {
                // pnet io is synchronous, must be spawned with blocking
                log::info!("[{:?}] receiving task started", prober.phase);

                let mut iter = pnet::transport::ipv4_packet_iter(&mut receiver);

                loop {
                    match iter.next() {
                        Ok((ip_packet, _addr)) => match prober.parse(ip_packet.packet(), false) {
                            Ok(result) => {
                                log::debug!("[{:?}] RECV: {:?}", prober.phase, result);
                                let _ = recv_tx.send(result);
                                recv_packets.fetch_add(1, SeqCst);
                            }
                            Err(e @ Error::ParseError(_)) => {
                                log::warn!("error occurred while parsing: {}", e);
                            }
                            Err(e) => {
                                log::debug!("error occurred while parsing: {}", e);
                            }
                        },
                        Err(_) => {
                            break;
                        }
                    }
                }

                log::info!("[{:?}] receiving task stopped", prober.phase);
            });

            tokio::spawn(async move {
                let poll_timeout = Duration::from_millis(200);
                loop {
                    if stopped.load(SeqCst) {
                        log::warn!("Windows: try closing socket");
                        unsafe {
                            pnet_sys::close(fd);
                        }
                        break;
                    }
                    tokio::time::sleep(poll_timeout).await;
                }
            });
        }

        Ok(())
    }

    pub async fn schedule_probe(&self, unit: ProbeUnit) {
        let _ = self.send_tx.send(unit).await;
    }

    pub fn stop(&mut self) {
        self.stopped.store(true, SeqCst);
        for tx in self.stop_txs.drain(..) {
            let _ = tx.send(());
        }
    }

    pub fn sent_packets(&self) -> u64 {
        self.sent_packets.load(SeqCst)
    }

    pub fn recv_packets(&self) -> u64 {
        self.recv_packets.load(SeqCst)
    }
}
