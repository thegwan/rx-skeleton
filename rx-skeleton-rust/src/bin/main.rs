use rx_skeleton_rust::{
    dpdk,
};

use std::ffi::CString;
use std::mem::MaybeUninit;
use std::ptr;
use std::env;

const PORT_ID: u16 = 0;
const CAPACITY: u32 = 65535;
const CACHE_SIZE: u32 = 512;
const NB_RX_DESC: u16 = 4096;

const SYMMETRIC_RSS_KEY: [u8; 40] = [ 
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
];

fn main() {
    dpdk::load_mlx5_driver();

    println!("Rust rx-skeleton");

    println!("Initializing EAL...");
    let mut args = vec![];
    let mut ptrs = vec![];
    for arg in env::args() {
        let s = CString::new(arg).unwrap();
        ptrs.push(s.as_ptr() as *mut u8);
        args.push(s);
    }

    {
        let ret = unsafe {dpdk::rte_eal_init(ptrs.len() as i32, ptrs.as_ptr() as *mut _)};
        assert!(ret >= 0);
    }

    println!("Initializing mbufpool on socket 0...");
    let mbufpool = mbufpool_init();

    println!("Initializing port 0...");
    port_init(mbufpool);
    
    {
        let ret = unsafe {dpdk::rte_eth_promiscuous_enable(PORT_ID)};
        assert!(ret >= 0);
    }
}

fn mbufpool_init() -> *mut dpdk::rte_mempool {
    let name = CString::new("mbufpool0").unwrap();
    let mbufpool = unsafe {dpdk::rte_pktmbuf_pool_create(
        name.as_ptr(), 
        CAPACITY, 
        CACHE_SIZE, 
        0, 
        dpdk::RTE_MBUF_DEFAULT_BUF_SIZE as u16, 
        0,
    )};
    assert!(!mbufpool.is_null());
    mbufpool
}

fn port_init(mbufpool: *mut dpdk::rte_mempool) {
    let mut port_conf: dpdk::rte_eth_conf = unsafe { 
            MaybeUninit::zeroed().assume_init() 
    };

    // turns on RSS
    port_conf.rxmode.mq_mode = dpdk::rte_eth_rx_mq_mode_ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_key = SYMMETRIC_RSS_KEY.as_ptr() as *mut u8;
    port_conf.rx_adv_conf.rss_conf.rss_key_len = 40 as u8;
    port_conf.rx_adv_conf.rss_conf.rss_hf = dpdk::ETH_RSS_IP as u64
                                            | dpdk::ETH_RSS_TCP as u64
                                            | dpdk::ETH_RSS_UDP as u64;
    
    // 1518 Byte max ethernet length
    port_conf.rxmode.max_rx_pkt_len = dpdk::RTE_ETHER_MAX_LEN;  

    // turns on VLAN stripping
    port_conf.rxmode.offloads |= dpdk::DEV_RX_OFFLOAD_VLAN_STRIP as u64;

    let nb_workers: u16 = unsafe {dpdk::rte_lcore_count() - 1} as u16;
    
    unsafe {
        let ret = dpdk::rte_eth_dev_configure(
            PORT_ID, nb_workers, 0, &port_conf as *const _
        );
        assert_eq!(ret, 0);


        let mut q = 0;
        let mut lcore_id = dpdk::rte_get_next_lcore(std::u32::MAX, 1, 0);
        while lcore_id < dpdk::RTE_MAX_LCORE {
            dpdk::rte_eth_rx_queue_setup(
                PORT_ID, 
                q, 
                NB_RX_DESC,
                dpdk::rte_eth_dev_socket_id(PORT_ID) as u32, 
                ptr::null(), 
                mbufpool.as_mut().unwrap(),
            );

            q += 1;
            lcore_id = dpdk::rte_get_next_lcore(lcore_id, 1, 0);
        }
    }
}