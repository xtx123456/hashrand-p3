use std::{collections::HashMap, time::SystemTime};

use crypto::hash::Hash;
use num_bigint::BigUint;
use types::{beacon::CTRBCMsg, beacon::{CoinMsg, GatherMsg, Replica}};

use crate::node::{Context, CTRBCState};

impl Context {
    pub async fn process_reconstruct(&mut self, ctrbc: CTRBCMsg, master_root: Hash, recon_sender: Replica) {
        let _now = SystemTime::now();
        if !self.round_state.contains_key(&ctrbc.round) {
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(ctrbc.round, rbc_new_state);
        }
        let round = ctrbc.round;
        let rbc_state = self.round_state.get_mut(&ctrbc.round).unwrap();
        let sec_origin = ctrbc.origin;
        let mut msgs_to_be_sent: Vec<CoinMsg> = Vec::new();
        log::info!(
            "Received RECON message from {} for secret from {} in round {}",
            recon_sender,
            ctrbc.origin,
            ctrbc.round
        );

        if rbc_state.terminated_secrets.contains(&sec_origin) {
            log::info!("Batch secret instance from node {} already terminated", sec_origin);
            return;
        }
        if !rbc_state.msgs.contains_key(&sec_origin) {
            rbc_state.add_recon(sec_origin, recon_sender, &ctrbc);
            return;
        }
        let (_beacon, shard) = rbc_state.msgs.get(&sec_origin).unwrap();
        if shard.mp.root() != master_root || !ctrbc.verify_mr_proof(&self.hash_context) {
            log::error!(
                "Merkle root of WSS Init from {} did not match Merkle root of Recon from {}",
                sec_origin,
                self.myid
            );
            return;
        }
        rbc_state.add_recon(sec_origin, recon_sender, &ctrbc);
        let res_root_vec = rbc_state.verify_reconstruct_rbc(
            sec_origin,
            self.num_nodes,
            self.num_faults,
            self.batch_size,
            &self.hash_context,
        );
        match res_root_vec {
            None => return,
            Some(_res) => {
                let beacon_msg = rbc_state.transform(sec_origin);
                let term_secrets = rbc_state.terminated_secrets.len();
                if term_secrets >= self.num_nodes - self.num_faults && !rbc_state.send_w1 {
                    log::info!("Terminated n-f Batch WSSs, sending list of first n-f Batch WSSs to other nodes");
                    log::info!("Terminated : {:?}", rbc_state.terminated_secrets);
                    log::info!("Terminated n-f wss instances. Sending echo2 message to everyone");
                    rbc_state.send_w1 = true;
                    let broadcast_msg = CoinMsg::GatherEcho(
                        GatherMsg {
                            nodes: rbc_state.terminated_secrets.clone().into_iter().collect(),
                        },
                        self.myid,
                        round,
                    );
                    msgs_to_be_sent.push(broadcast_msg);
                }
                if beacon_msg.appx_con.is_some() {
                    for (round_iter, messages) in beacon_msg.appx_con.clone().unwrap().into_iter() {
                        let appx_con_vals = messages
                            .into_iter()
                            .map(|(x, y)| (x, BigUint::from_bytes_be(&y)))
                            .collect();
                        let rbc_iterstate = self.round_state.get_mut(&round_iter).unwrap();
                        if rbc_iterstate.appxcon_allround_vals.contains_key(&sec_origin) {
                            let round_val_map = rbc_iterstate.appxcon_allround_vals.get_mut(&sec_origin).unwrap();
                            round_val_map.insert(round, appx_con_vals);
                        } else {
                            let mut round_val_map = HashMap::default();
                            round_val_map.insert(round, appx_con_vals);
                            rbc_iterstate.appxcon_allround_vals.insert(sec_origin, round_val_map);
                        }
                    }
                }
                if term_secrets >= self.num_nodes - self.num_faults {
                    self.witness_check(round).await;
                }
            }
        }
        for prot_msg in msgs_to_be_sent.iter() {
            self.broadcast(prot_msg.clone(), round).await;
            if let CoinMsg::GatherEcho(gather_msg, echo_sender, round) = prot_msg {
                self.process_gatherecho(gather_msg.nodes.clone(), *echo_sender, *round).await;
                self.witness_check(*round).await;
            }
        }
    }
}
