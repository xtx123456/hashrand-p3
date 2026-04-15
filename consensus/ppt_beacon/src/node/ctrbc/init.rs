use std::time::SystemTime;

use types::{beacon::{BeaconMsg, CoinMsg}, beacon::CTRBCMsg};

use crate::node::{Context, CTRBCState};

impl Context {
    pub async fn process_rbcinit(&mut self, beacon_msg: BeaconMsg, ctr: CTRBCMsg) {
        let now = SystemTime::now();
        let round = beacon_msg.round;
        let dealer = ctr.origin;

        if !self.round_state.contains_key(&round) {
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        // Complaint-after-ACS: invalid packets are dropped here, but no dealer is blamed
        // and no control-flow state is changed before post-ACS accountability.
        if !ctr.verify_mr_proof(&self.hash_context) {
            log::warn!(
                "[PPT][DROP] Invalid RBC shard Merkle proof from dealer {} in round {}",
                dealer, round
            );
            return;
        }

        if !beacon_msg.verify_proofs(&self.hash_context) {
            log::warn!(
                "[PPT][DROP] Invalid WSS batch proof from dealer {} in round {}",
                dealer, round
            );
            return;
        }

        log::info!("Received RBC Init from node {} for round {}", dealer, round);
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        rbc_state.add_message(beacon_msg.clone(), ctr.clone());
        rbc_state.add_echo(beacon_msg.origin, self.myid, &ctr);
        rbc_state.add_ready(beacon_msg.origin, self.myid, &ctr);

        self.broadcast(CoinMsg::CTRBCEcho(ctr.clone(), ctr.mp.root(), self.myid), ctr.round)
            .await;
        self.add_benchmark(
            String::from("process_batchwss_init"),
            now.elapsed().unwrap().as_nanos(),
        );
    }
}
