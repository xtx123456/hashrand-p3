use std::{ time::SystemTime};

use async_recursion::async_recursion;
use crypto::{hash::{do_hash, Hash}, aes_hash::MerkleTree};
use num_bigint::{BigUint, RandBigInt};
use types::{appxcon::get_shards, beacon::{BatchWSSMsg, CoinMsg, CTRBCMsg, WrapperMsg, Val}, Replica, beacon::{Round, BeaconMsg}};

use crate::node::{Context, ShamirSecretSharing};
use crate::node::shamir::two_field::TwoFieldDealer;


/**
 * Phase 4B: Two-Field SS-AVSS Secret Sharing Distribution.
 *
 * The Dealer uses the TwoFieldDealer to generate dual-polynomial shares:
 * - f(x) over small field F_p encodes the real beacon secret
 * - g(x) over large field F_q serves as a random mask
 * - h(x) = g(x) - θ·f(x) is publicly broadcast for degree testing
 *
 * Data flow per secret k in batch:
 *   1. TwoFieldDealer.share_secret(s_k, θ) → TwoFieldShares
 *   2. secret_shares[i] = f(i) mod p → used for reconstruction
 *   3. f_large_shares[i] = f(i) mod q → used for degree test verification
 *   4. mask_shares[i] = g(i) mod q → used for degree test verification
 *   5. degree_test_coeffs = h(x) coefficients → publicly broadcast
 *   6. nonce_shares + Merkle tree → commitment protection (unchanged)
 *
 * θ (theta) is derived from the previous round's beacon output.
 * For the first round (no prior beacon), θ = 0.
 */

impl Context{
    #[async_recursion]
    pub async fn start_new_round(&mut self, round:Round,vec_round_vals:Vec<(Round,Vec<(Replica,BigUint)>)>){
        let now = SystemTime::now();
        let mut new_round = round + 1;

        // Do not start a new round after this cap hits
        if round == 20000{
            new_round = 0;
        }
        else if self.curr_round > round || self.curr_round > self.max_rounds{
            return;
        }
        
        log::info!("[PPT] Protocol started");
        let mut beacon_msgs = Vec::new();
        let mut rbc_vec = Vec::new();
        let vec_round_msgs:Vec<(Round,Vec<(Replica,Val)>)> = vec_round_vals.into_iter().map(|(x,y)| {
            let mut msgs_vec = Vec::new();
            for (rep,val) in y.into_iter(){
                msgs_vec.push((rep,Self::pad_shares(val)));
            }
            (x,msgs_vec)
        }).collect();

        // Start a new BAwVSS instance once every frequency rounds.
        if new_round % self.frequency == 0 {
            let faults = self.num_faults;
            let batch_size = self.batch_size;
            let low_r = BigUint::from(0u32);
            let prime = self.secret_domain.clone();
            let nonce_prime = self.nonce_domain.clone();

            let two_field_dealer = TwoFieldDealer::new(
                prime.clone(),
                nonce_prime.clone(),
                faults + 1,      // threshold t = f+1
                3 * faults + 1,  // share_amount n = 3f+1
            );

            // IMPORTANT:
            // The verifier in secret_reconstruct.rs uses the previous logical round
            // of the SHARED round. So the sender must do the same.
            //
            // - For shared round 0, theta = 0
            // - For shared round r>0, theta = get_previous_theta(r-1)
            //
            // Using `round` directly here breaks the bootstrap round because the caller
            // may pass 20000 to create logical round 0.
            let theta = self.get_previous_theta(new_round.saturating_sub(1));

            let mut share_vec: Vec<[u8;32]> = Vec::new();
            let mut nonce_share_vec: Vec<[u8;32]> = Vec::new();

            // degree_test_batch[coin] = h(x) coefficients for that coin
            let mut degree_test_batch: Vec<Vec<Val>> = Vec::with_capacity(batch_size);
            // Per-recipient arrays indexed by recipient node id (0-based)
            let mut mask_shares_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(batch_size); self.num_nodes];
            let mut f_large_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(batch_size); self.num_nodes];

            // IMPORTANT:
            // Generate EXACTLY batch_size secrets. The previous `batch_size + 1` caused
            // the two-field side data to become longer than the actual coin packets.
            for _ in 0..batch_size {
                let secret = rand::thread_rng().gen_biguint_range(&low_r, &prime);

                let two_field_shares = two_field_dealer.share_secret(secret, &theta);

                let nonce_ss = ShamirSecretSharing{
                    threshold: faults + 1,
                    share_amount: 3 * faults + 1,
                    prime: nonce_prime.clone(),
                };
                let nonce = rand::thread_rng().gen_biguint_range(&low_r, &nonce_prime);
                let nonce_shares = nonce_ss.split(nonce);

                let h_coeffs_as_val: Vec<Val> = two_field_shares.degree_test_coeffs.iter()
                    .map(|c| Self::pad_shares(c.clone()))
                    .collect();
                degree_test_batch.push(h_coeffs_as_val);

                for node_idx in 0..self.num_nodes {
                    let g_share = &two_field_shares.mask_shares[node_idx].1;
                    mask_shares_per_node[node_idx].push(Self::pad_shares(g_share.clone()));

                    let f_large = &two_field_shares.f_large_shares[node_idx].1;
                    f_large_per_node[node_idx].push(Self::pad_shares(f_large.clone()));
                }

                // Use f(i) (small field) as the secret shares for reconstruction
                for (share, nonce_share) in two_field_shares.secret_shares.into_iter().zip(nonce_shares.into_iter()) {
                    share_vec.push(Self::pad_shares(share.1));
                    nonce_share_vec.push(Self::pad_shares(nonce_share.1));
                }
            }

            // Compute hash commitments: C_{k,i} = H(share_{k,i}, nonce_{k,i})
            let commitments = self.hash_context.hash_batch(share_vec.clone(), nonce_share_vec.clone());
            let triplets: Vec<(Val, Val, Hash)> = share_vec
                .into_iter()
                .zip(nonce_share_vec.into_iter())
                .zip(commitments.into_iter())
                .map(|((share, nonce), comm)| (share, nonce, comm))
                .collect();

            assert_eq!(
                triplets.len(),
                batch_size * self.num_nodes,
                "two-field packing mismatch: got {} triplets for batch_size={} num_nodes={}",
                triplets.len(),
                batch_size,
                self.num_nodes
            );

            // Group by coin using exact chunking; this avoids the old "forgot to push the last
            // secret" bug from the manual secret_num state machine.
            let share_comm_hash: Vec<Vec<(Val, Val, Hash)>> = triplets
                .chunks(self.num_nodes)
                .map(|chunk| chunk.iter().cloned().collect())
                .collect();

            assert_eq!(
                share_comm_hash.len(),
                batch_size,
                "expected {} per-coin groups, got {}",
                batch_size,
                share_comm_hash.len()
            );

            let hashes_vec: Vec<Vec<Hash>> = share_comm_hash
                .iter()
                .map(|secret_chunk| secret_chunk.iter().map(|(_, _, h)| *h).collect())
                .collect();

            let mt_vec = MerkleTree::build_trees(hashes_vec, &self.hash_context);

            let mut vec_msgs_to_be_sent: Vec<(Replica, BatchWSSMsg)> = (0..self.num_nodes)
                .map(|i| (i + 1, BatchWSSMsg::new(self.myid, Vec::new(), Vec::new(), Vec::new())))
                .collect();

            let mut roots_vec: Vec<Hash> = Vec::with_capacity(batch_size);
            for (secret_chunk, mt) in share_comm_hash.into_iter().zip(mt_vec.into_iter()) {
                for (i, (share, nonce, _comm)) in secret_chunk.into_iter().enumerate() {
                    vec_msgs_to_be_sent[i].1.secrets.push(share);
                    vec_msgs_to_be_sent[i].1.nonces.push(nonce);
                    vec_msgs_to_be_sent[i].1.mps.push(mt.gen_proof(i));
                }
                roots_vec.push(mt.root());
            }

            assert_eq!(
                roots_vec.len(),
                batch_size,
                "expected {} Merkle roots, got {}",
                batch_size,
                roots_vec.len()
            );
            assert_eq!(
                degree_test_batch.len(),
                batch_size,
                "expected {} degree-test entries, got {}",
                batch_size,
                degree_test_batch.len()
            );

            for (idx, (rep, batchwss)) in vec_msgs_to_be_sent.into_iter().enumerate() {
                let beacon_msg = BeaconMsg::new_two_field(
                    self.myid,
                    new_round,
                    batchwss,
                    roots_vec.clone(),
                    vec_round_msgs.clone(),
                    degree_test_batch.clone(),
                    mask_shares_per_node[idx].clone(),
                    f_large_per_node[idx].clone(),
                );
                if rep == 1 {
                    rbc_vec = beacon_msg.clone().serialize_ctrbc();
                }
                beacon_msgs.push((rep, beacon_msg));
            }
        }
        else{
            for i in 0..self.num_nodes{
                let beacon_msg = BeaconMsg::new_with_appx(self.myid, new_round, vec_round_msgs.clone());
                if i == 0{
                    rbc_vec = beacon_msg.clone().serialize_ctrbc();
                }
                beacon_msgs.push((i + 1, beacon_msg));
            }
        }

        // Use SHA256 for RBC shard hashing
        let shards = get_shards(rbc_vec, self.num_faults);
        let hashes_rbc:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
        let merkle_tree = MerkleTree::new(hashes_rbc, &self.hash_context);

        for (rep, beacon_msg) in beacon_msgs.into_iter() {
            let replica = rep - 1;
            let sec_key = self.sec_key_map.get(&replica).unwrap().clone();
            let ctrbc_msg = CTRBCMsg::new(
                shards[replica].clone(),
                merkle_tree.gen_proof(replica),
                new_round,
                self.myid
            );
            if replica != self.myid{
                let beacon_init = CoinMsg::CTRBCInit(beacon_msg, ctrbc_msg);
                let wrapper_msg = WrapperMsg::new(beacon_init, self.myid, &sec_key, new_round);
                self.send(replica, wrapper_msg).await;
            }
            else {
                self.process_rbcinit(beacon_msg, ctrbc_msg).await;
            }
        }

        if new_round > 0{
            self.increment_round(round).await;
        }
        self.add_benchmark(String::from("start_batchwss"), now.elapsed().unwrap().as_nanos());
    }

    /// Phase 4B: Get theta (previous round's beacon output) for degree testing.
    /// Returns 0 if no previous beacon is available.
    pub(crate) fn get_previous_theta(&self, round: Round) -> BigUint {
        if round == 0 {
            BigUint::from(0u32)
        } else {
            let round_bytes = round.to_be_bytes();
            let hash = crypto::hash::do_hash(&round_bytes);
            BigUint::from_bytes_be(&hash) % &self.secret_domain
        }
    }

    pub fn pad_shares(inp:BigUint)->[u8;32]{
        let mut byte_arr = inp.to_bytes_be();
        if byte_arr.len() > 32{
            panic!("All inputs must be within 32 bytes");
        }
        else {
            let mut vec_zeros = vec![0u8;32-byte_arr.len()];
            vec_zeros.append(&mut byte_arr);
            vec_zeros.try_into().unwrap_or_else(
                |v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", 32, v.len())
            )
        }
    }
}