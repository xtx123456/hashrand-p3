use std::{collections::{HashMap, HashSet}};

use crypto::{hash::{Hash, do_hash}, aes_hash::{Proof, HashState, MerkleTree}};
use num_bigint::{BigUint};
use types::{Replica, appxcon::{ reconstruct_and_return, get_shards}, beacon::{WSSMsg, CTRBCMsg, Val, BatchWSSReconMsg, MulticastRecoveredSharesMsg}, beacon::{BeaconMsg, BatchWSSMsg, Round}};

use crate::node::shamir::two_field::BatchExtractor;

/// Phase 3: Blame evidence for post-hoc accountability.
/// When a dealer's Merkle proof or commitment is inconsistent,
/// we record the dealer ID and the evidence (mismatched root, proof, etc.).
#[derive(Debug, Clone)]
pub struct BlameEvidence {
    pub dealer: Replica,
    pub round: Round,
    pub reason: BlameReason,
}

#[derive(Debug, Clone)]
pub enum BlameReason {
    /// RBC shard Merkle proof invalid
    InvalidRBCShardProof,
    /// WSS batch Merkle proof invalid
    InvalidWSSBatchProof,
    /// Commitment does not match share+nonce during reconstruction
    CommitmentMismatch { coin_num: usize, expected_root: Hash, got_item: Hash },
    /// Merkle proof root mismatch during reconstruction verification
    MerkleRootMismatch { coin_num: usize, expected_root: Hash, got_root: Hash },
}

use crate::node::{ShamirSecretSharing, appxcon::RoundState};

/**
 * This file contains the CTRBCState object responsible for keeping track of all messages and state in an n-parallel RBC.
 * We use Cachin-Tessaro's Reliable Broadcast protocol for broadcasting the vector of Merkle roots.  
 * 
 * TODO: Separate this monolith into separate modules for ease of maintenance
 * */ 
#[derive(Debug,Clone)]
pub struct CTRBCState{
    /// BeaconMsg contains the secret shares, CTRBCMsg contains its corresponding broadcasted root commitments
    pub msgs: HashMap<Replica,(BeaconMsg,CTRBCMsg),nohash_hasher::BuildNoHashHasher<Replica>>,
    /// Map of secret shares sent by a node
    pub node_secrets: HashMap<Replica,BatchWSSMsg,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// ECHO messages received in an RBC instantiated by the first key node and an ECHO sent by the second key node
    pub echos: HashMap<Replica,HashMap<Replica,(Vec<u8>,Proof)>,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// READY messages received in an RBC instantiated by the first key node and an ECHO sent by the second key node
    pub readys: HashMap<Replica,HashMap<Replica,(Vec<u8>,Proof)>,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// If READYs have been sent already?
    pub ready_sent:HashSet<Replica>,
    /// Messages for CT-RBC Erasure reconstruction
    pub recon_msgs:HashMap<Replica,HashMap<Replica,Vec<u8>>,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// Root Commitment vector for a BAwVSS instance instantiated by node i
    pub comm_vectors:HashMap<Replica,Vec<Hash>,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// List of all secrets whose BAwVSS instances have been terminated
    pub terminated_secrets: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// Secret shares for secret reconstruction. Each node shares a secret for which multiple nodes can sent secret shares
    pub secret_shares: HashMap<usize,HashMap<Replica,HashMap<Replica,BigUint>>,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// Reconstructed secrets
    pub reconstructed_secrets:HashMap<Replica,HashMap<Replica,BigUint,nohash_hasher::BuildNoHashHasher<Replica>>,nohash_hasher::BuildNoHashHasher<Replica>>,
    // Gather protocol related state context
    pub witness1: HashMap<Replica,Vec<Replica>,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// Witness2 messages
    pub witness2: HashMap<Replica,Vec<Replica>,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// States values in each round of Binary Approximate Agreement
    pub appxcon_allround_vals: HashMap<Replica,HashMap<Round,Vec<(Replica,BigUint)>>>,
    /// Final termination value of Binary Approximate Agreement
    pub appxcon_vals: HashMap<Replica,Vec<BigUint>>,
    /// AnyTrust Sample for this n-parallel BAwVSS instantiation 
    pub committee:Vec<Replica>,
    /// Which round of Approximate Agreement is this current BAwVSS instance undergoing?
    pub appxcon_round: Round,
    /// Witness has been sent in Gather?
    pub send_w1: bool,
    /// Witness2 has been sent in Gather?
    pub send_w2:bool,
    /// Did the Gather protocol terminate?
    pub started_baa:bool,
    /// Has the AnyTrust sampling been conducted already?
    pub committee_elected:bool,
    /// List of Accepted witnesses
    pub accepted_witnesses1: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub accepted_witnesses2: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub secret_domain: BigUint,
    /// Termination values for each Binary AA instance
    pub appx_con_term_vals: HashMap<Replica,BigUint,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// The contribution of each node to the final beacon output. Check out our weighted averaging approach in the paper
    pub contribution_map: HashMap<Replica,HashMap<Replica,BigUint,nohash_hasher::BuildNoHashHasher<Replica>>>,
    /// List of all reconstructed secrets
    pub recon_secrets:HashSet<Replica>,
    /// Phase 4B (Two-Field): Degree test polynomial h(x) coefficients per dealer.
    /// degree_test_coeffs[dealer][secret_idx] = [h_0, ..., h_{t-1}]
    pub degree_test_coeffs: HashMap<Replica,Vec<Vec<Val>>,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// Per-dealer mask shares g(i) received by this node.
    pub mask_shares: HashMap<Replica,Vec<Val>,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// Per-dealer f(i) values evaluated in the large field and received by this node.
    pub f_large_shares: HashMap<Replica,Vec<Val>,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// Phase 4B: Cached BatchExtractor for the immutable ACS-decided evaluation points.
    pub batch_extractor: Option<BatchExtractor>,
    /// Immutable ACS decided set used as the reconstruction basis.
    pub acs_decided_set: Option<Vec<Replica>>,
    /// Dealers blamed during post-ACS accountability. This is evidence only and never
    /// feeds back into reconstruction control flow.
    pub malicious_dealers: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    /// Post-ACS accountability evidence log.
    pub blame_log: Vec<BlameEvidence>,
    /// Full-share multicast packets received after batch recovery.
    pub post_complaint_packets: HashMap<Replica, MulticastRecoveredSharesMsg, nohash_hasher::BuildNoHashHasher<Replica>>,
    /// Have we already multicast our recovered-share disclosure for this round?
    pub recovered_shares_multicast_sent: bool,
    /// Has the ACS-decided batch already been recovered?
    pub batch_reconstruction_complete: bool,
    /// Has post-complaint processing completed?
    pub post_complaint_complete: bool,
    /// Beacon outputs computed by batch recovery, held back until post-complaint finishes.
    pub pending_beacon_outputs: HashMap<usize,Vec<u8>,nohash_hasher::BuildNoHashHasher<usize>>,
    /// Code for binary approximate agreement. Remember, Binary Approximate Agreement must run for self.rounds_aa number of rounds. Accordingly, those many round states need to be created and managed.
    pub round_state: HashMap<Round,RoundState>,
    pub cleared:bool,
}

impl CTRBCState{
    pub fn new(sec_domain:BigUint,num_nodes:usize)-> CTRBCState{
        let mut master_committee = Vec::new();
        for i in 0..num_nodes{
            master_committee.push(i);
        }
        CTRBCState{
            msgs: HashMap::default(),
            node_secrets: HashMap::default(),
            echos: HashMap::default(),
            readys:HashMap::default(),
            ready_sent:HashSet::default(),
            recon_msgs:HashMap::default(),
            comm_vectors:HashMap::default(),
            secret_shares:HashMap::default(),
            reconstructed_secrets:HashMap::default(),
            witness1:HashMap::default(),
            witness2: HashMap::default(),
            appxcon_allround_vals: HashMap::default(),
            committee:master_committee,
            appxcon_vals: HashMap::default(),
            appxcon_round: 0,
            send_w1:false,
            send_w2:false,
            started_baa:false,
            committee_elected:false,
            terminated_secrets:HashSet::default(),
            accepted_witnesses1:HashSet::default(),
            accepted_witnesses2:HashSet::default(),
            secret_domain:sec_domain,

            appx_con_term_vals:HashMap::default(),
            contribution_map: HashMap::default(),
            recon_secrets: HashSet::default(),
            degree_test_coeffs: HashMap::default(),
            mask_shares: HashMap::default(),
            f_large_shares: HashMap::default(),
            batch_extractor: None,
            acs_decided_set: None,
            malicious_dealers: HashSet::default(),
            blame_log: Vec::new(),
            post_complaint_packets: HashMap::default(),
            recovered_shares_multicast_sent: false,
            batch_reconstruction_complete: false,
            post_complaint_complete: false,
            pending_beacon_outputs: HashMap::default(),
            round_state:HashMap::default(),
            cleared:false,
        }
    }

    pub fn add_message(&mut self, beacon_msg:BeaconMsg,ctr:CTRBCMsg)->(){
        let sec_origin = beacon_msg.origin;
        // Message Validation happens in the method calling this method. 
        self.msgs.insert(sec_origin, (beacon_msg,ctr));
    }

    pub fn set_committee(&mut self,committee:Vec<Replica>){
        self.committee = committee.clone();
    }

    pub fn add_echo(&mut self, sec_origin: Replica, echo_origin: Replica, ctr:&CTRBCMsg){
        match self.echos.get_mut(&sec_origin)  {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(echo_origin,(ctr.shard.clone(),ctr.mp.clone()));
                self.echos.insert(sec_origin, hash_map);
            },
            Some(x) => {
                x.insert(echo_origin,(ctr.shard.clone(),ctr.mp.clone()));
            },
        }
    }

    pub fn add_ready(&mut self, sec_origin: Replica, ready_origin: Replica, ctr:&CTRBCMsg){
        match self.readys.get_mut(&sec_origin)  {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(ready_origin,(ctr.shard.clone(),ctr.mp.clone()));
                self.readys.insert(sec_origin, hash_map);
            },
            Some(x) => {
                x.insert(ready_origin,(ctr.shard.clone(),ctr.mp.clone()));
            },
        }
    }

    pub fn add_recon(&mut self, sec_origin: Replica, recon_origin: Replica, ctr:&CTRBCMsg){
        match self.recon_msgs.get_mut(&sec_origin) {
            None => {
                let mut reconset = HashMap::default();
                reconset.insert(recon_origin,ctr.shard.clone());
                self.recon_msgs.insert(sec_origin, reconset);
            },
            Some(x) => {
                x.insert(recon_origin,ctr.shard.clone());
            }
        }
    }
    /**
     * This function prepares to start Gather and Approximate agreement after terminating CTRBC protocol for a message.
     */
    pub fn transform(&mut self, terminated_index:Replica)->BeaconMsg{
        let beacon_msg = self.msgs.get(&terminated_index).unwrap().0.clone();
        if beacon_msg.appx_con.is_some(){
            let appxcon_msgs: Vec<(u32, Vec<(usize, [u8; 32])>)> = beacon_msg.appx_con.clone().unwrap();
            let appx_con_vals:Vec<(u32,Vec<(Replica,BigUint)>)> = appxcon_msgs.into_iter().map(|(x,y)|{
                let mut vec_values = Vec::new();
                for (rep,value) in y.into_iter(){
                    vec_values.push((rep,BigUint::from_bytes_be(&value)));
                }
                return (x,vec_values);
            }).collect();
            let mut hashmap_vals = HashMap::default();
            for (round,vals) in appx_con_vals.into_iter(){
                hashmap_vals.insert(round, vals);
            }
            self.appxcon_allround_vals.insert(beacon_msg.origin.clone(), hashmap_vals);
        }
        // Phase 4B: Store degree-test data before consuming the message.
        if let Some(ref dtc) = beacon_msg.degree_test_coeffs {
            self.degree_test_coeffs.insert(terminated_index, dtc.clone());
            log::info!("[TWO-FIELD] Stored degree_test_coeffs for dealer {} ({} secrets)",
                terminated_index, dtc.len());
        }
        if let Some(ref mask) = beacon_msg.mask_shares {
            self.mask_shares.insert(terminated_index, mask.clone());
        }
        if let Some(ref f_large) = beacon_msg.f_large_shares {
            self.f_large_shares.insert(terminated_index, f_large.clone());
        }
        if beacon_msg.wss.is_some(){
            let batch_wssmsg = beacon_msg.wss.unwrap().clone();
            self.node_secrets.insert(beacon_msg.origin.clone(), batch_wssmsg.clone());
            self.comm_vectors.insert(terminated_index, beacon_msg.root_vec.unwrap());
        }
        self.terminated_secrets.insert(terminated_index);
        // clean up for memory efficiency
        let beacon_msg = self.msgs.get(&terminated_index).unwrap().0.clone();
        self.msgs.remove(&terminated_index);
        self.echos.remove(&terminated_index);
        self.readys.remove(&terminated_index);
        self.recon_msgs.remove(&terminated_index);
        return beacon_msg;
    }

    pub fn add_secret_share(&mut self, coin_number:usize, secret_id:usize,share_provider:usize, share:Val){
        let share_bg = BigUint::from_bytes_be(&share);
        if self.secret_shares.contains_key(&coin_number){
            let coin_shares = self.secret_shares.get_mut(&coin_number).unwrap();
            if coin_shares.contains_key(&secret_id){
                coin_shares.get_mut(&secret_id).unwrap().insert(share_provider, share_bg);
            }
            else{
                let mut share_map = HashMap::default();
                share_map.insert(share_provider, share_bg);
                coin_shares.insert(secret_id, share_map);
            }
            //self.secret_shares.get_mut(&coin_number).unwrap().insert(share_provider, (coin_number,wss_msg.clone()));
        }
        else{
            let mut coin_shares = HashMap::default();
            let mut share_map= HashMap::default();
            share_map.insert(share_provider, share_bg);
            coin_shares.insert(secret_id, share_map);
            self.secret_shares.insert(coin_number, coin_shares);
        }
    }
    /**
     * Check the RBC's validity after you receive n-f ECHOs
     */
    // Returns the root of all individual polynomial merkle root vectors and the polynomial vector itself
    pub fn echo_check(&mut self, sec_origin: Replica, num_nodes: usize,num_faults:usize, batch_size:usize,hf:&HashState)-> Option<(Hash,Vec<Hash>)>{
        let echos = self.echos.get_mut(&sec_origin).unwrap();
        // 2. Check if echos reached the threshold, init already received, and round number is matching
        log::debug!("WSS ECHO check: echos.len {}, contains key: {}"
        ,echos.len(),self.msgs.contains_key(&sec_origin));
        
        if echos.len() == num_nodes-num_faults && 
            self.msgs.contains_key(&sec_origin) && !self.ready_sent.contains(&sec_origin){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies ECHO verification needed
            // Send your own shard in the echo phase to every other node. 
            let mut echo_map = HashMap::default();
            self.ready_sent.insert(sec_origin);
            for (rep,(shard,_mp)) in echos.clone().into_iter(){
                echo_map.insert(rep, shard);
            }
            // This function uses Erasure codes to reconstruct the root vector and checks if the broadcaster 
            // cheated or not. Only then it will echo the message. 
            return self.verify_reconstructed_root(sec_origin, num_nodes, num_faults, batch_size, echo_map,hf);   
        }
        None
    }
    /**
     * Check the RBC's validity after you receive f+1 or n-f readys
     */
    pub fn ready_check(&mut self, sec_origin: Replica, num_nodes:usize,num_faults:usize, batch_size:usize,hf:&HashState)-> (usize, Option<(Hash,Vec<Hash>)>){
        let readys = self.readys.get_mut(&sec_origin).unwrap();
        // 2. Check if readys reached the threshold, init already received, and round number is matching
        log::debug!("READY check: readys.len {}, contains key: {}"
        ,readys.len(),self.msgs.contains_key(&sec_origin));
        let mut ready_map = HashMap::default();
        for (rep,(shard,_mp)) in readys.clone().into_iter(){
            ready_map.insert(rep, shard);
        }
        if readys.len() == num_faults+1 && self.msgs.contains_key(&sec_origin) && !self.ready_sent.contains(&sec_origin){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies verification needed
            self.ready_sent.insert(sec_origin);
            return (num_faults+1,self.verify_reconstructed_root(sec_origin, num_nodes, num_faults, batch_size, ready_map,hf));
        }
        else if readys.len() == num_nodes-num_faults &&
            self.msgs.contains_key(&sec_origin){
            // Terminate RBC, RAccept the value
            // Add value to value list, add rbc to rbc list
            return (num_nodes-num_faults,self.verify_reconstructed_root(sec_origin, num_nodes, num_faults, batch_size, ready_map,hf));
        }
        (0,None)
    }
    /**
     * CTRBC Reconstruction phase. Reconstruct message using Erasure codes and veriy if the Root of Merkle tree is correctly formed.
     */
    pub fn verify_reconstruct_rbc(&mut self, sec_origin:Replica, num_nodes:usize, num_faults:usize, batch_size:usize,hf:&HashState) -> Option<(Hash,Vec<Hash>)>{
        let ready_check = self.readys.get(&sec_origin).unwrap().len() >= (num_nodes-num_faults);
        let vec_fmap = self.recon_msgs.get(&sec_origin).unwrap().clone();
        if vec_fmap.len()==num_nodes-num_faults && ready_check{
            // Reconstruct here
            let res_root = self.verify_reconstructed_root(sec_origin, num_nodes, num_faults, batch_size, vec_fmap,hf);
            match res_root.clone() {
                None=> {
                    log::error!("Error resulted in constructing erasure-coded data");
                    return None;
                }
                Some(_vec)=>{
                    log::info!("Successfully reconstructed message for Batch WSS, checking validity of root for secret {}",sec_origin);
                    self.terminated_secrets.insert(sec_origin);
                    // Initiate next phase of the protocol here
                    return res_root;
                }
            }
        }
        None
    }
    /**
     * Phase 4B: Use BatchExtractor for O(n) recovery instead of per-secret Lagrange interpolation.
     * The BatchExtractor's Lagrange coefficients are precomputed once when ACS decides,
     * then reused for all coin_number reconstructions in this round.
     */
    pub async fn reconstruct_secret(&mut self,coin_number:usize, wss_msg: WSSMsg, _num_nodes: usize, num_faults:usize)-> Option<BigUint>{
        let sec_origin = wss_msg.origin;
        if coin_number == 0{
            log::info!("Coin number: {}, secret shares: {:?}",0,self.secret_shares.get(&0).unwrap());
        }
        let sec_map = self.secret_shares.get_mut(&coin_number).unwrap().get_mut(&wss_msg.origin).unwrap();
        if coin_number == 0{
            log::info!("Sec map: {:?}",sec_map.clone());
        }
        let already_constructed = self.reconstructed_secrets.contains_key(&coin_number) && self.reconstructed_secrets.get(&coin_number).unwrap().contains_key(&sec_origin);
        if sec_map.len() >= num_faults+1 && !already_constructed{
            log::info!("Received t+1 shares for secret instantiated by {}, reconstructing secret for coin_num {}",wss_msg.origin,coin_number);
            
            // Phase 4B: Use BatchExtractor if available, otherwise fall back to direct Lagrange
            let secret = if let Some(ref extractor) = self.batch_extractor {
                // Use precomputed Lagrange coefficients from BatchExtractor
                // Build a single-coin shares_matrix for batch_recover
                let mut single_coin_matrix: HashMap<usize, HashMap<usize, BigUint>> = HashMap::new();
                let mut dealer_shares: HashMap<usize, BigUint> = HashMap::new();
                for (&rep, share) in sec_map.iter() {
                    // rep is 0-indexed, evaluation point is rep+1
                    dealer_shares.insert(rep + 1, share.clone());
                }
                single_coin_matrix.insert(0, dealer_shares);
                let recovered = extractor.batch_recover(&single_coin_matrix);
                if let Some((_, sec)) = recovered.into_iter().next() {
                    sec
                } else {
                    // Fallback: direct Lagrange interpolation
                    let mut secret_shares: Vec<(Replica, BigUint)> =
                        sec_map.clone().into_iter()
                        .map(|(rep, val)| (rep + 1, val))
                        .collect();
                    secret_shares.truncate(num_faults + 1);
                    let shamir_ss = ShamirSecretSharing {
                        threshold: num_faults + 1,
                        share_amount: 3 * num_faults + 1,
                        prime: self.secret_domain.clone()
                    };
                    shamir_ss.recover(&secret_shares)
                }
            } else {
                // No BatchExtractor yet — use traditional Lagrange interpolation
                let mut secret_shares: Vec<(Replica, BigUint)> =
                    sec_map.clone().into_iter()
                    .map(|(rep, val)| (rep + 1, val))
                    .collect();
                secret_shares.truncate(num_faults + 1);
                let shamir_ss = ShamirSecretSharing {
                    threshold: num_faults + 1,
                    share_amount: 3 * num_faults + 1,
                    prime: self.secret_domain.clone()
                };
                shamir_ss.recover(&secret_shares)
            };

            if !self.reconstructed_secrets.contains_key(&coin_number){
                let secret_share_map:HashMap<Replica,BigUint,nohash_hasher::BuildNoHashHasher<Replica>> = HashMap::default();
                self.reconstructed_secrets.insert(coin_number, secret_share_map);
            }
            let secret_share_map = self.reconstructed_secrets.get_mut(&coin_number).unwrap();
            secret_share_map.insert(sec_origin, secret.clone());
            self.sync_secret_maps().await;
            return Some(secret);
        }
        None
    }

    // Sync secrets and multiply them by the agreed-upon weight after terminating Approximate Agreement. 
    pub async fn sync_secret_maps(&mut self){
        //self.reconstructed_secrets.insert(sec_origin, secret.clone());
        for (coin_num,recon_sec) in self.reconstructed_secrets.clone().into_iter(){
            for (rep,sec) in recon_sec.into_iter(){
                if self.appx_con_term_vals.contains_key(&rep){
                    let appxcox_var = self.appx_con_term_vals.get_mut(&rep).unwrap();
                    if !self.contribution_map.contains_key(&coin_num){
                        let contribution_map_coin:HashMap<Replica, BigUint, nohash_hasher::BuildNoHashHasher<Replica>> = HashMap::default();
                        self.contribution_map.insert(coin_num, contribution_map_coin);
                    }
                    let sec_contrib_map = self.contribution_map.get_mut(&coin_num).unwrap();
                    sec_contrib_map.insert(rep, appxcox_var.clone()*sec.clone());
                }
            }
        }
    }
    /**
     * Return the set of secret shares for a given beacon index. 
     */
    /// Phase 3: Record a dealer as malicious with blame evidence.
    pub fn blame_dealer(&mut self, dealer: Replica, round: Round, reason: BlameReason) {
        let newly_flagged = self.malicious_dealers.insert(dealer);
        if newly_flagged || !self.blame_log.iter().any(|ev| ev.dealer == dealer && ev.round == round) {
            log::error!(
                "[POST-BLAME] Dealer {} flagged in round {}: {:?}",
                dealer, round, reason
            );
            self.blame_log.push(BlameEvidence { dealer, round, reason });
        }
    }

    /// Phase 3: Verify a share+nonce against the committed Merkle tree root.
    /// Returns true if the commitment matches the stored root vector for this dealer.
    pub fn verify_share_commitment(
        &self,
        dealer: Replica,
        coin_number: usize,
        share: &Val,
        nonce: &Val,
        mp: &Proof,
        hf: &HashState,
    ) -> bool {
        // 1. Check that the Merkle proof itself is valid
        if !mp.validate(hf) {
            log::warn!("[BLAME-CHECK] Merkle proof validation failed for dealer {} coin {}", dealer, coin_number);
            return false;
        }
        // 2. Verify commitment: H(share, nonce) == proof leaf
        let commitment = hf
            .hash_batch(vec![*share], vec![*nonce])
            .into_iter()
            .next()
            .expect("hash_batch returned no item");
        if commitment != mp.item() {
            log::warn!("[BLAME-CHECK] Commitment mismatch for dealer {} coin {}", dealer, coin_number);
            return false;
        }
        // 3. Verify Merkle root matches the committed root vector
        if let Some(root_vec) = self.comm_vectors.get(&dealer) {
            if coin_number < root_vec.len() {
                if mp.root() != root_vec[coin_number] {
                    log::warn!(
                        "[BLAME-CHECK] Root mismatch for dealer {} coin {}: proof root {:?} != committed {:?}",
                        dealer, coin_number, mp.root(), root_vec[coin_number]
                    );
                    return false;
                }
            }
        }
        true
    }


    pub fn secret_shares(&self, coin_number:usize)-> BatchWSSReconMsg{
        let mut shares_vector = Vec::new();
        let mut replicas = Vec::new();
        let mut nonces = Vec::new();
        let mut merkle_proofs = Vec::new();
        let mut mask_shares = Vec::new();
        let mut f_large_shares = Vec::new();

        let decided = self.acs_decided_set.clone().unwrap_or_default();
        for rep in decided.into_iter() {
            if !self.terminated_secrets.contains(&rep) {
                continue;
            }
            let Some(batch_wss) = self.node_secrets.get(&rep) else { continue; };
            let Some(secret) = batch_wss.secrets.get(coin_number) else { continue; };
            let Some(nonce) = batch_wss.nonces.get(coin_number) else { continue; };
            let Some(merkle_proof) = batch_wss.mps.get(coin_number) else { continue; };
            let Some(mask) = self.mask_shares.get(&rep).and_then(|v| v.get(coin_number)) else { continue; };
            let Some(f_large) = self.f_large_shares.get(&rep).and_then(|v| v.get(coin_number)) else { continue; };

            shares_vector.push(*secret);
            nonces.push(*nonce);
            merkle_proofs.push(merkle_proof.clone());
            mask_shares.push(*mask);
            f_large_shares.push(*f_large);
            replicas.push(rep);
        }
        BatchWSSReconMsg {
            origin: 0,
            secrets: shares_vector,
            nonces,
            origins: replicas,
            mps: merkle_proofs,
            mask_shares,
            f_large_shares,
            empty: false,
        }
    }

    fn verify_reconstructed_root(&mut self, sec_origin: Replica, num_nodes: usize,num_faults:usize,_batch_size:usize, shard_map: HashMap<usize,Vec<u8>>,hf:&HashState)-> Option<(Hash,Vec<Hash>)>{
        let merkle_root = self.msgs.get(&sec_origin).unwrap().1.mp.root().clone();
        let res = 
            reconstruct_and_return(&shard_map, num_nodes, num_faults);
        match res {
            Err(error)=> {
                log::error!("Shard reconstruction failed because of the following reason {:?}",error);
                return None;
            },
            Ok(vec_x)=> {
                // Further verify the merkle root generated by these hashes
                // let mut vec_xx = vec_x;
                // vec_xx.truncate(batch_size*32);
                // //log::info!("Vec_x: {:?} {}",vec_xx.clone(),vec_xx.len());
                // let split_vec:Vec<Hash> = 
                //     vec_xx.chunks(32).into_iter()
                //     .map(|x| {
                //         x.try_into().unwrap()
                //     })
                //     .collect();
                // let merkle_tree_master:MerkleTree<Hash,HashingAlg> = MerkleTree::from_iter(split_vec.clone().into_iter());
                let shards = get_shards(BeaconMsg::deserialize(&vec_x.as_slice()).serialize_ctrbc(),num_faults);
                let hashes_rbc:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
                let merkle_tree = MerkleTree::new(hashes_rbc.clone(),hf);
                if merkle_tree.root() == merkle_root{
                    return Some((merkle_root.clone(),hashes_rbc));
                }
                else {
                    log::error!("Reconstructing root hash polynomial failed, with params {:?} {:?} {:?}", hashes_rbc.clone(),merkle_tree.root(),merkle_root);
                    return None;
                }
            }
        }
    }
    /**
     * Check if the beacon can be reconstructed.
     * 1) All secrets for which Binary AA terminated with a non-zero weight must be reconstructed.
     * 2) All Binary AA instances should have terminated. s
     */
    pub async fn coin_check(&mut self, round: Round,coin_number: usize, num_nodes: usize)->Option<Vec<u8>>{
        log::info!("Coin check for round {} coin {}, keys appxcon: {:?}, contrib_map: {:?}",round,coin_number,self.appx_con_term_vals,self.contribution_map);
        // Each key,value pair in the contribution_map contains a beacon_number, and a list of contributions of each node in the system. 
        if self.contribution_map.contains_key(&coin_number) && self.appx_con_term_vals.len() == self.contribution_map.get(&coin_number).unwrap().len(){
            let mut sum_vars = BigUint::from(0u32);
            log::info!("Reconstruction for round {} and coin {}",round,coin_number);
            // Contribution_map stores each node's secret's contribution to the beacon. Check our paper for details about secret aggregation and beacon generation
            for (_rep,sec_contrib) in self.contribution_map.get(&coin_number).unwrap().clone().into_iter(){
                sum_vars = sum_vars + sec_contrib.clone();
                log::info!("Node's secret contribution: {}, node {}",sec_contrib.to_string(),_rep);
            }
            let rand_fin = sum_vars.clone() % self.secret_domain.clone();
            let _mod_number = self.secret_domain.clone()/(num_nodes);
            let _leader_elected = rand_fin.clone()/_mod_number;
            // Mark this secret as used, use the next secret from this point on
            self.recon_secrets.insert(coin_number);
            self.secret_shares.remove(&coin_number);
            self.reconstructed_secrets.remove(&coin_number);
            self.contribution_map.remove(&coin_number);
            // for (_rep,(_appx_con, processed, _num)) in self.contribution_map.iter_mut(){
            //     *processed = false;
            // }
            //log::error!("Random leader election terminated random number: sec_origin {} rand_fin{} leader_elected {}, elected leader is node",sum_vars.clone(),rand_fin.clone(),leader_elected.clone());
            return Some(BigUint::to_bytes_be(&rand_fin));
        }
        return None;
    }
    /**
     * Clear state after use for memory clean up
     */
    pub(crate) fn _clear(&mut self) {
        self.msgs.clear();
        self.echos.clear();
        self.readys.clear();
        self.accepted_witnesses1.clear();
        self.accepted_witnesses2.clear();
        self.appx_con_term_vals.clear();
        self.committee.clear();
        self.committee_elected = true;
        self.secret_shares.clear();
        self.appxcon_vals.clear();
        self.appxcon_allround_vals.clear();
        self.recon_msgs.clear();
        self.comm_vectors.clear();
        self.degree_test_coeffs.clear();
        self.mask_shares.clear();
        self.f_large_shares.clear();
        self.batch_extractor = None;
        self.acs_decided_set = None;
        self.contribution_map.clear();
        self.round_state.clear();
        self.witness1.clear();
        self.witness2.clear();
        self.terminated_secrets.clear();
        self.post_complaint_packets.clear();
        self.recovered_shares_multicast_sent = false;
        self.batch_reconstruction_complete = false;
        self.post_complaint_complete = false;
        self.pending_beacon_outputs.clear();
        self.cleared = true;
    }
}