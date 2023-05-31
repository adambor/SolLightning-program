use anchor_lang::{
    prelude::*,
    solana_program::instruction::Instruction,
    solana_program::hash
};
use std::str::FromStr;

static BTC_RELAY_ID_BASE58: &str = "8DMFpUfCk8KPkNLtE25XHuCSsT1GqYxuLdGzu59QK3Rt";
static IX_PREFIX: [u8; 8] = [
    0x9d,
    0x7e,
    0xc1,
    0x86,
    0x31,
    0x33,
    0x07,
    0x58
];

pub mod txutils {
    use super::*;

    // pub struct Utxo {
    //     pub hash: [u8; 32],
    //     pub index: u32
    // }

    // pub struct TxInput {
    //     pub utxo: Utxo,
    //     pub sequence: u32
    // }

    pub struct TxOutput<'a> {
        pub value: u64,
        pub script: &'a [u8]
    }

    // pub struct BitcoinTransaction<'a> {
    //     pub version: u32,
    //     pub tx_in: Vec<TxInput>,
    //     pub tx_out: Vec<TxOutput<'a>>,
    //     pub locktime: u32,

    //     pub hash: [u8; 32],
    //     pub witness: bool
    // }

    pub struct VerifyTransaction<'a> {
        pub version: u32,
        pub out: Option<TxOutput<'a>>,
        pub locktime: u32,
        pub hash: [u8; 32],
        pub n_sequence: u32
    }

    // pub struct PartialParsedBitcoinTransaction<'a> {
    //     pub version: u32,
    //     pub data: &'a [u8],
    //     pub locktime: u32,

    //     input_count: u64,
    //     input_offset: usize,

    //     output_count: u64,
    //     output_offset: usize
    // }
    
    // impl<'a> PartialParsedBitcoinTransaction<'a> {
    //     pub fn new(data: &'a [u8]) -> Self {
    //         let version = u32::from_le_bytes(data[0..4].try_into().unwrap());

    //         let mut offset = 4;
    
    //         let input_size_resp = read_var_int(data, offset);
    
    //         offset += input_size_resp.1;
    //         let input_count = input_size_resp.0;
    //         let input_offset = offset;
    
    //         for _i in 0..(input_size_resp.0) {
    //             //let prev_tx_hash: [u8;32] = data[offset..(offset+32)].try_into().unwrap();
    //             offset += 32; //UTXO
    //             //let utxo_index: u32 = u32::from_le_bytes(data[(offset)..(offset+4)].try_into().unwrap());
    //             offset += 4; //Index
    //             let input_script_resp = read_var_int(data, offset);
    //             let total_len = (input_script_resp.0 as usize)+input_script_resp.1;
    //             offset += total_len; //Script len + script
    //             //let sequence = u32::from_le_bytes(data[(offset)..(offset+4)].try_into().unwrap());
    //             offset += 4; //Sequence
    //         }
    
    //         let output_size_resp = read_var_int(data, offset);
    
    //         offset += output_size_resp.1;
    //         let output_count = output_size_resp.0;
    //         let output_offset = offset;
    
    //         for _i in 0..(output_size_resp.0) {
    //             //let value: u64 = u64::from_le_bytes(data[(offset)..(offset+8)].try_into().unwrap());
    //             offset += 8; //Value
    //             let output_script_resp = read_var_int(data, offset);
    //             offset += output_script_resp.1; //Output script size
    //             let script_len = output_script_resp.0 as usize;
    //             //let script = &data[offset..(offset+script_len)];
    //             offset += script_len; //Script
    //         }
    
    //         let locktime = u32::from_le_bytes(data[offset..(offset+4)].try_into().unwrap());

    //         PartialParsedBitcoinTransaction::<'a> {
    //             version: version,
    //             data: data,
    //             locktime: locktime,
    //             input_count: input_count,
    //             input_offset: input_offset,
    //             output_count: output_count,
    //             output_offset: output_offset
    //         }
    //     }

    //     pub fn read_output(&self, vout: u64) -> Option<TxOutput> {
    //         if vout>=self.output_count {
    //             return None;
    //         }
    //         let mut offset = self.output_offset;
    
    //         let mut curr_vout = 0;
    //         for _i in 0..(self.output_count) {
    //             if curr_vout==vout {
    //                 let value: u64 = u64::from_le_bytes(self.data[(offset)..(offset+8)].try_into().unwrap());
    //                 offset += 8; //Value
    //                 let output_script_resp = read_var_int(self.data, offset);
    //                 offset += output_script_resp.1; //Output script size
    //                 let script_len = output_script_resp.0 as usize;
    //                 let script = &self.data[offset..(offset+script_len)];
    //                 offset += script_len; //Script
    //                 return Some(TxOutput {
    //                     value: value,
    //                     script: script
    //                 });
    //             } else {
    //                 //let value: u64 = u64::from_le_bytes(data[(offset)..(offset+8)].try_into().unwrap());
    //                 offset += 8; //Value
    //                 let output_script_resp = read_var_int(self.data, offset);
    //                 offset += output_script_resp.1; //Output script size
    //                 let script_len = output_script_resp.0 as usize;
    //                 //let script = &data[offset..(offset+script_len)];
    //                 offset += script_len; //Script
    //             }
                
    //             curr_vout += 1;
    //         }

    //         return None;
    //     }

    //     pub fn get_hash(&self) -> [u8; 32] {
    //         return hash::hash(&hash::hash(&self.data).to_bytes()).to_bytes();
    //     }

    //     pub fn get_input_nonce(&self) -> Option<u32> {
            
    //         let mut offset = self.input_offset;
    
    //         let mut unset = true;
    //         let mut n_sequence = 0;

    //         for _i in 0..(self.input_count) {
    //             //let prev_tx_hash: [u8;32] = data[offset..(offset+32)].try_into().unwrap();
    //             offset += 32; //UTXO
    //             //let utxo_index: u32 = u32::from_le_bytes(data[(offset)..(offset+4)].try_into().unwrap());
    //             offset += 4; //Index
    //             let input_script_resp = read_var_int(self.data, offset);
    //             let total_len = (input_script_resp.0 as usize)+input_script_resp.1;
    //             offset += total_len; //Script len + script
    //             let sequence = u32::from_le_bytes(self.data[(offset)..(offset+4)].try_into().unwrap());
    //             offset += 4; //Sequence
    //             if unset {
    //                 n_sequence = sequence & 0x00FFFFFF;
    //                 unset = false;
    //             }
    //             if n_sequence != (sequence & 0x00FFFFFF) || (sequence & 0xF0000000) != 0xF0000000 {
    //                 return None;
    //             }
    //         }

    //         return Some(n_sequence);

    //     }
    // }

    pub fn read_var_int(data: &[u8], start: usize) -> (u64, usize) {
        if data[start] <= 0xFC {
            return (data[start] as u64, 1);
        } else if data[start] == 0xFD {
            let val = u16::from_le_bytes(data[(start+1)..(start+3)].try_into().unwrap());
            return (val as u64, 3);
        } else if data[start] == 0xFE {
            let val = u32::from_le_bytes(data[(start+1)..(start+5)].try_into().unwrap());
            return (val as u64, 5);
        } else {
            let val = u64::from_le_bytes(data[(start+1)..(start+9)].try_into().unwrap());
            return (val, 9);
        }
    }

    // pub fn parse_transaction(data: &[u8]) -> BitcoinTransaction {
        
    //     let version = u32::from_le_bytes(data[0..4].try_into().unwrap());

    //     let flag = data[4];

    //     let mut offset = 4;
    //     if flag == 0 {
    //         offset = 6;
    //     }

    //     let input_size_resp = read_var_int(data, offset);

    //     offset += input_size_resp.1;

    //     let mut witness_input_count = 0;
    //     let mut inputs: Vec<TxInput> = Vec::new();
    //     for _i in 0..(input_size_resp.0) {
    //         let prev_tx_hash: [u8;32] = data[offset..(offset+32)].try_into().unwrap();
    //         offset += 32; //UTXO
    //         let utxo_index: u32 = u32::from_le_bytes(data[(offset)..(offset+4)].try_into().unwrap());
    //         offset += 4; //Index
    //         let input_script_resp = read_var_int(data, offset);
    //         if input_script_resp.0==0 {
    //             witness_input_count += 1;
    //         }
    //         let total_len = (input_script_resp.0 as usize)+input_script_resp.1;
    //         offset += total_len; //Script len + script
    //         let sequence = u32::from_le_bytes(data[(offset)..(offset+4)].try_into().unwrap());
    //         offset += 4; //Sequence
    //         inputs.push(TxInput {
    //             utxo: Utxo {
    //                 hash: prev_tx_hash,
    //                 index: utxo_index
    //             },
    //             sequence: sequence
    //         });
    //     }

    //     let output_size_resp = read_var_int(data, offset);

    //     offset += output_size_resp.1;

    //     let mut outputs: Vec<TxOutput> = Vec::new();
    //     for _i in 0..(output_size_resp.0) {
    //         let value: u64 = u64::from_le_bytes(data[(offset)..(offset+8)].try_into().unwrap());
    //         offset += 8; //Value
    //         let output_script_resp = read_var_int(data, offset);
    //         offset += output_script_resp.1; //Output script size
    //         let script_len = output_script_resp.0 as usize;
    //         let script = &data[offset..(offset+script_len)];
    //         offset += script_len; //Script
    //         outputs.push(TxOutput {
    //             value: value,
    //             script: script
    //         });
    //     }

    //     let witness_start_index = offset;

    //     if flag == 0 {
    //         for _i in 0..witness_input_count {
    //             let witness_size_resp = read_var_int(data, offset);
    //             offset += witness_size_resp.1;
                
    //             for _i in 0..(witness_size_resp.0) {
    //                 let witness_data_resp = read_var_int(data, offset);
    //                 offset += witness_data_resp.1; //Witness data size
    //                 offset += witness_data_resp.0 as usize; //Witness data
    //             }
    //         }
    //     }

    //     let locktime = u32::from_le_bytes(data[offset..(offset+4)].try_into().unwrap());

    //     offset += 4; //locktime

    //     let hash: [u8; 32];
    //     if flag == 0 {
    //         let mut stripped_data = Vec::with_capacity((witness_start_index-2)+4);
    //         stripped_data.extend_from_slice(&data[0..4]); //Start, skip flag
    //         stripped_data.extend_from_slice(&data[6..witness_start_index]); //All the data till witness data
    //         stripped_data.extend_from_slice(&data[(offset-4)..]); //Locktime
    
    //         hash = hash::hash(&hash::hash(&stripped_data).to_bytes()).to_bytes();
    //     } else {
    //         hash = hash::hash(&hash::hash(&data).to_bytes()).to_bytes();
    //     }

    //     return BitcoinTransaction {
    //         version: version,
    //         tx_in: inputs,
    //         tx_out: outputs,
    //         locktime: locktime,
    //         hash: hash,
    //         witness: flag==0
    //     }

    // }
    
    pub fn verify_transaction(data: &[u8], vout: u64, verify_nonce: bool) -> Option<VerifyTransaction> {
        
        //Security against spoofing bitcoin txs as merkle tree nodes
        // https://blog.rsk.co/ru/noticia/the-design-of-bitcoin-merkle-trees-reduces-the-security-of-spv-clients/
        if data.len()==64 {
            return None;
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());

        let mut offset = 4;

        let input_size_resp = read_var_int(data, offset);

        offset += input_size_resp.1;

        let mut unset = true;
        let mut n_sequence = 0;
        for _i in 0..(input_size_resp.0) {
            //let prev_tx_hash: [u8;32] = data[offset..(offset+32)].try_into().unwrap();
            offset += 32; //UTXO
            //let utxo_index: u32 = u32::from_le_bytes(data[(offset)..(offset+4)].try_into().unwrap());
            offset += 4; //Index
            let input_script_resp = read_var_int(data, offset);
            let total_len = (input_script_resp.0 as usize)+input_script_resp.1;
            offset += total_len; //Script len + script
            let sequence = u32::from_le_bytes(data[(offset)..(offset+4)].try_into().unwrap());
            offset += 4; //Sequence
            if unset {
                n_sequence = sequence & 0x00FFFFFF;
                unset = false;
            }
            if verify_nonce {
                if n_sequence != (sequence & 0x00FFFFFF) || (sequence & 0xF0000000) != 0xF0000000 {
                    return None;
                }
            }
        }

        let output_size_resp = read_var_int(data, offset);

        offset += output_size_resp.1;

        let mut out: Option<TxOutput> = None;
        for i in 0..(output_size_resp.0) {
            if i==vout {
                let value: u64 = u64::from_le_bytes(data[(offset)..(offset+8)].try_into().unwrap());
                offset += 8; //Value
                let output_script_resp = read_var_int(data, offset);
                offset += output_script_resp.1; //Output script size
                let script_len = output_script_resp.0 as usize;
                let script = &data[offset..(offset+script_len)];
                offset += script_len; //Script
                out = Some(TxOutput {
                    value: value,
                    script: script
                });
            } else {
                //let value: u64 = u64::from_le_bytes(data[(offset)..(offset+8)].try_into().unwrap());
                offset += 8; //Value
                let output_script_resp = read_var_int(data, offset);
                offset += output_script_resp.1; //Output script size
                let script_len = output_script_resp.0 as usize;
                //let script = &data[offset..(offset+script_len)];
                offset += script_len; //Script
            }
        }

        let locktime = u32::from_le_bytes(data[offset..(offset+4)].try_into().unwrap());

        let hash: [u8; 32] = hash::hash(&hash::hash(&data).to_bytes()).to_bytes();

        return Some(VerifyTransaction {
            version: version,
            out: out,
            n_sequence: n_sequence,
            locktime: locktime,
            hash: hash
        });

    }

    pub fn verify_tx_ix(ix: &Instruction, reversed_tx_id: &[u8; 32], confirmations: u32) -> Result<u8> {
        let btc_relay_id: Pubkey = Pubkey::from_str(BTC_RELAY_ID_BASE58).unwrap();

        if  ix.program_id       != btc_relay_id
        {
            return Ok(10);
        }

        return Ok(check_tx_data(&ix.data, reversed_tx_id, confirmations)); // If that's not the case, check data
    }

    /// Verify serialized BtcRelay instruction data
    pub fn check_tx_data(data: &[u8], reversed_tx_id: &[u8; 32], confirmations: u32) -> u8 {
        for i in 0..8 {
            if data[i] != IX_PREFIX[i] {
                return 1;
            }
        }
        for i in 8..40 {
            if data[i] != reversed_tx_id[i-8] {
                return 2;
            }
        }

        let _confirmations = u32::from_le_bytes(data[40..44].try_into().unwrap());
        if confirmations != _confirmations {
            return 3;
        }

        return 0;
    }
}