//! Fetch and print a whoiam identity.
//!
//! cargo run -p whoiam-client --example whoiam-fetch -- \
//!   --key <bs58-or-hex pubkey> [--node ws://...] [--avatar-out avatar.png]

const DEFAULT_NODE: &str = "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut node = DEFAULT_NODE.to_string();
    let mut keystr = None;
    let mut avatar_out = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--node" => node = it.next().expect("--node wants a value").clone(),
            "--key" => keystr = Some(it.next().expect("--key wants a value").clone()),
            "--avatar-out" => avatar_out = Some(it.next().expect("--avatar-out wants a value").clone()),
            other => {
                eprintln!("unknown argument {other:?}");
                std::process::exit(2);
            }
        }
    }
    let Some(keystr) = keystr else {
        eprintln!("usage: whoiam-fetch --key <pubkey> [--node URL] [--avatar-out FILE]");
        std::process::exit(2);
    };
    let pk = match whoiam_client::parse_pubkey(&keystr) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("bad --key: {e}");
            std::process::exit(2);
        }
    };

    println!("identity  {}", whoiam_client::format_pubkey(&pk));
    println!("contract  {}", whoiam_client::contract_key(&pk).id());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match rt.block_on(whoiam_client::fetch(&node, &pk)) {
        Ok(id) => {
            match &id.profile {
                Some(p) => println!("name      {}\nbio       {}", p.name, p.bio),
                None => println!("profile   (none)"),
            }
            match &id.avatar {
                Some(bytes) => {
                    println!("avatar    {} bytes", bytes.len());
                    if let Some(path) = avatar_out {
                        std::fs::write(&path, bytes).expect("write avatar");
                        println!("          written to {path}");
                    }
                }
                None => println!("avatar    (none)"),
            }
            let extra: Vec<&String> = id
                .raw_slots
                .keys()
                .filter(|k| k.as_str() != "profile" && k.as_str() != "avatar")
                .collect();
            if !extra.is_empty() {
                println!("extra     {extra:?}");
            }
        }
        Err(e) => {
            eprintln!("fetch failed: {e}");
            std::process::exit(1);
        }
    }
}
