//! Reading a transparent output's OP_RETURN for the confirmation screen.
//!
//! A THORChain deposit carries its whole instruction in the memo: swap to what
//! and to whom, add to which pool, withdraw how much. That memo decides where
//! the money ends up, so the device shows it in words beside the raw text, and
//! never pretends to know more than the memo says (the vault address itself
//! cannot be checked here).

/// The payload of a null-data script: `OP_RETURN <one push>`, or `None` for
/// any other script or a malformed push.
pub fn null_data(script: &[u8]) -> Option<&[u8]> {
    let (&op, rest) = script.split_first()?;
    if op != 0x6a {
        return None;
    }
    let (&push, rest) = match rest.split_first() {
        None => return Some(&[]),
        Some(p) => p,
    };
    let (len, data) = match push {
        0x01..=0x4b => (push as usize, rest),
        0x4c => {
            let (&n, rest) = rest.split_first()?;
            (n as usize, rest)
        }
        _ => return None,
    };
    (data.len() == len).then_some(data)
}

/// The output label for a null-data payload:
/// `thorchain:<words>|<memo>` for an instruction this reads,
/// `memo:<text>` for other printable text, `op-return:<hex>` otherwise.
pub fn label(data: &[u8]) -> String {
    let text = core::str::from_utf8(data)
        .ok()
        .filter(|t| !t.is_empty() && t.bytes().all(|b| (0x20..0x7f).contains(&b)));
    match text {
        Some(memo) => match describe(memo) {
            Some(words) => format!("thorchain:{words}|{memo}"),
            None => format!("memo:{memo}"),
        },
        None => format!("op-return:{}", crate::hex(data)),
    }
}

/// A THORChain swap, add or withdraw memo in plain words, or `None` for
/// anything else. `|` is refused so the words and the raw memo can share one
/// label line without one masquerading as the other.
pub fn describe(memo: &str) -> Option<String> {
    if memo.contains('|') {
        return None;
    }
    let parts: Vec<&str> = memo.split(':').collect();
    let field = |i: usize| parts.get(i).copied().filter(|s| !s.is_empty());
    match parts[0].to_ascii_lowercase().as_str() {
        "=" | "s" | "swap" => {
            let asset = field(1)?;
            let dest = field(2)?;
            let limit = field(3).and_then(|l| l.split('/').next()).unwrap_or("0");
            let min = match fixed8(limit)? {
                0 => "no minimum".to_string(),
                n => format!("at least {}", units(n)),
            };
            Some(format!("swap to {asset}, {min}, paid to {dest}"))
        }
        "+" | "a" | "add" => {
            let pool = field(1)?;
            Some(match field(2) {
                Some(pair) => format!("add liquidity to the {pool} pool, paired with {pair}"),
                None => format!("add liquidity to the {pool} pool"),
            })
        }
        "-" | "wd" | "withdraw" => {
            let pool = field(1)?;
            let bps: u32 = field(2)?
                .parse()
                .ok()
                .filter(|b| (1..=10_000).contains(b))?;
            Some(format!(
                "withdraw {} of your liquidity from the {pool} pool",
                percent(bps)
            ))
        }
        _ => None,
    }
}

/// A THORChain amount: an integer in 1e8 fixed point.
fn fixed8(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn units(n: u64) -> String {
    let whole = n / 100_000_000;
    let frac = n % 100_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:08}");
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

fn percent(bps: u32) -> String {
    let (whole, frac) = (bps / 100, bps % 100);
    if frac == 0 {
        format!("{whole}%")
    } else {
        format!("{whole}.{}%", format!("{frac:02}").trim_end_matches('0'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_null_data_pushes() {
        assert_eq!(null_data(&[0x6a, 0x02, b'h', b'i']), Some(&b"hi"[..]));
        let long = [b'x'; 80];
        let mut s = vec![0x6a, 0x4c, 80];
        s.extend_from_slice(&long);
        assert_eq!(null_data(&s), Some(&long[..]));
        assert_eq!(null_data(&[0x6a, 0x03, b'h', b'i']), None, "short push");
        assert_eq!(null_data(&[0x76, 0xa9]), None, "p2pkh is not null data");
    }

    #[test]
    fn swap_in_words() {
        assert_eq!(
            describe("=:ETH.ETH:0xabc:3100000/1/0:zafu:0").unwrap(),
            "swap to ETH.ETH, at least 0.031, paid to 0xabc"
        );
        assert_eq!(
            describe("swap:BTC.BTC:bc1q").unwrap(),
            "swap to BTC.BTC, no minimum, paid to bc1q"
        );
        assert_eq!(describe("=:ETH.ETH:0xabc:1e6"), None, "unread limit");
        assert_eq!(describe("=:ETH.ETH"), None, "no destination");
    }

    #[test]
    fn liquidity_in_words() {
        assert_eq!(
            describe("+:ZEC.ZEC").unwrap(),
            "add liquidity to the ZEC.ZEC pool"
        );
        assert_eq!(
            describe("+:ZEC.ZEC:thor1xyz").unwrap(),
            "add liquidity to the ZEC.ZEC pool, paired with thor1xyz"
        );
        assert_eq!(
            describe("-:ZEC.ZEC:5000").unwrap(),
            "withdraw 50% of your liquidity from the ZEC.ZEC pool"
        );
        assert_eq!(
            describe("-:ZEC.ZEC:125").unwrap(),
            "withdraw 1.25% of your liquidity from the ZEC.ZEC pool"
        );
        assert_eq!(describe("-:ZEC.ZEC:20000"), None);
    }

    #[test]
    fn labels() {
        assert_eq!(
            label(b"+:ZEC.ZEC"),
            "thorchain:add liquidity to the ZEC.ZEC pool|+:ZEC.ZEC"
        );
        assert_eq!(label(b"hello"), "memo:hello");
        assert_eq!(label(b"=:a:b|fake"), "memo:=:a:b|fake", "| never parsed");
        assert_eq!(
            label(b"a\nb"),
            "op-return:610a62",
            "no line breaks reach the screen"
        );
        assert_eq!(label(&[0xff]), "op-return:ff");
    }
}
