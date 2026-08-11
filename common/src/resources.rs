//! Well-known resource slots and their schemas. The authoritative
//! consumer-facing prose lives in docs/resources.md; these are the same
//! rules as code.

use serde::{Deserialize, Serialize};

pub const SLOT_PROFILE: &str = "profile";
pub const SLOT_AVATAR: &str = "avatar";

pub const MAX_NAME_CHARS: usize = 64;
pub const MAX_BIO_CHARS: usize = 280;
pub const MAX_AVATAR_BYTES: usize = 128 * 1024;
pub const MIN_AVATAR_DIM: u32 = 64;
pub const MAX_AVATAR_DIM: u32 = 512;

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ProfileV1 {
    pub name: String,
    pub bio: String,
}

pub fn check_profile(p: &ProfileV1) -> Result<(), String> {
    if p.name.chars().count() > MAX_NAME_CHARS {
        return Err(format!("name exceeds {MAX_NAME_CHARS} characters"));
    }
    if p.bio.chars().count() > MAX_BIO_CHARS {
        return Err(format!("bio exceeds {MAX_BIO_CHARS} characters"));
    }
    Ok(())
}

/// Container sniff only — PNG or WebP magic and the byte cap. Pixel
/// dimensions are enforced at upload time by the UI (which re-encodes);
/// consumers should still treat dimensions as advisory.
pub fn check_avatar_bytes(b: &[u8]) -> Result<(), String> {
    if b.len() > MAX_AVATAR_BYTES {
        return Err(format!("avatar exceeds {MAX_AVATAR_BYTES} bytes"));
    }
    let png = b.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    let webp = b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP";
    if !(png || webp) {
        return Err("avatar must be PNG or WebP".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_limits() {
        assert!(check_profile(&ProfileV1 {
            name: "graff".into(),
            bio: "hello".into()
        })
        .is_ok());
        assert!(check_profile(&ProfileV1 {
            name: "x".repeat(MAX_NAME_CHARS + 1),
            bio: String::new()
        })
        .is_err());
        assert!(check_profile(&ProfileV1 {
            name: String::new(),
            bio: "x".repeat(MAX_BIO_CHARS + 1)
        })
        .is_err());
    }

    #[test]
    fn avatar_magic() {
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0];
        assert!(check_avatar_bytes(&png).is_ok());
        let mut webp = b"RIFF\x00\x00\x00\x00WEBP".to_vec();
        webp.push(0);
        assert!(check_avatar_bytes(&webp).is_ok());
        assert!(check_avatar_bytes(b"GIF89a....").is_err());
        assert!(check_avatar_bytes(&vec![0x89; MAX_AVATAR_BYTES + 1]).is_err());
    }
}
