#!/usr/bin/env python3
# Cleans SingStar .pkg.drm files signed with an OpenPSID
# For more info see https://github.com/EdnessP/scee-london

# Usage:
#    -k | --drmkey <hex> Your PS3's OpenPSID that was used to download from SingStore
#       python  strip_drmkey.py  "X:\path\to\DownloadSong"  -k "0123456789ABCDEF FEDCBA9876543210"

# Written by Edness   v1.0.1   2026-07-21

import glob, hashlib, os

RSA_MOD = 0xDD3CFCF814D2AE65C09623F814E8BD445CFBB71E246815D11952BC1EA77C5D3774EF64D80D146D060684F15F8B24FD71BE32F500CF0DB3BECD9D8C51DA8A044ECAD467DA27E8072D451C236D83DD5F2E2FEA17297653A391AE6913B00E453F99C3F6395CDF2084BF5E6F06B4F27B3E1BEF92F957FC640D39B84E6BDE84B40979DA3C9C16BF7BD7BB6DBF1FB063BBDB15BD57FA8F024E2E2DB542999F17E113E727E37927DE2B8957A8C552EFD7955EDEA292E6515E6CFB4ACE562145A58B42DB67D896229C8A19FCE4DFF9D60843D556482706F59AD37F15D1EA4FAEB52A19BA92944487D9E6EF172B4EC341BC7C7341D8708CD5740B4B220B4C6BB4D9425983

UINT32 = lambda num: num & 0xFFFFFFFF
BSWAP32 = lambda num: num >> 24 & 0xFF | num >> 8 & 0xFF00 | (num & 0xFF00) << 8 | (num & 0xFF) << 24

def rsa_verify(msg, mod):
    orig = msg
    # (msg ** 65537) % mod, but fast
    for i in range(16):
        msg = (msg * msg) % mod
    return (msg * orig) % mod

def get_xtea_xor_key(v1, key):
    sum = 0x0
    v0 = 0x12345678
    for i in range(20):
        v0 = UINT32(v0 + ((v1 << 4 ^ v1 >> 5) + v1 ^ sum + key[sum & 3]))
        sum += 0x9E3779B9
        v1 = UINT32(v1 + ((v0 << 4 ^ v0 >> 5) + v0 ^ sum + key[(sum >> 11) & 3]))
    return v1 << 32 | v0

def strip_keystore(path, psid):
    path = os.path.abspath(path)
    print("Stripping", os.path.split(path)[1])
    try: psid = bytes.fromhex(psid)
    except: raise AssertionError(ERR_PSID)
    assert len(psid) == 0x10, ERR_PSID
    psid_hash = hashlib.sha1(psid).digest()
    blank_hash = hashlib.sha1(b"").digest()
    with open(path, "r+b") as file:
        file.seek(-0x100, 2)
        keystore = file.read(0x100)
        signed = False
        if not keystore.endswith(b"SDRM"):  # [0xFC:0x100]
            keystore = int.to_bytes(rsa_verify(int.from_bytes(keystore, "big"), RSA_MOD), 0x100, "big")
            signed = True
        keystore = bytearray(keystore)
        assert keystore.endswith(b"\x00\xFE\x06\x01SDRM"), ERR_SDRM  # [0xF8:0x100]
        assert keystore[0x60:0x74] == hashlib.sha1(keystore[0x74:] + keystore[:0x60]).digest(), ERR_SDRM
        assert keystore[0x9C:0xB0] == blank_hash, ERR_SDRM
        assert keystore[0x74:0x84] == bytes.fromhex("F33964A9 46BD983F 6B1B6306 73E79E0B"), ERR_SDRM
        assert keystore[0xD8:0xE8] == bytes.fromhex("5D4C6E15 44015809 AC35AC16 575FC123"), ERR_SDRM
        assert keystore[0xE8:0xF8] == bytes.fromhex("ECD56806 BA777B7F 685A55ED 78114B9A"), ERR_SDRM
        assert keystore[0x98:0x9C] == b"\x03\x01\xFF\x01", ERR_SDRM
        assert keystore[0xB0:0xB4] == b"\x00\x00\x00\x00", ERR_SDRM
        assert keystore[0x5F] == 0x14, ERR_SDRM
        file.seek(0x0)
        filesize = os.path.getsize(path) - 0x100
        size = min(0x10000, filesize)
        sha = hashlib.sha1()
        sha.update(file.read(size))
        while file.tell() + 0x3FC00 < filesize:
            file.seek(0x3FC00, 1)
            sha.update(file.read(min(0x400, filesize - file.tell())))
        assert keystore[0x84:0x98] == sha.digest(), ERR_HASH
        blank_key = int.from_bytes(hashlib.sha1(bytes(0x14) + blank_hash).digest()[:0x10], "big")
        drm_key = int.from_bytes(keystore[0xB4:0xC4], "big")
        if keystore[0xC4:0xD8] == bytes(0x14):
            if signed: print(f"[INFO] {os.path.split(path)[1]} is already DRM free!")  # very rare but known to occur
            else: print(f"[INFO] {os.path.split(path)[1]} is already stripped!")
            drm_key ^= blank_key
            write_ks = False
        else:
            psid_key = int.from_bytes(hashlib.sha1(psid_hash + blank_hash).digest()[:0x10], "big")
            assert keystore[0xC4:0xD8] == hashlib.sha1(psid_hash).digest(), ERR_PSID
            keystore[0xC4:0xD8] = bytes(0x14)
            keystore[0xB4:0xC4] = int.to_bytes(drm_key ^ psid_key ^ blank_key, 0x10, "big")
            keystore[0x60:0x74] = hashlib.sha1(keystore[0x74:] + keystore[:0x60]).digest()
            drm_key ^= psid_key
            write_ks = True
        file.seek(0x0)
        target_key = int.from_bytes(file.read(0x8), "little") ^ 0x204547414B434150
        key = (BSWAP32(drm_key >> 96), BSWAP32(drm_key >> 64), BSWAP32(drm_key >> 32), BSWAP32(drm_key))
        assert get_xtea_xor_key(0x0, key) == target_key, ERR_SDRM
        if write_ks:
            file.seek(-0x100, 2)
            file.write(keystore)

def main(path, psid):
    if os.path.isfile(path):
        strip_keystore(path, psid)
    else:  # os.path.isdir(path):
        for file in glob.iglob(os.path.join(glob.escape(path), "**", "*.pkg.drm"), recursive=True):
            strip_keystore(file, psid)

ERR_PSID = "[ERROR] Provided OpenPSID is invalid"
ERR_SDRM = "[ERROR] Provided file's keystore is invalid"
ERR_HASH = "[ERROR] Provided file's hash is invalid"

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parses and cleans .pkg.drm files signed with an OpenPSID")
    parser.add_argument("path", type=str, help="path to scan for .pkg.drm files")
    parser.add_argument("-k", "--drmkey", type=str, default="00000000000000000000000000000000", help="your PS3's OpenPSID")

    args = parser.parse_args()
    main(args.path, args.drmkey)
