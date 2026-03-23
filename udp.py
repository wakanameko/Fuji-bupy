#!/usr/bin/env python3
"""
UPD BIOS Extractor
==============================
Script to extract raw BIOS image as *.bin
from Fujitsu (InsydeH2O)'s BIOS update file (UPD).

Sample: FJNB2C6.UPD (V1.24.0.0, 2024-10-18)

Construct:
    .text  (0x0280)                         ← Loader code
    (unnamed) (0x4E00)                      ← Some resources?
    .xdata (0x5060)                         ← Exception table
    .reloc (0x5140)                         ← ※ 実際はペイロード格納領域
        [PE reloc header]  408 bytes
        $_IFLASH_DRV_IMG                    ← Chunk of the Driver to flash EFI
            [Inner PE64 EFI DLL]            ← Driver? I did not analyzed this chunk cuz no related to BIOS img. 
                .text / text / .xdata / .reloc
        $_IFLASH_BIOSIMG                    ← Chunk of the BIOS image
            [UEFI Firmware Volumes]         ← Raw image about 12MB
        [Authenticode Signiture]            ← PKCS#7 / "Fujitsu BIOS Secure Firmware Update {yyyy} Certificate"

$_IFLASH chunk (28 bytes):
    offs    type        description
    0x0 :   char[16]    tag name ('$_IFLASH_BIOSIMG')
    0x10:   uint32_le   aligned_size (size of aligned data_size)
    0x14:   uint32_le   data_size
    0x18:               <raw BIOS img>

"""

from typing import Optional, List, Tuple
import struct
import re
from pathlib import Path


IFLASH_TAG_SIZE = 0x18              # tag name 0x10 + v1(0x4) + v2(0x4)
BIOSIMG_TAG = b'$_IFLASH_BIOSIMG'
DRVIMG_TAG  = b'$_IFLASH_DRV_IMG'



def find_tag_iflash(data: bytes, tag: bytes) -> Optional[int]:
    """Find the tag $_IFLASH_*. Except: None"""
    pos = data.find(tag)
    return pos if pos != -1 else None


def parse_chunk_iflash(data: bytes, offset: int) -> Tuple[str, int, int, int]:
    """
    Parse the chunk $_IFLASH.

    Returns: (tag_name, aligned_size, data_size, data_offset)
    """
    tag_name = data[offset:offset + 0x10].rstrip(b'\x00').decode(errors='replace')
    aligned_size = struct.unpack_from('<I', data, offset + 0x10)[0]
    data_size    = struct.unpack_from('<I', data, offset + 0x14)[0]
    data_offset  = offset + IFLASH_TAG_SIZE
    return tag_name, aligned_size, data_size, data_offset


def validate_pe(data: bytes, offset: int = 0) -> bool:
    """find the signiture MZ || PE"""
    if data[offset:offset + 0x2] != b'MZ':
        return False
    e_lfanew = struct.unpack_from('<I', data, offset + 0x3C)[0]
    return data[offset+e_lfanew:offset+e_lfanew + 0x4] == b'PE\x00\x00'


def find_uefi_volumes(data: bytes) -> List[Tuple[int, int]]:
    """Find UEFI Firmware Volumes and return them."""
    ret = []
    for m in re.finditer(b'_FVH', data):
        base = m.start() - 40
        if base < 0:
            continue
        try:
            fv_len = struct.unpack_from('<Q', data, base+32)[0]
            # 妥当なサイズか確認する (1KB ~ 64MB)
            if 1024 <= fv_len <= 64 * 1024 * 1024:
                ret.append((base, fv_len))
        except struct.error:
            continue
    return ret


def extract(path_upd: str, out_path: Optional[str] = None) -> str:
    """
    Extract the BIOS image from UPD file, and save it as *.bin.

    Returns: Path of the output file
    """
    path_upd = Path(path_upd)
    if not path_upd.exists():
        raise FileNotFoundError("Input file not found: {}".format(path_upd))
 
    print("[*] Reading: {} ({:,} bytes)".format(path_upd, path_upd.stat().st_size))
    data = path_upd.read_bytes()
 
    # ---- 1. Check Outer PE ----
    if not validate_pe(data):
        raise ValueError("Input is not a valid PE/EFI executable")
    print("[+] Outer PE64 EFI DLL confirmed")
 
    # ---- 2. Find the tag $_IFLASH_DRV_IMG ----
    drv_pos = find_tag_iflash(data, DRVIMG_TAG)
    if drv_pos is None:
        raise ValueError("$_IFLASH_DRV_IMG tag not found")
    drv_name, drv_aligned, drv_size, drv_data_off = parse_chunk_iflash(data, drv_pos)
    print("[+] {}: data_size=0x{:08X} ({} KB) @ 0x{:08X}".format(drv_name, drv_size, drv_size // 1024, drv_pos))
 
    if not validate_pe(data, drv_data_off):
        print("[!] Warning: Inner EFI DRV does not start with MZ — offset may be off")
    else:
        print("    Inner EFI DRV (MZ) @ 0x{:08X}".format(drv_data_off))
 
    # ---- 3. Find the tag $_IFLASH_BIOSIMG ----
    bios_pos = find_tag_iflash(data, BIOSIMG_TAG)
    if bios_pos is None:
        raise ValueError("$_IFLASH_BIOSIMG tag not found")
    bios_name, bios_aligned, bios_size, bios_data_off = parse_chunk_iflash(data, bios_pos)
    print("[+] {}: data_size=0x{:08X} ({} MB) @ 0x{:08X}".format(bios_name, bios_size, bios_size // 1024 // 1024, bios_pos))
 
    if bios_data_off + bios_size > len(data):
        raise ValueError(
            (
                "BIOS image extends beyond file: need 0x{:X}, "
                "have 0x{:X}"
            ).format(bios_data_off + bios_size, len(data))
        )
 
    # ---- 4. Extract BIOS ----
    bios_image = data[bios_data_off : bios_data_off + bios_size]
 
    # ---- 5. Check UEFI FV ----
    fvs = find_uefi_volumes(bios_image)
    print("[+] Found {} UEFI Firmware Volume(s):".format(len(fvs)))
    for fv_off, fv_len in fvs:
        guid = bios_image[fv_off + 16 : fv_off + 32].hex()
        print("    0x{:08X}: size=0x{:08X} ({:5} KB) GUID={}...".format(fv_off, fv_len, fv_len//1024, guid[:8]))
 
    # ---- 6. Save BIOS as binary ----
    if out_path is None:
        out_path = str(path_upd.with_suffix('.bin'))
    out_path = Path(out_path)
    out_path.write_bytes(bios_image)
    print("[+] BIOS image saved: {} ({:,} bytes)".format(out_path, len(bios_image)))
    return str(out_path)
 
 
# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
 
def show_signature_info(data: bytes, bios_end_offset: int) -> None:
    """Echo Authenticode Information"""
    sig_data = data[bios_end_offset:]
    # PKCS#7 (ASN.1 SEQUENCE = 0x30 0x82)
    if len(sig_data) > 16 and sig_data[16:18] == b'\x30\x82':
        # "Fujitsu BIOS Secure Firmware Update" を探す
        marker = b'Fujitsu BIOS Secure Firmware Update'
        pos = sig_data.find(marker)
        if pos != -1:
            cert_name = sig_data[pos:pos + 60].split(b'\x00')[0].decode(errors='replace')   # たぶんできた
            print("[i] Authenticode certificate: {}".format(cert_name))


def main(path_udp_dir:str):
    if path_udp_dir is None:
        print("[udp.py]\tGave an unalivable path.")
        return None

    root = Path(path_udp_dir)
    path_upd = Path.joinpath(root, root.name[:-5] + ".UPD")
    path_out = Path.joinpath(root.parent.parent, root.name[:-4] + ".bin")

    try:
        result = extract(path_upd, path_out)
        print("[✓] Extraction complete: {}".format(result))
    except Exception as e:
        print("[✗] Error: {}".format(e))
        return None
