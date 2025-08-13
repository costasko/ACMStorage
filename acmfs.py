#!/usr/bin/env python3

from collections import defaultdict
import errno
import logging
import os
import pickle
import stat
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Sequence
from pathlib import Path

import boto3
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fuse import FUSE, FuseOSError, Operations

ROOT_DIR = Path(os.getenv("ACMFS_ROOT", "./ACMFS")).resolve()
INDEX_FILE = ROOT_DIR / "acm_index.pkl"
CA_KEY_FILE = ROOT_DIR / "ca.key"
CA_CERT_FILE = ROOT_DIR / "ca.crt"

AWS_REGION = os.getenv("AWS_REGION", "eu-west-1")
_session = boto3.session.Session(region_name=AWS_REGION)
acm = _session.client("acm")

CUSTOM_OID = ObjectIdentifier("2.16.840.1.113730.1.13")  # nsComment
MAX_CHUNK = 1523333  # keep chain cert under ACM 1.5MB due do base64 encoding


def generate_ca():
    ca_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ACMFS CA")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    return ca_key, builder.sign(ca_key, hashes.SHA256(), backend=default_backend())


def ensure_local_ca():
    if CA_KEY_FILE.exists() and CA_CERT_FILE.exists():
        logging.info(f"[-] Reusing existing CA at {CA_KEY_FILE}")
        with open(CA_KEY_FILE, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return ca_key, ca_cert

    ROOT_DIR.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = generate_ca()
    with open(CA_KEY_FILE, "wb") as f:
        f.write(
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    with open(CA_CERT_FILE, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    logging.info("Generated local CA in %s", ROOT_DIR)
    return ca_key, ca_cert


# Keep an index of files


def load_index() -> Dict[str, List[str]]:
    if INDEX_FILE.exists():
        with open(INDEX_FILE, "rb") as f:
            data = pickle.load(f)
        return data
    save_index(defaultdict(list, {".": ["."]}))
    return load_index()


def list_files():
    with open(INDEX_FILE, "rb") as f:
        data = pickle.load(f)
    return data.keys()


def save_index(index: Dict[str, List[str]], pop_key=""):
    p = Path(INDEX_FILE)
    try:
        store: dict[str, list] = pickle.loads(p.read_bytes())
    except FileNotFoundError:
        store = defaultdict(list)
    if pop_key:
        store.pop(pop_key)
    store.update(index)
    p.write_bytes(pickle.dumps(store, protocol=pickle.HIGHEST_PROTOCOL))


def list_acm_certificates() -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    paginator = acm.get_paginator("list_certificates")
    for page in paginator.paginate(CertificateStatuses=["ISSUED"]):
        for c in page.get("CertificateSummaryList", []):
            mapping[c["CertificateArn"].split("/")[-1] + ".pem"] = c["CertificateArn"]
    return mapping


def create_end_entity_certificate(data_chunk: bytes, ca_key, ca_cert):
    ee_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "X509 Data Carrier")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(ee_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=1))
        .add_extension(
            x509.UnrecognizedExtension(CUSTOM_OID, data_chunk), critical=False
        )
    )
    return builder.sign(ca_key, hashes.SHA256(), backend=default_backend())


# FUSE


class ACMFS(Operations):
    def __init__(self):
        self.ca_key, self.ca_cert = ensure_local_ca()
        self.index = load_index()
        self.fd = 1
        self._buffers: Dict[int, bytes] = {}
        self._filenames: Dict[int, str] = {}
        self._cache: Dict[str, bytes] = {}
        logging.info("[-] ACMFS mounted")

    # ------ helpers ------
    def _full(self, path: str) -> str:
        return path.lstrip("/")

    def _assemble_data(self, fname: str) -> bytes:
        logging.info(f"Assembling {fname}")
        if fname in self._cache:
            return self._cache[fname]
        arns: Sequence[str] = self.index.get(fname, [])
        chunks = bytearray()
        logging.info(f"Processing {arns}")
        for arn in arns:
            cert = acm.get_certificate(CertificateArn=arn)
            parsed_cert = x509.load_pem_x509_certificate(
                bytes(cert["CertificateChain"], "utf-8")
            )
            logging.info("Got certs")
            val = parsed_cert.extensions.get_extension_for_oid(CUSTOM_OID).value.value
            chunks.extend(val[8:])
        self._cache[fname] = chunks
        logging.info(f"Got {fname} with size {len(chunks)}")
        return chunks

    # ------ filesystem ops ------

    def readdir(self, path, fh):
        if path in [".", "..", "/"]:
            for fname in self.index:
                yield fname

    def unlink(self, path):
        name = self._full(path)
        for arn in self.index.get(name, []):
            acm.delete_certificate(CertificateArn=arn)
        self.index.pop(name, None)
        save_index(self.index, pop_key=name)
        self._cache.pop(name, None)

    # ---- open / read ----
    def open(self, path, flags):
        fname = self._full(path)
        if fname not in self.index:
            raise FuseOSError(errno.ENOENT)
        self.fd += 1
        return self.fd

    def read(self, path, size, offset, fh):
        logging.info(f"Reading {path} with {size}")
        data = self._assemble_data(self._full(path))
        logging.info("out of read")
        return bytes(data[offset : offset + size])

    def getattr(self, path, fh=None):
        logging.info(f"Getting attr for {path} with {fh}")
        now = time.time()
        st = dict(
            st_mode=stat.S_IFDIR | 0o755,
            st_nlink=2,
            st_size=0,
            st_ctime=now,
            st_mtime=now,
            st_atime=now,
        )

        if path == "/":
            return st
        st["st_mode"] = stat.S_IFREG | 0o644
        st["st_nlink"] = 1
        fname = self._full(path)

        if fname not in self.index and fh not in self._filenames:
            raise FuseOSError(errno.ENOENT)
        elif fname not in self.index and fh in self._filenames:
            logging.info(f"File is local but not remote")
            st["st_size"] = 0
            st["st_ino"] = fh
            st["st_gid"] = os.getgid()
            st["st_uid"] = os.getuid()
            return st
        else:
            try:
                logging.error(f"Stating remote {fname}")
                st["st_size"] = len(
                    self._assemble_data(fname)
                )  # TODO: pickle size to avoid double call
                st["st_gid"] = os.getgid()
                st["st_uid"] = os.getuid()
            except FuseOSError as e:
                logging.error(f"FuseOSError: {e}")
                raise
            except Exception as e:
                logging.error(f"Exception {e}")
                st["st_size"] = 0
            return st

    # ---- write pipeline ----
    def create(self, path, mode, fi=None):
        name = self._full(path)
        logging.info(f"Creating {name} for {self.fd}")
        if name in self.index:
            raise FuseOSError(errno.EEXIST)
        self.fd += 1
        self._buffers[self.fd] = b""
        self._filenames[self.fd] = name
        return self.fd

    def write(self, path, data, offset, fh):
        self._buffers[fh] += data
        logging.info(f"Writing {data} in {path}")
        return len(data)

    def flush(self, path, fh):
        logging.info(f"Flushing {path} to {fh}")
        if fh not in self._buffers:
            return 0
        blob = self._buffers.pop(fh)
        fname = self._filenames.pop(fh)

        chunks = [blob[i : i + MAX_CHUNK] for i in range(0, len(blob), MAX_CHUNK)] or [
            b""
        ]
        total = len(chunks)

        arns: List[str] = []
        ca_key_pem = self.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ca_cert_pem = self.ca_cert.public_bytes(serialization.Encoding.PEM)

        for seq, chunk in enumerate(chunks, 1):
            payload = seq.to_bytes(4, "big") + total.to_bytes(4, "big") + chunk
            ee_cert = create_end_entity_certificate(payload, self.ca_key, self.ca_cert)
            ee_cert_pem = ee_cert.public_bytes(serialization.Encoding.PEM)
            resp = acm.import_certificate(
                Certificate=ca_cert_pem,
                CertificateChain=ee_cert_pem,
                PrivateKey=ca_key_pem,
            )
            arns.append(resp["CertificateArn"])

        self.index[fname] = arns
        save_index(self.index)
        self._cache[fname] = blob


def main(mountpoint: str, foreground: bool = False):
    logging.basicConfig(level=logging.INFO, format="[ACMFS] %(levelname)s: %(message)s")
    FUSE(
        ACMFS(),
        mountpoint,
        foreground=foreground,
        allow_other=True,
        nothreads=True,
        debug=True,
    )


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser("Mount AWS ACM as a filesystem")
    p.add_argument("mountpoint")
    p.add_argument("--foreground", action="store_true")
    args = p.parse_args()
    main(args.mountpoint, args.foreground)
