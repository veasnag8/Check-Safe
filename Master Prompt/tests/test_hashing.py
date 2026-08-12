from app.utils.hashing import compute_hashes


def test_sha256():
    hashes = compute_hashes(b"abc")
    assert hashes["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
