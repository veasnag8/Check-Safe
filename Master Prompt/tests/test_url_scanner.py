from app.utils.url_utils import extract_hostname, is_ip_address_hostname, normalize_url


def test_url_normalization():
    assert normalize_url("example.com").startswith("http://")


def test_hostname_extraction():
    assert extract_hostname("https://example.com/path") == "example.com"


def test_ip_url_detection():
    assert is_ip_address_hostname("127.0.0.1")
