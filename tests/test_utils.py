from mini_ids.utils import (NetSet, WindowCounter, WindowDistinct, WindowSum, base_domain,
                            domain_matches, shannon_entropy, subdomain_part)


def test_window_counter_slides():
    w = WindowCounter(10)
    for t in range(5):
        w.add("k", float(t))
    assert w.count("k", 4.0) == 5
    assert w.count("k", 12.5) == 2          # chỉ còn t=3,4 trong [2.5, 12.5]
    w.prune(100.0)
    assert len(w) == 0


def test_window_distinct_counts_unique_values():
    w = WindowDistinct(10)
    assert w.add("src", 80, 0.0) == 1
    assert w.add("src", 80, 1.0) == 1
    assert w.add("src", 443, 2.0) == 2
    assert w.add("src", 22, 11.5) == 2      # port 80 (last 1.0) đã rơi khỏi cửa sổ
    assert sorted(w.values("src")) == [22, 443]


def test_window_sum():
    w = WindowSum(5)
    w.add("a", 0.0, 100)
    assert w.add("a", 3.0, 50) == 150
    assert w.add("a", 6.0, 10) == 60


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert abs(shannon_entropy("ab") - 1.0) < 1e-9
    assert shannon_entropy("mzxw6ytboi4dsnbvgy3tqojqgezdgnbv") > 3.8
    assert shannon_entropy("mail") < 2.5


def test_domains():
    assert base_domain("a.b.example.com.") == "example.com"
    assert base_domain("www.vnexpress.com.vn") == "vnexpress.com.vn"
    assert subdomain_part("x1.t.tunnel.example") == "x1.t"
    assert subdomain_part("example.com") == ""
    assert domain_matches("update.malware-c2.example", ["malware-c2.example"]) == "malware-c2.example"
    assert domain_matches("notmalware-c2.example", ["malware-c2.example"]) is None


def test_netset():
    n = NetSet(["192.168.0.0/16", "10.0.0.1", "# comment", "garbage"])
    assert len(n) == 2
    assert "192.168.1.20" in n
    assert "10.0.0.1" in n
    assert "10.0.0.2" not in n
    assert "8.8.8.8" not in n
    assert None not in n
