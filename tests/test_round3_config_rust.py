"""Round 3 (qrp-pokazateli kragg-3): the kinds of Config and Rust misses found on a DEV corpus
of 16 public repositories (kragg-3/dev-korpus, labelled by Jev; NOT the frozen blind corpus,
which was never opened). Each kind below is real inventory, and each has its look-alikes.

  templates   Ansible/Salt Jinja templates (`sites-default.conf.j2`, `haproxy_run.sh.j2`) were
              "type not claimed": 357 of kolla-ansible's files, every nginx and sshd template.
  key files   an SSH host or identity key named by its file (`ssh_host_rsa_key`, `id_dsa`).
  key type    community.crypto's `type: RSA` / openssh_keypair's `type: rsa`, ssh-keygen -t.
  DH params   a DH parameter file or size configured (dovecot, nginx, haproxy, postfix).
  sshd        the options that name RSA (RSAAuthentication, RequiredRSASize).
  Rust        RustCrypto's own types and variants (RsaKeypair, KeypairData::Dsa), and in .rs
              the family as a word of a snake_case name, a module or a cargo feature.
"""

import pytest

from qrp_mcp.scan import scan_directory


def _families(tmp_path, name, text):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    result = scan_directory(tmp_path)
    rows = [r for r in result["evidence"]["source_code"] + result["evidence"]["iac"]
            if r["path"] == name]
    return {r["algorithm"] for r in rows}, result


@pytest.mark.parametrize("name, text, family", [
    ("templates/sites-default.conf.j2",
     "ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;\n", "ECDSA"),
    ("templates/sites-default.conf.j2", "ssl_ecdh_curve X25519:secp384r1;\n", "X25519"),
    ("templates/haproxy_run.sh.j2",
     "openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes -keyout k -out c\n", "RSA"),
    ("templates/sshd_config.j2", "HostKeyAlgorithms ssh-ed25519,ssh-rsa\n", "RSA"),
    ("templates/nova-ssh.json.j2", '{"dest": "/var/lib/nova/.ssh/id_rsa"}\n', "RSA"),
    # A template whose rendered name is no type of its own is configuration.
    ("templates/realm.provider.j2", "ssl_ecdh_curve X25519;\n", "X25519"),
])
def test_a_jinja_template_is_read_as_the_file_it_renders(tmp_path, name, text, family):
    found, result = _families(tmp_path, name, text)
    assert family in found, found
    assert not any(name in r.get("paths", []) for r in result["coverage"]["not_examined"])


def test_a_documentation_template_stays_unclaimed(tmp_path):
    found, result = _families(tmp_path, "docs/index.md.j2", "Use `ssh-rsa` keys.\n")
    assert not found
    assert any("docs/index.md.j2" in r.get("paths", []) for r in result["coverage"]["not_examined"])


@pytest.mark.parametrize("name, text, family", [
    ("vars/Debian.yml", "sshd_hostkeys:\n  - /etc/ssh/ssh_host_rsa_key\n", "RSA"),
    ("vars/Debian.yml", "sshd_hostkeys:\n  - /etc/ssh/ssh_host_dsa_key\n", "DSA"),
    ("sshd_config", "HostKey /etc/ssh/ssh_host_rsa_key\n", "RSA"),
    ("tests/private_key.rs", 'const OPENSSH_DSA_EXAMPLE: &str = include_str!("examples/id_dsa_1024");\n',
     "DSA"),
    ("conf/keystone.json", '{"source": "{{ dir }}/id_rsa.pub"}\n', "RSA"),
])
def test_an_ssh_key_file_names_its_type(tmp_path, name, text, family):
    assert family in _families(tmp_path, name, text)[0]


@pytest.mark.parametrize("text", [
    "grid_rsa = 1\n", "valid_dsa: true\n", "id_rsassa: x\n", "ssh_host_rsakeys: []\n",
])
def test_key_file_lookalikes(tmp_path, text):
    assert not _families(tmp_path, "a.yml", text)[0] & {"RSA", "DSA"}


@pytest.mark.parametrize("text, family", [
    ("- name: key\n  community.crypto.openssl_privatekey:\n    path: /k\n    type: RSA\n", "RSA"),
    ("- community.crypto.openssh_keypair:\n    path: /k\n    type: dsa\n", "DSA"),
    ("- community.crypto.openssl_privatekey:\n    type: ECC\n    curve: secp384r1\n", "EC"),
    ("- shell: ssh-keygen -q -t rsa -f /tmp/rsa_key -N ''\n", "RSA"),
    ("- shell: ssh-keygen -t dsa -f /tmp/k\n", "DSA"),
])
def test_a_key_type_in_a_task(tmp_path, text, family):
    assert family in _families(tmp_path, "tasks/main.yml", text)[0]


@pytest.mark.parametrize("text", [
    "type: string\n", "  type: rsakey_ref\n", "description: the type: RSA or ECC\n",
])
def test_key_type_lookalikes(tmp_path, text):
    assert not _families(tmp_path, "a.yml", text)[0] & {"RSA", "EC"}


@pytest.mark.parametrize("name, text", [
    ("dovecot.conf", "ssl_dh = </etc/ssl/mail/dhparams.pem\n"),
    ("nginx.conf", "    ssl_dhparam /etc/nginx/dhparam.pem;\n"),
    ("haproxy.cfg", "    tune.ssl.default-dh-param 4096\n"),
    ("main.cf", "smtpd_tls_dh1024_param_file = /etc/ssl/dh.pem\n"),
    ("ssl.conf", 'SSLOpenSSLConfCmd DHParameters "/etc/ssl/dh.pem"\n'),
])
def test_dh_parameters_configured(tmp_path, name, text):
    # main.cf is not a claimed name; the rule is checked through a .conf copy of it.
    name = name if name != "main.cf" else "postfix-main.conf"
    assert "DH" in _families(tmp_path, name, text)[0]


def test_a_dh_params_variable_in_code_is_not_a_setting(tmp_path):
    assert "DH" not in _families(tmp_path, "a.py", "ssl_dhparams = None\n")[0]


@pytest.mark.parametrize("text", [
    "RSAAuthentication yes\n", "RequiredRSASize 3072\n", "RhostsRSAAuthentication no\n",
])
def test_sshd_options_that_name_rsa(tmp_path, text):
    assert "RSA" in _families(tmp_path, "sshd_config", text)[0]


@pytest.mark.parametrize("text, family", [
    ("impl From<RsaKeypair> for PrivateKey {\n", "RSA"),
    ("    Self::Dsa(dsa) => dsa.private().as_bytes(),\n", "DSA"),
    ("    Ok(KeypairData::Dsa(DsaKeypair::new(pk, sk)?))\n", "DSA"),
    ("let rsa_keys = RSAKeys::new(DEFAULT_KEY_SIZE)?;\n", "RSA"),
    ("let key = RsaOaepDecryptionKey::generate(2048).unwrap();\n", "RSA"),
    ("assert_eq!(Algorithm::Dsa, cert.public_key().algorithm());\n", "DSA"),
    ("mod dsa;\n", "DSA"),
    ("fn decode_dsa_openssh() {\n", "DSA"),
    ('#[cfg(feature = "dsa")]\n', "DSA"),
    ("fn jwe_rsa_oaep() {\n", "RSA"),
    ("let key = rsa_to_pkcs8(&pem);\n", "RSA"),
])
def test_rust_names(tmp_path, text, family):
    assert family in _families(tmp_path, "src/key.rs", text)[0]


@pytest.mark.parametrize("text", [
    "use ml_dsa::{MlDsa65, KeyGen};\n", "let s = slh_dsa::SigningKey::new();\n",
    "let k = MlDsa65::key_gen(&mut rng);\n", "let versa = vice;\n", "fn dsap() {}\n",
])
def test_rust_lookalikes(tmp_path, text):
    assert "DSA" not in _families(tmp_path, "src/key.rs", text)[0]
    assert "RSA" not in _families(tmp_path, "src/key.rs", text)[0]


def test_snake_case_words_are_rust_only(tmp_path):
    # A Python test name is not given the Rust reading.
    assert "DSA" not in _families(tmp_path, "t.py", "def decode_dsa_openssh():\n    pass\n")[0]
