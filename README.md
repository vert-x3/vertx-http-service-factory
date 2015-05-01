## Vertx http service factory

A service factory that deploys from HTTP servers

```
vertx run https://myserver.net/myverticle.zip
```

Supports basic auth, client configuration (for ssl, etc...), local cache, signature verification

## todo

### doc
### better http response code handling (redirection)
### Keybase.io support

The query https://keybase.io/_/api/1.0/key/fetch.json?pgp_key_ids=9F9358A769793D09 returns:

```
{
  "guest_id": "59f51fac9c456e246b2b99d327ef2508",
  "status": {
    "code": 0,
    "name": "OK"
  },
  "keys": [
    {
      "bundle": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1 ... -----END PGP PUBLIC KEY BLOCK-----",
      "uid": "ba283be4f1ac501126a6d19443202219",
      "username": "julienviet",
      "key_type": 1,
      "kid": "010173c51039584ed2fa1de43fb0adc531e2e148c4f98f30e0047fd22a656c5ccebc0a",
      "self_signed": 0,
      "primary_bundle_in_keyring": 1,
      "fingerprint": "33f0d7ae129514007cdf67de9f9358a769793d09",
      "key_fingerprint": "33f0d7ae129514007cdf67de9f9358a769793d09",
      "sig": "-----BEGIN PGP MESSAGE-----\n ... -----END PGP MESSAGE-----",
      "sig_type": 1,
      "sig_json": "{\"body\":{\"key\":{\"fingerprint\":\"33f0d7ae129514007cdf67de9f9358a769793d09\",\"host\":\"keybase.io\",\"key_id\":\"9f9358a769793d09\",\"kid\":\"010173c51039584ed2fa1de43fb0adc531e2e148c4f98f30e0047fd22a656c5ccebc0a\",\"uid\":\"ba283be4f1ac501126a6d19443202219\",\"username\":\"julienviet\"},\"type\":\"web_service_binding\",\"version\":1},\"ctime\":1430407086,\"expire_in\":157680000,\"prev\":null,\"seqno\":1,\"tag\":\"signature\"}\n",
      "self_sign_type": 2,
      "subkeys": {
        "0c27f527aa28fac2": {
          "flags": 12,
          "is_primary": 0
        },
        "9f9358a769793d09": {
          "flags": 3,
          "is_primary": 1
        }
      },
      "secret": 0
    }
  ],
  "csrf_token": "lgHZIDU5ZjUxZmFjOWM0NTZlMjQ2YjJiOTlkMzI3ZWYyNTA4zlVDlZvOAAFRgMDEIDDymrygwispOTHPrB7XgO3D1xZ8al/AIlQ+frXLsLmy"
}
```


