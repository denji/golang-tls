##### Generate private key (.key)

```sh
# Key considerations for algorithm "RSA" ≥ 2048-bit
openssl genrsa -out server.key 2048

# Key considerations for algorithm "ECDSA" (X25519 || ≥ secp384r1)
# https://safecurves.cr.yp.to/
# List ECDSA the supported curves (openssl ecparam -list_curves)
openssl ecparam -genkey -name secp384r1 -out server.key
```

##### Generation of self-signed(x509) public key (PEM-encodings `.pem`|`.crt`) based on the private (`.key`)

```sh
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```

---

#### Simple Golang HTTPS/TLS Server

```go
package main

import (
    // "fmt"
    // "io"
    "net/http"
    "log"
)

func HelloServer(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte("This is an example server.\n"))
    // fmt.Fprintf(w, "This is an example server.\n")
    // io.WriteString(w, "This is an example server.\n")
}

func main() {
    http.HandleFunc("/hello", HelloServer)
    err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}
```

Hint: visit, please do not forget to use https begins, otherwise chrome will download a file as follows:

```bash
$ curl -sL https://localhost:443 | xxd
0000000: 1503 0100 0202 0a                        .......
```

#### TLS (transport layer security) — `Server`

```go
package main

import (
    "log"
    "crypto/tls"
    "net"
    "bufio"
)

func main() {
    log.SetFlags(log.Lshortfile)

    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }

    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    ln, err := tls.Listen("tcp", ":443", config) 
    if err != nil {
        log.Println(err)
        return
    }
    defer ln.Close()

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()
    r := bufio.NewReader(conn)
    for {
        msg, err := r.ReadString('\n')
        if err != nil {
            log.Println(err)
            return
        }

        println(msg)

        n, err := conn.Write([]byte("world\n"))
        if err != nil {
            log.Println(n, err)
            return
        }
    }
}
```

#### TLS (transport layer security) — `Client`

```go
package main

import (
    "log"
    "crypto/tls"
)

func main() {
    log.SetFlags(log.Lshortfile)

    conf := &tls.Config{
         //InsecureSkipVerify: true,
    }

    conn, err := tls.Dial("tcp", "127.0.0.1:443", conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()

    n, err := conn.Write([]byte("hello\n"))
    if err != nil {
        log.Println(n, err)
        return
    }

    buf := make([]byte, 100)
    n, err = conn.Read(buf)
    if err != nil {
        log.Println(n, err)
        return
    }

    println(string(buf[:n]))
}
```

##### [Perfect SSL Labs Score with Go](https://blog.bracelab.com/achieving-perfect-ssl-labs-score-with-go)

```go
package main

import (
    "crypto/tls"
    "log"
    "net/http"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
        w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        w.Write([]byte("This is an example server.\n"))
    })
    cfg := &tls.Config{
        MinVersion:               tls.VersionTLS12,
        CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        },
    }
    srv := &http.Server{
        Addr:         ":443",
        Handler:      mux,
        TLSConfig:    cfg,
        TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
    }
    log.Fatal(srv.ListenAndServeTLS("tls.crt", "tls.key"))
}
```

#### Generation of self-sign a certificate with a private (`.key`) and public key (PEM-encodings `.pem`|`.crt`) in one command:

```sh
# ECDSA recommendation key ≥ secp384r1
# List ECDSA the supported curves (openssl ecparam -list_curves)
openssl req -x509 -nodes -newkey ec:secp384r1 -keyout server.ecdsa.key -out server.ecdsa.crt -days 3650
# openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) -keyout server.ecdsa.key -out server.ecdsa.crt -days 3650
# -pkeyopt ec_paramgen_curve:… / ec:<(openssl ecparam -name …) / -newkey ec:…
ln -sf server.ecdsa.key server.key
ln -sf server.ecdsa.crt server.crt

# RSA recommendation key ≥ 2048-bit
openssl req -x509 -nodes -newkey rsa:2048 -keyout server.rsa.key -out server.rsa.crt -days 3650
ln -sf server.rsa.key server.key
ln -sf server.rsa.crt server.crt
```

* `.crt` — Alternate synonymous most common among *nix systems `.pem` (pubkey).
* `.csr` — Certficate Signing Requests (synonymous most common among *nix systems).
* `.cer` — Microsoft alternate form of `.crt`, you can use MS to convert `.crt` to `.cer` (`DER` encoded `.cer`, or `base64[PEM]` encoded `.cer`).
* `.pem` = The PEM extension is used for different types of X.509v3 files which contain ASCII (Base64) armored data prefixed with a «—– BEGIN …» line. These files may also bear the `cer` or the `crt` extension.
* `.der` — The DER extension is used for binary DER encoded certificates.

#### Generating the Certficate Signing Request

    openssl req -new -sha256 -key server.key -out server.csr
    openssl x509 -req -sha256 -in server.csr -signkey server.key -out server.crt -days 3650

ECDSA & RSA — FAQ
---
* Validate the elliptic curve parameters `-check`
* List "ECDSA" the supported curves `openssl ecparam -list_curves`
* Encoding to explicit "ECDSA" `-param_enc explicit`
* Conversion form to compressed "ECDSA" `-conv_form compressed`
* "EC" parameters and a private key `-genkey`

CA Bundle Path
---

| Distro                                                       	| Package         	| Path to CA                               	|
|--------------------------------------------------------------	|-----------------	|------------------------------------------	|
| Fedora, RHEL, CentOS                                         	| ca-certificates 	| /etc/pki/tls/certs/ca-bundle.crt         	|
| Debian, Ubuntu, Gentoo, Arch Linux                           	| ca-certificates 	| /etc/ssl/certs/ca-certificates.crt       	|
| SUSE, openSUSE                                               	| ca-certificates 	| /etc/ssl/ca-bundle.pem                   	|
| FreeBSD                                                      	| ca_root_nss     	| /usr/local/share/certs/ca-root-nss.crt   	|
| Cygwin                                                       	| -               	| /usr/ssl/certs/ca-bundle.crt             	|
| macOS (MacPorts)                                             	| curl-ca-bundle  	| /opt/local/share/curl/curl-ca-bundle.crt 	|
| Default cURL CA bunde path (without --with-ca-bundle option) 	|                 	| /usr/local/share/curl/curl-ca-bundle.crt 	|
| Really old RedHat?                                           	|                 	| /usr/share/ssl/certs/ca-bundle.crt       	|

Reference Link
---
* https://getgophish.com/blog/post/2018-12-02-building-web-servers-in-go/
* [Go programming language secure coding practices guide](https://github.com/Checkmarx/Go-SCP)
* ~~[Achieving a Perfect SSL Labs Score with Go – `blog.bracelab.com`](https://web.archive.org/web/20160520182043/https://blog.bracelab.com/achieving-perfect-ssl-labs-score-with-go)~~
* [Automatic HTTPS With Free SSL Certificates Using Go + Let's Encrypt](https://www.captaincodeman.com/2017/05/07/automatic-https-with-free-ssl-certificates-using-go-lets-encrypt)
* https://golang.org/pkg/crypto/tls/
* [OpenSSL without prompt – `superuser.com` (Stack Exchange)](http://superuser.com/a/226229/205366)
* [TLS server and client — `gist.github.com/spikebike`](https://gist.github.com/spikebike/2232102)
* ~~[Echo, a fast and unfancy micro web framework for Go — `echo.labstack.com/guide`](https://web.archive.org/web/20150925030955/http://echo.labstack.com/guide)~~
* https://kjur.github.io/jsrsasign/sample-ecdsa.html
* [Creating Self-Signed ECDSA SSL Certificate using OpenSSL – `guyrutenberg.com`](https://www.guyrutenberg.com/2013/12/28/creating-self-signed-ecdsa-ssl-certificate-using-openssl/)
* https://www.openssl.org/docs/manmaster/
 * https://www.openssl.org/docs/manmaster/man1/ecparam.html
 * https://www.openssl.org/docs/manmaster/man1/ec.html
 * https://www.openssl.org/docs/manmaster/man1/req.html
* https://digitalelf.net/2016/02/creating-ssl-certificates-in-3-easy-steps/
* [HTTPS and Go – `kaihag.com`](http://www.kaihag.com/https-and-go/)
* [The complete guide to Go net/http timeouts – `blog.cloudflare.com`](https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/)
* [Certificate fetcher in Go – `gist.github.com`](https://gist.github.com/jtwaleson/1fdd77260bcb48377b6b)
* [How to redirect HTTP to HTTPS with a golang webserver – `gist.github.com`](https://gist.github.com/d-schmidt/587ceec34ce1334a5e60)
* __[XCA - X Certificate and key management](https://sourceforge.net/projects/xca/)__
* Package [tcplisten](https://github.com/valyala/tcplisten) provides customizable TCP `net.Listener` with various performance-related options 
* https://github.com/bifurcation/mint — minimal TLS 1.3 Implementation in Go
* https://github.com/cloudflare/tls-tris — crypto/tls, now with 100% more 1.3
* https://github.com/Xeoncross/secureserver
* https://github.com/cloudflare/cfssl
* https://github.com/google/certificate-transparency
* https://cipherli.st/
* https://github.com/cmrunton/tls-dashboard — dashboard written in JavaScript & HTML to check the remaining time before a TLS certificate expires.
* https://github.com/tomato42/tlsfuzzer
* https://github.com/mozilla/tls-observatory (https://observatory.mozilla.org/)
* https://dev.ssllabs.com/ssltest/
* https://indieweb.org/HTTPS
* https://github.com/konklone/shaaaaaaaaaaaaa (https://shaaaaaaaaaaaaa.com/)
* https://securityheaders.io/
* https://testssl.sh/
* https://github.com/nabla-c0d3/sslyze
* https://github.com/iSECPartners/sslyze
* https://github.com/mozilla/cipherscan
* https://github.com/ssllabs/ssllabs-scan
* https://github.com/chromium/badssl.com (https://badssl.com)
* https://github.com/datatheorem/TrustKit
* https://github.com/certifi/gocertifi
* https://github.com/unrolled/secure
* https://github.com/tidwall/modern-server
* https://github.com/genkiroid/cert
* https://github.com/zmap/zlint
* https://github.com/globalsign/certlint
* https://github.com/google/certificate-transparency-go
* https://github.com/FiloSottile/mkcert
* https://github.com/Evolix/chexpire
* https://github.com/mimoo/cryptobible/blob/master/protocols/tls.mediawiki
* https://posener.github.io/http2/
* https://seclists.org/oss-sec/2018/q4/123
* …
