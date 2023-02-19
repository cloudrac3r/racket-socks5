#lang hyper-literate typed/racket/base
@(require (for-label typed/racket/base
                     racket/math
                     (only-in racket/contract/base cons/c)
                     openssl
                     net/url
                     net/http-client
                     net/http-easy))

@title[#:style manual-doc-style]{SOCKS5 TCP Client in Racket}
@author[(author+email "Cadence Ember" "cadence@disroot.org" #:obfuscate? #t)]

@local-table-of-contents[]

@section{Provides}

@defmodule[socks5]

@defproc[(socks5-connect [socks-host string?]
                         [socks-port positive-integer?]
                         [dest-host string?]
                         [dest-port positive-integer?]
                         [#:username-password username-password (cons/c bytes? bytes?) #f])
         (values input-port? output-port?)]{
@racket[socks-host] is the IP or hostname of the SOCKS5 server to connect to.

@racket[dest-host] is the IP or hostname of the destination server to connect to via the proxy. If it is a hostname, it will be resolved to an IP address by the proxy server. If this behaviour is undesirable, you can locally resolve the IP and pass it instead of the hostname.

@racket[#:username-password] (optional) is a pair of a username and password to try, as bytes. Not all SOCKS5 servers require authentication. Note that as a limitation of the SOCKS5 protocol, the username and password will be transmitted through the network in cleartext.
}

@subsubsub*section{Example usage}

@racketblock[
;; establish connection to example.com:80 via the proxy 127.0.0.1:1080
(define-values (in out) (socks5-connect "127.0.0.1" 1080 "example.com" 80))
;; send HTTP request and say that the connection should be closed
(displayln "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" out)
;; send TCP FIN
(close-output-port out)
;; print the server's response
(copy-port in (current-output-port))
]

@subsubsub*section{Typed Racket definition}

@chunk[<provide>
       (provide socks5-connect)
       (: socks5-connect (String Positive-Integer String Positive-Integer [#:username-password (Option (Pair Bytes Bytes))]
                          -> (Values Input-Port Output-Port)))
       (define (socks5-connect socks-host socks-port dest-host dest-port #:username-password [username-password #f])
         <socks-connect-body>)]

@defproc[(make-socks5-proxy [socks-host string?]
                            [socks-port positive-integer?]
                            [matches? (url? . -> . boolean?) (λ (_) #t)]
                            [#:username-password username-password (cons/c bytes? bytes?) #f])
         proxy?]{
This is intended to only be used with @seclink["Proxies" #:doc '(lib "net/http-easy.scrbl")]{the proxies feature of http-easy}.

@racket[socks-host] is the IP or hostname of the SOCKS5 server to connect to.

@racket[matches?] is a function that takes a URL and returns whether it should be handled by this proxy.

@racket[#:username-password] (optional) is a pair of a username and password to try, as bytes. Not all SOCKS5 servers require authentication. Note that as a limitation of the SOCKS5 protocol, the username and password will be transmitted through the network in cleartext.

@subsubsub*section[#:tag "make-socks5-proxy-example"]{Example usage}

@racketblock[
(define my-proxy (make-socks5-proxy "127.0.0.1" 1080))
(define my-session (make-session #:proxies (list my-proxy)))
(define my-response (session-request my-session "https://example.com"))
(response-body my-response)
]
}

@subsubsub*section{Typed Racket definition}

@chunk[<provide>
       (provide make-socks5-proxy)
       (: make-socks5-proxy ((String Positive-Integer) (Proxy-Matches? #:username-password (Option (Pair Bytes Bytes)))
                             . ->* . Proxy))
       (define (make-socks5-proxy socks-host socks-port [matches? (λ (_) #t)] #:username-password [username-password #f])
         <make-socks5-proxy-body>)]

@section[#:style '(toc)]{Source}

This is the full source code of the socks5 library. It is written in a literate programming style, where documentation and code live side by side, using the @other-doc['(lib "hyper-literate/scribblings/hyper-literate.scrbl")] language.

@local-table-of-contents[]

@subsection{SOCKS connection process}

@itemlist[
@item{Tell the SOCKS server which authentication methods we allow.}
@item{Server replies with its chosen authentication method.}
@item{Do authentication according to that method.}
@item{Tell the SOCKS server which destination host and port to connect to.}
@item{Server attempts remote connection and replies with connection status.}
@item{If connection was successful, the TCP ports act exactly as if they were directly connected to the destination. (No more in-band SOCKS messages are possible.)}
#:style 'ordered
]

@chunk[<socks-connect-body>
       (define-values (username password)
         (if (pair? username-password)
             (values (car username-password) (cdr username-password))
             (values #f #f)))
       <authentication-methods>
       (define-values (in out) (tcp-connect socks-host socks-port))
       (parameterize ([current-input-port in] [current-output-port out])
         <send-version-identifier>
         <receive-version-and-execute-method>
         <request-connect>
         <receive-connect>
         (values in out))]

The SOCKS5 protocol is described in @hyperlink["https://datatracker.ietf.org/doc/html/rfc1928/" "RFC 1928, SOCKS Protocol Version 5"], which I will quote from throughout this document.

@subsubsection{Initial exchange}

@subsubsub*section{Initial request}

@nested[#:style 'inset]{
When a TCP-based client wishes to establish a connection to an object, it must open a TCP connection to the appropriate SOCKS port on the SOCKS server system. The SOCKS service is conventionally located on TCP port 1080.  If the connection request succeeds, the client enters a negotiation for the authentication method to be used, authenticates with the chosen method, then sends a relay request.  The SOCKS server evaluates the request, and either establishes the appropriate connection or denies it.

The client connects to the server, and sends a version identifier/method selection message:

@codeblock0{
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
}
}

The version number is 5 for SOCKS5.

@chunk[<send-version-identifier>
       (send (bytes 5))
       <send-supported-authentication-methods>
       (flush-output)]

The "methods" fields describe authentication methods. The client sends all supported authentication method implementations, and the server chooses which one shall be used (or 0xFF for no choice).

Here are the authentication methods that I will implement:

@chunk[<authentication-methods>
       (define methods (ann (make-hasheq) (Mutable-HashTable Integer (-> Void))))
       (hash-set! methods 0 (λ () <method-none>))
       (when (and username password)
         (hash-set! methods 2 (λ () <method-username-password>)))]

Send the number of supported authentication methods, then the ID of each method.

@chunk[<send-supported-authentication-methods>
       (send (bytes (hash-count methods)))
       (for ([(id fn) (in-hash methods)])
         (send (bytes id)))]

@subsubsub*section{Initial response}

From my list of supported authentication methods, the server chooses which authentication method shall be used.

@nested[#:style 'inset]{
The server selects from one of the methods given in METHODS, and sends a METHOD selection message:

@codeblock0{
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+
}
}

After I receive this data, I verify the version field, then hand over to the server's chosen @seclink["Authentication_methods"]{authentication method} to negiotiate authentication.

@chunk[<receive-version-and-execute-method>
       (define bs (expect 2))
       (define ver (bytes-ref bs 0))
       (unless (eq? ver 5)
         (error 'receive-version-and-execute-method "server responded with unexpected version #~a" ver))
       (define method-id (bytes-ref bs 1))
       (define method (hash-ref methods method-id))
       (unless method
         (error 'receive-version-and-execute-method "server said to use unsupported method #~a" method))
       (method)]

@subsubsection{Authentication methods}

@subsubsub*section{None}

For this method, nothing happens. The server is already happy and there is no need to send authentication details. There is no additional data exchange.

@chunk[<method-none>
       (void)]

@subsubsub*section{Username/password}

This method is described in @hyperlink["https://datatracker.ietf.org/doc/html/rfc1929/" "RFC 1929, Username/Password Authentication for SOCKS V5"]:

@nested[#:style 'inset]{
Once the SOCKS V5 server has started, and the client has selected the
Username/Password Authentication protocol, the Username/Password
subnegotiation begins. This begins with the client producing a
Username/Password request:

@codeblock0{
+----+------+----------+------+----------+
|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
+----+------+----------+------+----------+
| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
+----+------+----------+------+----------+
}
}

The protocol says the username and password are transmitted in cleartext, which is a little surprising. At least it's easy for me to implement! Just be sure not to use that password for anything else...

@chunk[<method-username-password>
       (send (bytes 1))
       (send (bytes (bytes-length username)))
       (send username)
       (send (bytes (bytes-length password)))
       (send password)
       (flush-output)
       <receive-username-password-status>]

@nested[#:style 'inset]{
The server verifies the supplied UNAME and PASSWD, and sends the following response:

@codeblock0{
+----+--------+
|VER | STATUS |
+----+--------+
| 1  |   1    |
+----+--------+
}
}

Status 0 means success. The RFC has a chart of what the other numbers mean, if you were interested.

@chunk[<receive-username-password-status>
       (let* ([bs (expect 2)]
              [ver (bytes-ref bs 0)]
              [status (bytes-ref bs 1)])
         (unless (eq? ver 1)
           (error 'receive-username-password-status "server responded with unexpected version #~a" ver))
         (unless (eq? status 0)
           (error 'receive-username-password-status "server rejected username/password combination (status #~a)" ver)))]

@subsubsection{Connect to destination}

@subsubsub*section{Connect request}

@nested[#:style 'inset]{
Once the method-dependent subnegotiation has completed, the client
sends the request details.  If the negotiated method includes
encapsulation for purposes of integrity checking and/or
confidentiality, these requests MUST be encapsulated in the method-
dependent encapsulation.

The SOCKS request is formed as follows:

@codeblock0{
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
}

@itemlist[
@item{VER: Protocol version=5}
@item{CMD: Connect=1, Bind=2, UDP Associate=3}
@item{RSV: Reserved=0}
@item{ATYP: Address type: IPv4=1, IPv6=4, Fully-qualified domain name=3}
@item{DST-ADDR: Destination address}
@item{PORT: Destination port in network octet order}
]
}

For CMD, I will only implement Connect in this implementation. Connect is used in all circumstances, whereas Bind is only used with protocols that establish server-to-client connections like FTP, and UDP Associate is only used with UDP.

@chunk[<request-connect>
       (send (bytes 5 1 0))
       <send-destination-address>
       (send (integer->integer-bytes dest-port 2 #f #t))
       (flush-output)]

The destination address can be one of the following:

@itemlist[
@item{IPv4: Binary encoded address, 4 octets.}
@item{IPv6: Binary encoded address, 16 octets.}
@item{Fully-qualified domain name. First octet is the length of the name, then send the actual name.}
]

To make the end-user interface easier, my program will receive every type as a string (or bytes), and branch based on how the string is formatted. I will use the net/ip module to help.

@chunk[<make-addr>
       (define addr (with-handlers ([exn:fail:contract? (λ (_) #f)])
                      (make-ip-address dest-host)))]

Then, if it is an IP address, send it:

@chunk[<send-addr>
       [(ip-address? addr) (send (bytes (if (eq? (ip-address-version addr) 4) 1 4)))
                           (send (ip-address->bytes addr))]]

Otherwise, it's a domain name, so send that:

@chunk[<send-domain>
       [else (send (bytes 3 (string-length dest-host)))
             (send dest-host)]]

Putting the previous chunks together:

@chunk[<send-destination-address>
       <make-addr>
       (cond
         <send-addr>
         <send-domain>)]

@subsubsub*section{Connect response}

@nested[#:style 'inset]{
The server evaluates the request, and returns a reply formed as follows:

@codeblock0{
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
}
}

The complete connection is successful if Rep=0.

@chunk[<receive-connect>
       (let* ([bs (expect 4)]
              [ver (bytes-ref bs 0)]
              [rep (bytes-ref bs 1)]
              [addr-type (bytes-ref bs 3)])
         (unless (eq? ver 5)
           (error 'receive-connect "server responded with unexpected version #~a" ver))
         (unless (eq? rep 0)
           (error 'receive-connect "server rejected connection for reason #~a" rep))
         <read-server-bindings>)]

The server says which destination host and port it connected to, but I don't care, so I just read those bytes and throw them into the @racket[void].

@chunk[<read-server-bindings>
       (void 'server-binding-address
             (case addr-type
               [(1) (expect 4)]
               [(4) (expect 16)]
               [(3) (let ([bs (expect 1)])
                      (expect (bytes-ref bs 0)))]))
       (void 'server-binding-port
             (integer-bytes->integer (expect 2) #f #t))]

After this point, the connection is completed. The TCP ports act exactly as if they were directly connected to the destination, but in reality, the SOCKS server will be forwarding all data through the ports in both directions.

The SOCKS protocol does not support any more in-band messages, which means I can hand off the ports to the next protocol layer like HTTP without having to worry about escape codes or control being passed back to the SOCKS layer.

@subsection{Proxy for http-easy}

The http-easy library has a @seclink["Proxies" #:doc '(lib "net/http-easy.scrbl")]{proxies feature.} If a proxy is added to a session, then when http-easy needs to establish an HTTP connection, it will run the proxy's connect procedure instead of the usual @racket[http-conn-open!] code. After the connection is established, HTTP requests and responses are sent like normal through the ports without explicitly calling proxy code.

Writing this procedure was very difficult for me to get my head around, which is why I'm documenting it so verbosely. The http-easy library includes some @hyperlink["https://github.com/Bogdanp/racket-http-easy/blob/master/http-easy-lib/http-easy/private/proxy.rkt" "sample proxies"] which my code is based on.

First, I'll set up the scaffolding. @racket[make-proxy] is called with the desired @racket[matches?] function and the connect procedure. @racket[matches?] is called to determine whether a URL should be handled by this proxy.

@chunk[<make-socks5-proxy-body>
       (make-proxy matches? <λ-proxy-connect>)]

Now for the connect procedure. Normally with no proxy, these specific steps would be followed to establish a new HTTP connection:

@itemlist[
@item{A blank HTTP connection object @racket[http-conn?] is created. It starts with no state.}
@item{@racket[http-conn-open!] is called on the HTTP connection object to connect to a host. This basically just calls @racket[tcp-connect] to the destination host and port. If SSL should be used, it instead calls @racket[ssl-connect]. The HTTP connection object is mutated to store the newly established connection.}
@item{HTTP requests and responses may now be sent through the ports with functions like @racket[http-conn-send!].}
#:style 'ordered
]

For a proxy connection, step 2 is replaced. The proxy's connect procedure receives the blank HTTP connection object (as well as the destination URL and SSL context), opens the ports, does SSL negotiation on them if needed, then finally mutates the HTTP connection object's state. Once the procedure is done, the HTTP connection object is ready to rock.

I'll first define the signature and the parameter types of the proxy connect function.

@chunk[<λ-proxy-connect>
       (λ ([conn : HTTP-Connection] [u : URL] [ssl-ctx : SSL-Client-Context])
         <proxy-connect-body>)]

@itemlist[
@item{@racket[conn] is the @racket[http-conn?] object previously described.}
@item{@racket[u] is a @racket[url?] struct stating which HTTP server I really want to connect to.}
@item{@racket[ssl-ctx] is an @racket[ssl-client-context?] struct stating the parameters for the SSL connection, such as acceptable versions, ciphers, and certificate verification.}
]

The first step in the procedure is to determine where to connect to. This information is stored in @racket[u]. I also determine that SSL should be used iif the protocol is https://.

@chunk[<proxy-connect-body>
       (define main-stream-encrypted? (equal? (url-scheme u) "https"))
       (define target-host (cast (url-host u) String))
       (define target-port (cast (or (url-port u) (if main-stream-encrypted? 443 80)) Positive-Integer))]

Now I know where to connect to, I can establish the SOCKS connection and get my pair of ports.

@chunk[<proxy-connect-body>
       (define-values (in out)
         (socks5-connect socks-host socks-port target-host target-port #:username-password username-password))]

Finally, I open the HTTP connection on the provided HTTP connection object atop that pair of ports.

@chunk[<proxy-connect-body>
       (http-conn-open! conn
                        target-host #:port target-port
                        #:ssl? <ssl-and-tunnel-properties>)]

"But wait! Why are you calling @racket[http-conn-open!] when that procedure sets up a new, normal, not proxied connection?", I hear you ask. That's a very good and accurate question, but in this case, the @racket[#:ssl?] parameter is actually a misnomer. While it would normally accept an @racket[ssl-client-context?] and establish its own connection, it can also accept @racket[(list/c ssl-client-context? input-port? output-port? connection-abandon-procedure)]. In this case, it makes the connection atop the already-established input and output port. This is exactly what I want when I'm tunnelling the connection through those ports!

When SSL is not used, it really is as simple as making that list, with @racket[#f] for the context to indicate SSL is not used:

@chunk[<ssl-and-tunnel-properties>
       (cond [(not main-stream-encrypted?)
              (list #f
                    in
                    out
                    (λ (_) (close-input-port in) (close-output-port out)))]
             [else <establish-ssl-ports-for-https>])]

When SSL is used, @racket[http-conn-open!] won't do SSL for me, so I need to do it myself by calling @racket[ports->ssl-ports].

I need to set up @racket[ssl-ctx*] first, just to normalise whatever value I got in to be a real @racket[ssl-client-context?].

Specifying @racket[#:close-original #t] means when the SSL ports are closed, the underlying tunnel ports are also closed. Therefore I can just use @racket[ssl-abandon-port] for the @racket[connection-abandon-procedure].

@chunk[<establish-ssl-ports-for-https>
       (define ssl-ctx*
         (cond
           [(ssl-client-context? ssl-ctx) ssl-ctx]
           [(symbol? ssl-ctx) (ssl-make-client-context ssl-ctx)]
           [else (error 'make-socks5-proxy-connect! "don't know how to normalise ssl-ctx: ~v" ssl-ctx)]))
       (define-values (in* out*)
         (ports->ssl-ports in out
                           #:mode 'connect
                           #:context ssl-ctx*
                           #:close-original? #t
                           #:hostname target-host))
       (list ssl-ctx* in* out* ssl-abandon-port)]

To see how @racket[make-socks5-proxy] would be used in another application, @seclink["make-socks5-proxy-example"]{see examples.}

@subsection{Utilities}

@racket[send] just calls @racket[display]. If @racket[print-txrx?] is set, it also logs what was sent.

@chunk[<send>
       (provide print-txrx?)
       (define print-txrx? : (Parameter Boolean) (make-parameter #f))

       (: send ((U Bytes String) -> Void))
       (define (send x)
         (define y (if (bytes? x) x (string->bytes/latin-1 x)))
         (when (print-txrx?)
           (eprintf "--> ~a ~a~n" y (bytes->list y)))
         (display y))]

Racket's @racket[read-bytes] may return fewer bytes than requested if end-of-file is reached early. This function will quit with an error message if the server ends the response stream at an unexpected moment. If @racket[print-txrx?] is set, it also logs what was received.

@chunk[<expect>
       (: expect (Nonnegative-Integer -> Bytes))
       (define (expect n)
         (define res (read-bytes n))
         (when (print-txrx?)
           (eprintf "<-- ~a ~a~n" res (if (eof-object? res) "" (bytes->list res))))
         (define len (if (eof-object? res) 0 (bytes-length res)))
         (if (or (eof-object? res) (len . < . n))
             (error 'expect "expected ~a bytes, got ~a with early end-of-file" n len)
             res))]

@subsection{Requires}

This program depends on the following libraries:

@bold{net/ip (installable as net-ip-lib)}

@chunk[<require>
       (require/typed net/ip
         [#:opaque IP-Address ip-address?]
         [make-ip-address (String -> IP-Address)]
         [ip-address->bytes (IP-Address -> Bytes)]
         [ip-address-version (IP-Address -> (U 4 6))])]

@bold{net/http-easy (installable as http-easy-lib)}
@chunk[<require>
       (require/typed net/http-easy
         [#:opaque Proxy proxy?]
         [make-proxy (Proxy-Matches? Proxy-Connect! -> Proxy)])]

@bold{typed/net/url, typed/net/http-client typed/openssl (installable as typed-racket-more)}
@code{begin} is necessary to @hyperlink["https://docs.racket-lang.org/test.hl/index.html#%28part._.Avoiding_for-label%29" "avoid identifiers being loaded twice"].
@chunk[<require>
       (begin (require typed/net/url typed/net/http-client typed/openssl))
       (define-type Proxy-Matches? (URL -> Boolean))
       (define-type Proxy-Connect! (HTTP-Connection URL SSL-Client-Context -> Void))]

@bold{racket/tcp (included in base)}
@chunk[<require>
       (require racket/tcp)]

@subsection{Main chunk}

Assembling the pieces.

@chunk[<*>
       <require>
       <expect>
       <send>
       <provide>]

@chunk[<test>
       (module* test racket
         (require (submod ".."))
         (require net/http-easy openssl)
         (parameterize ([print-txrx? #t])
           (define p (make-socks5-proxy "127.0.0.1" 1080))
           (define s (make-session #:proxies (list p) #:ssl-context (ssl-make-client-context) #:pool-config (make-pool-config #:max-size 1 #:idle-timeout 5)))
           (define r (session-request s "http://127.0.0.1:8008"))
           (println (bytes-length (response-body r)))
           (define r2 (session-request s "https://example.com"))
           (println (bytes-length (response-body r2)))
           #;(begin
               (define-values (in out) (socks5-connect "127.0.0.1" 1080 "example.com" 8008))
               (displayln "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" out)
               (close-output-port out)
               (copy-port in (current-output-port)))))]

@section{Other Resources}

@itemlist[
@item{@hyperlink["https://datatracker.ietf.org/doc/html/rfc1928/" "RFC 1928, SOCKS Protocol Version 5"]}
@item{@hyperlink["https://datatracker.ietf.org/doc/html/rfc1929/" "RFC 1929, Username/Password Authentication for SOCKS V5"]}
@item{@hyperlink["https://en.wikipedia.org/wiki/SOCKS" "Wikipedia: SOCKS"]}
@item{@hyperlink["https://wiki.archlinux.org/title/Proxy_server#Web_proxy_options" "Arch Wiki: Proxy Server"]}
@item{@hyperlink["https://blog.zhaytam.com/2019/11/15/socks5-a-net-core-implementation-from-scratch/" "Socks5 – A .NET Core implementation from scratch"]}
]
