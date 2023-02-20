# racket-socks5

This library makes TCP connections via SOCKS5 proxy servers.

- [Library Documentation](https://docs.racket-lang.org/socks5/Provides.html)
- [Weaved Code](https://docs.racket-lang.org/socks5/Source.html)
- [Package Entry](https://pkgd.racket-lang.org/pkgn/package/socks5)

## Story

The program is written using a literate programming style. Literate programming makes documentation just as important as code, and you can read about its principles on literateprogramming.com. This was my first time using literate programming. I'm using the [hyper-literate](https://docs.racket-lang.org/hyper-literate/index.html) implementation, with Typed Racket as the programming language. I definitely wouldn't use literate programming for every task, but it was extremely useful in this situation for the following reasons:

When writing `socks5-connect`, the protocol is specified in an RFC, so my task is to implement that spec in Typed Racket. I did this by first reading the specification from start to end and figuring out which parts were relevant to me. Then I went through it again, for each relevant paragraph from the RFC, I copied it into my document and wrote the corresponding code chunk. This made it easy to verify that my code matched the spec at each step. [You can see the code here.](https://docs.racket-lang.org/socks5/SOCKS_connection_process.html)

When writing `make-socks5-proxy`, integrating with http-easy proxies had no spec to follow, so I instead had to do some reverse engineering through the http-easy source as well as the Racket source. I prototyped my code inside a single chunk. Once I figured out the code flow and got my prototype working, I moved it into chunks and explained each chunk, so that if I forget later I can look at my documentation. I feel that standard code comments wouldn't have cut it in this case, because there's so much to understand compared to the relatively short implementation, and none of Racket's HTTP library is concisely described. [You can see my explanations here.](https://docs.racket-lang.org/socks5/Proxy_for_http-easy.html)

This was an interesting project! I learned a lot about an unfamiliar programming technique which turned out to be a great match for the problem. I also hope to use my SOCKS5 library in my other projects, so if there are any bugs, I should be able to find and fix them.

## Contact

Feel free to get in touch with whatever you'd like to know.

Suggestions and code changes can be emailed to me or opened on GitHub, whichever you prefer.

https://cadence.moe/contact
