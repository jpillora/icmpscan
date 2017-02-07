# icmpscan

ICMPv4 scan all hosts across a number of subnets in Go (golang)

### Programmatic Usage

[![GoDoc](https://godoc.org/github.com/jpillora/icmpscan?status.svg)](https://godoc.org/github.com/jpillora/icmpscan)

```go
hosts, err := icmpscan.Run(icmpscan.Spec{
	Hostnames: true,
	MACs:      true,
	Log:       true,
})
```

### CLI

**Binaries**

Download [the latest release](https://github.com/jpillora/icmpscan/releases/latest), or

Install latest release now with `curl https://i.jpillora.com/icmpscan! | bash`

**Source**

``` sh
$ go get -v github.com/jpillora/icmpscan
```

```
$ icmpscan --help

  Usage: icmpscan [options] [networks...]

  <networks> is a list of subnets to scan (defaults to all interface subnets)

  Options:
  --interface, -i   Source interface (default chosen by OS)
  --timeout, -t     Scan timeout (default 1s)
  --dns-server, -d  Server to perform reverse DNS lookups against (defaults to X.X.X.1)
  --json, -j        Output results in JSON
  --log, -l         Log actions to stderr
  --help, -h
  --version, -v

  Version:
    0.0.0-src
```

#### MIT License

Copyright © 2017 Jaime Pillora &lt;dev@jpillora.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.