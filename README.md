# simple-argon2

[![CircleCI](https://circleci.com/gh/mdouchement/simple-argon2.svg?style=shield)](https://circleci.com/gh/mdouchement/simple-argon2)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/mdouchement/simple-argon2)
[![Go Report Card](https://goreportcard.com/badge/github.com/mdouchement/simple-argon2)](https://goreportcard.com/report/github.com/mdouchement/simple-argon2)
[![License](https://img.shields.io/github/license/mdouchement/simple-argon2.svg)](http://opensource.org/licenses/MIT)

simple-argon2 provides a convenience wrapper around Go's existing [argon2](http://golang.org/x/crypto/argon2) (formaly `argon2id`) package that makes it easier to securely derive strong keys ("hash user passwords").

It is strongly inspired of [github.com/elithrar/simple-scrypt](https://github.com/elithrar/simple-scrypt) package (source code, comments & readme).

The API closely mirrors Go's [bcrypt](http://golang.org/x/crypto/bcrypt) library in an effort to make it easy to migrate—and because it's an easy to grok API.

## Usage

```sh
go get github.com/mdouchement/simple-argon2
```

```go
package main

import (
  "fmt"
  "log"

  argon2 "github.com/mdouchement/simple-argon2"
)

func main() {
  hashed, err := argon2.GenerateFromPasswordString("42password42", argon2.Default)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(hashed)
  // $argon2id$v=19$m=65536,t=3,p=2$/lASHr1GVXVkV/628wFUVGqINrLbWo7v86TjaooJmUY$igyAvrODju4SsBSefcYOzMaLl9xGjSkjsY1tnaKaTxk

  err = argon2.CompareHashAndPasswordString(hashed, "42password42")
  if err != nil {
    // Invalid password
    log.Fatal(err)
  }

  // Valid password
}
```

## License

**MIT**

## Contributing

All PRs are welcome.

1. Fork it
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
5. Push to the branch (git push origin my-new-feature)
6. Create new Pull Request

As possible, run the following commands to format and lint the code:

```sh
# Format
find . -name '*.go' -exec gofmt -s -w {} \;

# Lint
golangci-lint run -c .golangci.yml
```
