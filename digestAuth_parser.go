package main

import (
	"fmt"
	"strings"
)

// WWW-Authenticate k/v map parser
type parserState interface {
	fmt.Stringer
}

// Parse an unquoted token. Branches to the next state without advancing the character pointer,
// since this stops on the first disallowed character for a token.
type parserStateParsingToken struct {
	Next func(string) (parserState, error)

	start int

	// determines whether the token parser is ready, i.e. it has found a non-whitespace character and
	// has determined the start of the token.
	ok bool
}

func (p *parserStateParsingToken) String() string {
	return fmt.Sprintf("%T[start=%d,ok=%v]", p, p.start, p.ok)
}

// Parse a delimiter, ignoring any whitespace.
type parserStateParsingDelimiter struct {
	Delim rune
	Next parserState
}

func (p *parserStateParsingDelimiter) String() string {
	return fmt.Sprintf("%T[delim=%c,next=%v]", p, p.Delim, p.Next)
}

// Branch (without advancing the character pointer) depending on the rune that is found, optionally
// ignoring whitespace.
type parserStateBranch struct {
	IgnoreWhitespace bool
	Next func(rune) parserState
}

func (p *parserStateBranch) String() string {
	return fmt.Sprintf("%T[ignoreWhitespace=%v]", p, p.IgnoreWhitespace)
}

// Parse a quoted value.
type parserStateParsingQuotedValue struct {
	ok, escape bool
	buf strings.Builder

	Next func(string) (parserState, error)
}

func (p *parserStateParsingQuotedValue) String() string {
	return fmt.Sprintf("%T[ok=%v,escape=%v,buf=%v]", p, p.ok, p.escape, p.buf.String())
}

var rfc2616Separators = "()<>@,;:\\\"/[]?={} \x09"

func isRfc2616Separator(r rune) bool {
	for _, sep := range rfc2616Separators {
		if sep == r {
			return true
		}
	}
	return false
}

// Creates a parser state that encapsulates all the steps necessary to parse a key and value
// into the `out` map.
func newParserStateParsingKey(out map[string]string) parserState {
	// a full entry is <token>=<token | quoted-value>

	// for a quoted string, the graph is:
	// parserStateParsingToken
	//   -> parserStateParsingDelimiter{delim='='}
	//   -> parserStateBranch (quote is matched)
	//   -> parserStateParsingQuotedValue
	//      -> parserStateParsingToken
	//      -> ...
	// for an unquoted string, the graph is:
	// parserStateParsingToken
	//   -> parserStateParsingDelimiter{delim='='}
	//   -> parserStateBranch (non-quote is matched)
	//   -> parserStateParsingToken
	//      -> parserStateParsingToken
	//      -> ...

	return &parserStateParsingToken{
		Next: func(key string) (parserState, error) {
			if _, ok := out[key]; ok {
				return nil, fmt.Errorf("duplicated key: %v", key)
			}

			commitValue := func(val string) (parserState, error) {
				out[key] = val

				// we expect ',' after a value, then another key
				return &parserStateParsingDelimiter{
					Delim: ',',
					Next: newParserStateParsingKey(out),
				}, nil
			}

			parseTokenOrQuotedString := &parserStateBranch{
				IgnoreWhitespace: true,
				Next: func(c rune) parserState {
					// determine whether this is a token or a quoted string
					if c == '"' {
						// quote delimited string
						return &parserStateParsingQuotedValue{
							Next: commitValue,
						}
					} else if !isRfc2616Separator(c) {
						// assume this is another token
						return &parserStateParsingToken{
							Next: commitValue,
						}
					} else {
						// unknown??
						return nil
					}
				},
			}

			parseEqualAndValue := &parserStateParsingDelimiter{
				Delim: '=',
				Next: parseTokenOrQuotedString,
			}

			return parseEqualAndValue, nil
		},
	}
}

// assumes that 'h' is already sanitized as necessary
func parseWWWAuthenticate(h string) (map[string]string, error) {
	// WWW-Authenticate: Digest realm="<snip>", domain="::",
	// 									 qop="auth", nonce="<snip>",
	// 									 opaque="", algorithm="MD5",stale="FALSE"
	// it would be acceptable to just:
	// - split by ',' here, it would work 99% of times
	// - just use regular expressions to extract individual fields
	// let's assume that the server is evil and can send something like realm="," or
	// realm="nonce="kaboom"", so we will manually parse the header token per token.
	if !strings.HasPrefix(h, "Digest") || len(h) > 512 { // arbitrary length limit
		return nil, fmt.Errorf("unexpected invalid header: %v", h)
	}

	rawParams := strings.TrimLeft(strings.TrimPrefix(h, "Digest"), " ")
	rawParamsRunes := []rune(rawParams)

	out := make(map[string]string)
	var ps parserState = newParserStateParsingKey(out)

	// parse runes
	for pos, char := range rawParams {
	again:
		switch s := ps.(type) {
		case *parserStateParsingToken:
			if !s.ok {
				if char == ' ' {
					// ignore initial whitespace (but not whitespace in the middle of the string)
					continue
				}
				s.ok = true
				s.start = pos
			}

			// stop on the first invalid character
			if char < 32 || isRfc2616Separator(char) {
				// ensure value would be valid
				if s.start == pos {
					goto parserFail
				}

				value := string(rawParamsRunes[s.start:pos])
				next, err := s.Next(value)

				if err != nil {
					return nil, err
				}

				ps = next

				// since token processing stops after finding the first invalid character, the next state
				// might depend on the character we're currently on. do not advance the character pointer
				// and run another processing step.
				goto again
			}
		case *parserStateParsingDelimiter:
			if char == ' ' { // whitespace is irrelevant for delimiters
				continue
			}

			if char != s.Delim {
				goto parserFail
			}

			ps = s.Next
		case *parserStateBranch:
			if s.IgnoreWhitespace && char == ' ' {
				continue
			}

			next := s.Next(char)

			if next == nil {
				goto parserFail
			}

			ps = next

			goto again
		case *parserStateParsingQuotedValue:
			// find initial quote
			if !s.ok {
				s.ok = true

				if char == '"' { // begin of string
					continue
				} else {
					goto parserFail
				}
			}

			if s.escape {
				// add to buffer without doing further processing
				s.escape = false
			} else if char == '\\' { // special case: escape symbol
				s.escape = true
				// do not add '\' to the buffer
				continue
			} else if char == '"' { // end of string
				value := s.buf.String()
				next, err := s.Next(value)

				if err != nil {
					return nil, err
				}

				ps = next
				continue
			}

			s.buf.WriteRune(char)
		}

		continue

		parserFail:
		return nil, fmt.Errorf("unexpected character at pos %d, state %v: %c", pos, ps, char)
	}

	if s, ok := ps.(*parserStateParsingDelimiter); !ok || s.Delim != ',' {
		return nil, fmt.Errorf("parser finished at end of string in invalid state %v", ps)
	}

	return out, nil
}
