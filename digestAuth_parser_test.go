package main

import (
	"reflect"
	"testing"
)

func TestDigestAuthParser_Standard(t *testing.T) {
	input := `Digest token="value", hello="world", nonce="nonce"`
	expected := map[string]string {
		"token": "value",
		"hello": "world",
		"nonce": "nonce",
	}

	if got, err := parseWWWAuthenticate(input); err != nil || !reflect.DeepEqual(expected, got) {
		t.Fatalf("parseWWWAuthenticate(%q) = %v, %v - wanted %v", input, got, err, expected)
	}
}

func TestDigestAuthParser_Unquoted(t *testing.T) {
	input := `Digest token="value", hello=world, nonce="nonce"`
	expected := map[string]string {
		"token": "value",
		"hello": "world",
		"nonce": "nonce",
	}

	if got, err := parseWWWAuthenticate(input); err != nil || !reflect.DeepEqual(expected, got) {
		t.Fatalf("parseWWWAuthenticate(%q) = %v, %v - wanted %v", input, got, err, expected)
	}
}

func TestDigestAuthParser_EscapedCharacters(t *testing.T) {
	input := `Digest token="a\"b", hello="world"`
	expected := map[string]string {
		"token": `a"b`,
		"hello": "world",
	}

	if got, err := parseWWWAuthenticate(input); err != nil || !reflect.DeepEqual(expected, got) {
		t.Fatalf("parseWWWAuthenticate(%q) = %v, %v - wanted %v", input, got, err, expected)
	}
}

func TestDigestAuthParser_Comma(t *testing.T) {
	input := `Digest token="value1,value2", hello="world"`
	expected := map[string]string {
		"token": "value1,value2",
		"hello": "world",
	}

	if got, err := parseWWWAuthenticate(input); err != nil || !reflect.DeepEqual(expected, got) {
		t.Fatalf("parseWWWAuthenticate(%q) = %v, %v - wanted %v", input, got, err, expected)
	}
}

func TestDigestAuthParser_Evil(t *testing.T) {
	input := `Digest token="value1\",\"value2\"", hello=",,world\""`
	expected := map[string]string {
		"token": `value1","value2"`,
		"hello": `,,world"`,
	}

	if got, err := parseWWWAuthenticate(input); err != nil || !reflect.DeepEqual(expected, got) {
		t.Fatalf("parseWWWAuthenticate(%q) = %v, %v - wanted %v", input, got, err, expected)
	}
}

func TestDigestAuthParser_Invalid(t *testing.T) {
	invalidInputs := []string{
		``,
		`Digest`,
		`Digest ,token="value", hello=world, nonce="nonce"`,
		`Digest token="", hello="world, nonce="nonce",`,
		`Digest token=""", hello=world, nonce="nonce",`,
		`Digest token=""", hello="world, nonce="nonce",`,
		`Digest token="value", hello=world, nonce="nonce",`,
		`Digest token="value", hello=world, nonce="nonce", `,
	}

	for _, input := range invalidInputs {
		if got, err := parseWWWAuthenticate(input); err == nil {
			t.Fatalf("parseWWWAuthenticate(%q) = %v, %v - wanted error", input, got, err)
		}

	}
}
