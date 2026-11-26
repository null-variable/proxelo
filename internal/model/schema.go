package model

import _ "embed"

// SchemaJSON is the JSON Schema of every resource spec, generated from this
// package by schemagen.go.
//
//go:embed schema.json
var SchemaJSON []byte
