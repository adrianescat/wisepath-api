//go:generate go run github.com/99designs/gqlgen generate

package graph

import (
	"sync"
	"wisepath.adrianescat.com/graph/model"
	"wisepath.adrianescat.com/internal/jsonlog"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	Models model.Models
	Logger *jsonlog.Logger
	Wg     sync.WaitGroup
}
