package main

import (
	"context"
	"net/http"
	"wisepath.adrianescat.com/graph/model"
)

// The contextSetUser() method returns a new copy of the request with the provided
// User struct added to the context. Note that we use our userContextKey constant as the
// key.
func (app *app) contextSetUser(r *http.Request, user *model.User) *http.Request {
	ctx := context.WithValue(r.Context(), "user", user)
	return r.WithContext(ctx)
}

// The contextGetUser() retrieves the User struct from the request context. The only
// time that we'll use this helper is when we logically expect there to be User struct
// value in the context, and if it doesn't exist it will firmly be an 'unexpected' error.
// As we discussed earlier in the book, it's OK to panic in those circumstances.
func (app *app) contextGetUser(r *http.Request) *model.User {
	user, ok := r.Context().Value("user").(*model.User)
	if !ok {
		panic("missing user value in request context")
	}
	return user
}
