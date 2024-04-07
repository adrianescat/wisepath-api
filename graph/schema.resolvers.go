package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.45

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"wisepath.adrianescat.com/graph/model"
	"wisepath.adrianescat.com/internal/validator"
)

// CreateUser is the resolver for the createUser field.
func (r *mutationResolver) CreateUser(ctx context.Context, input model.NewUserInput) (*model.User, error) {
	user := &model.User{
		Name:      input.Name,
		Lastname:  input.LastName,
		Email:     input.Email,
		Activated: false,
	}

	err := user.Password.Set(input.Password)
	if err != nil {
		return nil, err
	}

	v := validator.New()

	if model.ValidateUser(v, user); !v.Valid() {
		return nil, errors.New("wrong inputs")
	}

	err = r.Models.Users.Insert(user)

	if err != nil {
		r.Logger.PrintError(fmt.Errorf("%s", err), nil)
		return nil, err
	}

	return user, nil
}

// CreateAuthToken is the resolver for the createAuthToken field.
func (r *mutationResolver) CreateAuthToken(ctx context.Context, input model.AuthTokenInput) (*model.AuthTokenResponse, error) {
	// Validate the email and password provided by the client.
	v := validator.New()

	model.ValidateEmail(v, input.Email)
	model.ValidatePasswordPlaintext(v, input.Password)

	if !v.Valid() {
		return nil, errors.New("email and Password should be valid")
	}

	user, err := r.Models.Users.GetByEmail(input.Email)

	if err != nil {
		switch {
		case errors.Is(err, model.ErrRecordNotFound):
			return nil, errors.New("invalid credentials")
		default:
			return nil, errors.New("server error")
		}
	}

	// Check if the provided password matches the actual password for the user.
	match, err := user.Password.Matches(input.Password)
	if err != nil {
		return nil, errors.New("server error")
	}

	if !match {
		return nil, errors.New("invalid credentials")
	}

	token, err := r.Models.Tokens.New(user.ID, 24*time.Hour, model.ScopeAuthentication)
	if err != nil {
		return nil, errors.New("server error")
	}

	return &model.AuthTokenResponse{
		AuthenticationToken: &model.AuthToken{
			Key:    token.Plaintext,
			Expire: token.Expiry,
		},
	}, nil
}

// LogOut is the resolver for the logOut field.
func (r *mutationResolver) LogOut(ctx context.Context, userID string) (*model.LogoutResponse, error) {
	_, err := RequireAuthAndActivatedUser(ctx)
	if err != nil {
		return nil, err
	}

	uId, err := strconv.ParseInt(userID, 10, 64)
	if err != nil {
		return nil, errors.New("wrong profile id type")
	}

	err = r.Models.Tokens.DeleteAllForUser(model.ScopeAuthentication, uId)

	if err != nil {
		r.Logger.PrintError(fmt.Errorf("%s", err), nil)
		return nil, err
	}

	return &model.LogoutResponse{
		Success: true,
	}, nil
}

// Users is the resolver for the users field.
func (r *queryResolver) Users(ctx context.Context) ([]*model.User, error) {
	users, err := r.Models.Users.GetAll()

	if err != nil {
		r.Logger.PrintError(fmt.Errorf("%s", err), nil)
		return nil, err
	}

	return users, nil
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
