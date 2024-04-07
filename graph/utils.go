package graph

import (
	"context"
	"errors"
	"wisepath.adrianescat.com/graph/model"
)

func RequireAuthAndActivatedUser(ctx context.Context) (*model.User, error) {
	userFromCtx := ctx.Value("user").(*model.User)

	if userFromCtx == nil || userFromCtx.IsAnonymous() {
		return nil, errors.New("unauthorized")
	}

	if !userFromCtx.Activated {
		return nil, errors.New("user is not activated")
	}

	return userFromCtx, nil
}
