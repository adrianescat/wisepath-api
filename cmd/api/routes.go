package main

import (
	"database/sql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
	"net/http"
	"wisepath.adrianescat.com/graph"
	"wisepath.adrianescat.com/graph/dataloaders"
	"wisepath.adrianescat.com/graph/model"
)

func (app *app) routes(db *sql.DB) http.Handler {
	router := httprouter.New()
	router.NotFound = http.HandlerFunc(app.notFoundResponse)
	router.MethodNotAllowed = http.HandlerFunc(app.methodNotAllowedResponse)

	loader := dataloaders.NewDataLoader(&model.UserModel{DB: db})

	gql := handler.NewDefaultServer(graph.NewExecutableSchema(graph.Config{Resolvers: &graph.Resolver{
		Models: model.NewModels(db),
		Logger: app.logger,
	}}))

	plg := playground.Handler("GraphQL playground", "/query")

	router.Handle(http.MethodPost, "/query", func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		gql.ServeHTTP(w, req)
	})

	router.Handle(http.MethodGet, "/", func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		plg.ServeHTTP(w, req)
	})

	standard := alice.New(app.recoverPanic, app.logRequest, secureHeaders, app.enableCORS, app.authenticate)

	// wrap the query handler with middleware to inject dataloader
	dataloaderMiddleware := dataloaders.Middleware(loader, router)

	return standard.Then(dataloaderMiddleware)
}
