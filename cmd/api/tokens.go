package main

import (
	"errors"
	"net/http"
	"time"

	"greenlight.natenine.com/internal/data"
	"greenlight.natenine.com/internal/validator"
)

func (app *application) createAuthenticationTokenHandler(w http.ResponseWriter, r *http.Request) {

	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := app.readJSON(w, r, &input)
	if err != nil {
		app.badBadRequestResponse(w, r, err)
		return
	}

	// To validate the email and password provided by the client
	v := validator.New()

	data.ValidateEmail(v, input.Email)
	data.ValidatePassowrdPlaintext(v, input.Password)

	if !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}

	// Lookup the user record based on that email
	user, err := app.models.Users.GetByEmail(input.Email)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			app.invalidCredentialsResponse(w, r)
		default:
			app.serveErrorResponse(w, r, err)
		}
		return
	}

	// Check if the password that was passed was the actual one used to signup
	match, err := user.Password.Matches(input.Password)
	if err != nil {
		app.serveErrorResponse(w, r, err)
		return
	}

	// If the password doesn't match
	if !match {
		app.invalidCredentialsResponse(w, r)
		return
	}

	// Now anything after is if the password is correct
	token, err := app.models.Tokens.New(user.ID, 24*time.Hour, data.ScopeAuthentication)
	if err != nil {
		app.serveErrorResponse(w, r, err)
		return
	}

	err = app.writeJSON(w, http.StatusCreated, envelope{"authentication_token": token}, nil)
	if err != nil {
		app.serveErrorResponse(w, r, err)
	}

}
