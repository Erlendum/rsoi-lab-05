package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"log/slog"
	"net/http"
	"strings"
)

const (
	authorizationHeader = "Authorization"
	bearerPrefix        = "Bearer "
	userClaim           = "preferred_username"
)

const (
	tokenCtxKey = "token"
	userCtxKey  = "user"
)

func GetToken(ctx context.Context) string {
	value, _ := ctx.Value(tokenCtxKey).(string)
	return value
}
func SetToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenCtxKey, token)
}
func GetUser(ctx context.Context) string {
	value, _ := ctx.Value(userCtxKey).(string)
	return value
}
func SetUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userCtxKey, user)
}

func Middleware(jwksURI string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token, ok := getBearerToken(c)
			if !ok {
				slog.Warn("no bearer token in request header")
				return c.NoContent(http.StatusUnauthorized)
			}
			user, err := getUserFromToken(token, jwksURI)
			if err != nil {
				slog.Warn("unable to get user from token", "error", err)
				return c.NoContent(http.StatusUnauthorized)
			}
			ctx := c.Request().Context()
			ctx = SetToken(ctx, token)
			ctx = SetUser(ctx, user)
			c.SetRequest(c.Request().WithContext(ctx))
			return next(c)
		}
	}
}

func getBearerToken(c echo.Context) (string, bool) {
	header := c.Request().Header.Get(authorizationHeader)
	if header == "" {
		return "", false
	}
	if !strings.HasPrefix(header, bearerPrefix) {
		return "", false
	}
	return strings.TrimPrefix(header, bearerPrefix), true
}

func getUserFromToken(rawToken, jwksURI string) (string, error) {
	jwks, err := keyfunc.Get(jwksURI, keyfunc.Options{})
	if err != nil {
		return "", fmt.Errorf("get keyfunc: %w", err)
	}
	token, err := jwt.Parse(rawToken, jwks.Keyfunc)
	if err != nil {
		return "", fmt.Errorf("parse jwt: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token type")
	}
	user, ok := claims[userClaim].(string)
	if !ok {
		return "", errors.New("invalid user claim")
	}
	return user, nil
}
