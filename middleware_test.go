package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func authTestRouter(token string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/protected", bearerTokenAuthMiddleware(token), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return router
}

func TestBearerTokenAuthMiddleware(t *testing.T) {
	tests := []struct {
		name            string
		configuredToken string
		authorization   string
		wantStatus      int
	}{
		{name: "missing deployment token fails closed", wantStatus: http.StatusServiceUnavailable},
		{name: "missing authorization", configuredToken: "secret", wantStatus: http.StatusUnauthorized},
		{name: "wrong token", configuredToken: "secret", authorization: "Bearer wrong", wantStatus: http.StatusUnauthorized},
		{name: "wrong scheme", configuredToken: "secret", authorization: "Basic secret", wantStatus: http.StatusUnauthorized},
		{name: "valid token", configuredToken: "secret", authorization: "Bearer secret", wantStatus: http.StatusNoContent},
		{name: "case insensitive scheme", configuredToken: "secret", authorization: "bearer secret", wantStatus: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.authorization != "" {
				request.Header.Set("Authorization", tt.authorization)
			}

			authTestRouter(tt.configuredToken).ServeHTTP(recorder, request)
			assert.Equal(t, tt.wantStatus, recorder.Code)
		})
	}
}
