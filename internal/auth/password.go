package auth

import (
	"github.com/inovex/backend-demo-evilginx/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// VerifyPassword reports whether password matches the user's stored hash.
func VerifyPassword(u *store.User, password string) bool {
	return bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)) == nil
}

// HasTOTP reports whether the user has a second factor enrolled.
func HasTOTP(u *store.User) bool {
	return u.TOTPSecret != ""
}
