package auth

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"time"

	"github.com/inovex/backend-demo-evilginx/internal/store"
)

// pushTTL bounds how long a passwordless push approval request stays valid.
const pushTTL = 2 * time.Minute

// BeginPush creates a passwordless push approval request for the user, sets a
// short-lived cookie identifying it on the polling browser, and returns the
// match number to display on the sign-in screen.
func (a *Auth) BeginPush(w http.ResponseWriter, u *store.User) int {
	match := NewMatchNumber()
	req := a.Store.CreatePushRequest(u.ID, u.Username, match, pushTTL)
	a.setCookie(w, pushCookie, req.ID, int(pushTTL.Seconds()))
	return match
}

// PendingPush returns the push request referenced by the browser's cookie, if
// it still exists and has not expired.
func (a *Auth) PendingPush(r *http.Request) (*store.PushRequest, bool) {
	c, err := r.Cookie(pushCookie)
	if err != nil {
		return nil, false
	}
	req, ok := a.Store.PushByID(c.Value)
	if !ok || time.Now().After(req.ExpiresAt) {
		return nil, false
	}
	return req, true
}

// ClearPush removes the push request and its cookie once it has been consumed.
func (a *Auth) ClearPush(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(pushCookie); err == nil {
		a.Store.DeletePushRequest(c.Value)
	}
	a.clearCookie(w, pushCookie)
}

// NewMatchNumber returns a random two-digit number used for number matching.
func NewMatchNumber() int { return randRange(10, 99) }

// NumberChoices returns the match number plus two distinct decoys, in random
// order, for the authenticator's number-matching prompt. Approving with the
// wrong number denies the request — exactly as real number matching behaves.
func NumberChoices(match int) []int {
	nums := []int{match}
	for len(nums) < 3 {
		n := randRange(10, 99)
		dup := false
		for _, m := range nums {
			if m == n {
				dup = true
				break
			}
		}
		if !dup {
			nums = append(nums, n)
		}
	}
	// Fisher–Yates shuffle so the match isn't always first.
	for i := len(nums) - 1; i > 0; i-- {
		j := randRange(0, i)
		nums[i], nums[j] = nums[j], nums[i]
	}
	return nums
}

// randRange returns a uniformly random int in [min, max] using crypto/rand.
func randRange(min, max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		// crypto/rand failing is unrecoverable; for a demo, panic is fine.
		panic(err)
	}
	return min + int(n.Int64())
}
