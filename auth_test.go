package auth_test

import (
	"testing"

	"github.com/mahendraprabu/auth"
	"github.com/stretchr/testify/assert"
)

func TestInMemoryAuthStore(t *testing.T) {
	store := auth.NewInMemoryAuthStore()

	role1 := &auth.Role{
		ID:          1,
		Name:        "admin",
		Description: "Administrator",
	}
	role2 := &auth.Role{
		ID:          2,
		Name:        "user",
		Description: "Regular user",
	}
	store.Roles[role1.ID] = role1
	store.Roles[role2.ID] = role2

	group1 := &auth.Group{
		ID:   1,
		Name: "admins",
		Roles: []auth.Role{
			*role1,
		},
	}
	group2 := &auth.Group{
		ID:   2,
		Name: "users",
		Roles: []auth.Role{
			*role2,
		},
	}
	store.Groups[group1.ID] = group1
	store.Groups[group2.ID] = group2

	// Add some test data
	pass1, _ := auth.HashPassword("password456")
	pass2, _ := auth.HashPassword("password789")

	user1 := &auth.User{
		ID:       1,
		Username: "john",
		Password: pass1,
		Email:    "john@example.com",
		Groups:   []auth.Group{*group1},
		Roles:    []auth.Role{*role1, *role2},
	}

	user2 := &auth.User{
		ID:       2,
		Username: "jane",
		Password: pass2,
		Email:    "jane@example.com",
		Groups:   []auth.Group{*group2},
		Roles:    []auth.Role{*role2},
	}
	store.Users[user1.ID] = user1
	store.Users[user2.ID] = user2

	// Test FindUserByID
	foundUser, err := store.FindUserByID(user1.ID)
	assert.NoError(t, err)
	assert.Equal(t, user1, foundUser)

	// Test FindUserByUsername
	foundUser, err = store.FindUserByUsername(user2.Username)
	assert.NoError(t, err)
	assert.Equal(t, user2.ID, foundUser.ID)

	// Test FindUserByEmail
	foundUser, err = store.FindUserByEmail(user1.Email)
	assert.NoError(t, err)
	assert.Equal(t, user1.ID, foundUser.ID)

	// Test Authenticate
	authUser, err := store.Authenticate(user1.Username, "password456")
	if err != nil {
		t.Error(err)
	}

	assert.Equal(t, user1.Username, authUser.Username)

	// Test Authorize
	assert.True(t, store.Authorize(user1, role1.Name))
	assert.True(t, store.Authorize(user1, role2.Name))

	// Test AuthorizeGroup
	assert.True(t, store.AuthorizeGroup(user1, group1.Name))
	assert.False(t, store.AuthorizeGroup(user1, group2.Name))

}
