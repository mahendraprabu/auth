package auth

import "fmt"

// declare errors
var (
	ErrorUserNotFound    = fmt.Errorf("user not found")
	ErrorUserExists      = fmt.Errorf("user already exists")
	ErrorGroupNotFound   = fmt.Errorf("group not found")
	ErrorGroupExists     = fmt.Errorf("group already exists")
	ErrorRoleNotFound    = fmt.Errorf("role not found")
	ErrorRoleExists      = fmt.Errorf("role already exists")
	ErrorUnAuthorized    = fmt.Errorf("unauthorized")
	ErrorInvalidPassword = fmt.Errorf("invalid password")
)

type User struct {
	ID       int
	Username string
	Password string
	Email    string
	Groups   []Group
	Roles    []Role
}

type Group struct {
	ID          int
	Name        string
	Description string
	Roles       []Role
}

type Role struct {
	ID          int
	Name        string
	Description string
}

type AuthStore interface {
	FindUserByID(id int) (*User, error)
	FindUserByUsername(username string) (*User, error)
	FindUserByEmail(email string) (*User, error)
	CreateUser(user *User) error
	UpdateUser(user *User) error
	Authenticate(username, password string) (*User, error)
	Authorize(user *User, role string) bool
	AuthorizeGroup(user *User, group string) bool
}
