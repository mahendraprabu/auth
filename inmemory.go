package auth

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// InMemoryAuthStore provides an in-memory implementation of AuthStore
type InMemoryAuthStore struct {
	Users  map[int]*User
	Groups map[int]*Group
	Roles  map[int]*Role
}

func NewInMemoryAuthStore() *InMemoryAuthStore {
	return &InMemoryAuthStore{
		Users:  make(map[int]*User),
		Groups: make(map[int]*Group),
		Roles:  make(map[int]*Role),
	}
}

func NewInMemoryAuthStoreFromBackup(filename string) *InMemoryAuthStore {
	s := NewInMemoryAuthStore()
	s.Restore(filename)
	return s
}

func (s *InMemoryAuthStore) CreateGroup(group *Group) error {
	if _, ok := s.Groups[group.ID]; ok {
		return fmt.Errorf("group already exists")
	}
	s.Groups[group.ID] = group
	return nil
}

func (s *InMemoryAuthStore) CreateRole(role *Role) error {
	if _, ok := s.Roles[role.ID]; ok {
		return fmt.Errorf("role already exists")
	}
	s.Roles[role.ID] = role
	return nil
}

func (s *InMemoryAuthStore) UpdateRole(role *Role) error {
	if _, ok := s.Roles[role.ID]; !ok {
		return fmt.Errorf("role does not exist")
	}
	s.Roles[role.ID] = role
	return nil
}

func (s *InMemoryAuthStore) CreateUser(user *User) error {
	if _, ok := s.Users[user.ID]; ok {
		return fmt.Errorf("user already exists")
	}
	s.Users[user.ID] = user
	return nil
}

func (s *InMemoryAuthStore) UpdateUser(user *User) error {
	if _, ok := s.Users[user.ID]; !ok {
		return ErrorUserNotFound
	}
	s.Users[user.ID] = user
	return nil
}

func (s *InMemoryAuthStore) FindUserByID(id int) (*User, error) {
	if user, ok := s.Users[id]; ok {
		return user, nil
	}
	return nil, ErrorUserNotFound
}

func (s *InMemoryAuthStore) FindUserByUsername(username string) (*User, error) {
	for _, user := range s.Users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, ErrorUserNotFound
}

func (s *InMemoryAuthStore) FindUserByEmail(email string) (*User, error) {
	for _, user := range s.Users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, ErrorUserNotFound
}

// Authenticate authenticates a user by their username and password
func (s *InMemoryAuthStore) Authenticate(username, password string) (*User, error) {
	user, err := s.FindUserByUsername(username)
	if err != nil {
		return nil, ErrorUserNotFound
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, ErrorInvalidPassword
	}
	return user, nil
}

func (s *InMemoryAuthStore) Authorize(user *User, role string) bool {
	for _, r := range user.Roles {
		if r.Name == role {
			return true
		}
	}

	for _, g := range user.Groups {
		for _, r := range g.Roles {
			if r.Name == role {
				return true
			}
		}
	}

	return false
}

func (s *InMemoryAuthStore) AuthorizeGroup(user *User, group string) bool {
	for _, g := range user.Groups {
		if g.Name == group {
			return true
		}
	}
	return false
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Backup writes the in-memory data to a file
func (s *InMemoryAuthStore) Backup(filename string) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

// Restore reads the in-memory data from a file
func (s *InMemoryAuthStore) Restore(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, s)
	if err != nil {
		return err
	}
	return nil
}
