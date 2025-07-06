package authz_test

import (
	"slices"
	"testing"
	"time"

	"authz"
)

// Example types to test authorizations on
type User struct {
	UserID  string
	Team    string
	Roles   []string
	IsAdmin bool
}

type Resource struct {
	Owner   string
	Created time.Time
}

func initializeUserUserAuthorizer() *authz.Authorizer[User, User] {
	authUserUser := authz.NewAuthorizer[User, User]()

	// Can user1 delete user2?
	authUserUser.AddPolicy("delete", func(user1 User, user2 User) bool {
		// Admins cannot be deleted
		if user2.IsAdmin {
			return false
		}
		// Admins can delete other users
		if user1.IsAdmin {
			return true
		}
		// Non-admins cannot delete users
		return false
	})

	// Can user1 update user2's profile?
	authUserUser.AddPolicy("update:profile", func(user1 User, user2 User) bool {
		// Admins can update anyone's profile
		if user1.IsAdmin {
			return true
		}
		// Anyone can update their own profile
		if user1.UserID == user2.UserID {
			return true
		}
		// Profile moderators can update anyone's profile
		if slices.Contains(user1.Roles, "ProfileModerator") {
			return true
		}
		// Otherwise, people can't update each other's profiles
		return false
	})

	return authUserUser
}

func initializeUserResourceAuthorizer() *authz.Authorizer[User, Resource] {
	authUserResource := authz.NewAuthorizer[User, Resource]()

	authUserResource.AddPolicy("delete", func(user User, resource Resource) bool {
		// Admins can delete any resource
		if user.IsAdmin {
			return true
		}
		// Users can delete a resource they own
		if user.UserID == resource.Owner {
			return true
		}
		// Certain teams are allowed to delete these resources
		if user.Team == "ResourceManagers" {
			return true
		}
		// Users with a certain role are allowed to delete resources more than 30 days old
		if slices.Contains(user.Roles, "Archivist") && resource.Created.Before(time.Now().Add(-time.Hour*24*30)) {
			return true
		}
		return false
	})

	return authUserResource
}

func TestUserUserAuthorizer(t *testing.T) {
	auth := initializeUserUserAuthorizer()

	tests := []struct {
		name     string
		user1    User
		user2    User
		action   string
		expected bool
	}{
		// Test deletes
		{
			name:     "can't delete admin",
			user1:    User{IsAdmin: true},
			user2:    User{IsAdmin: true},
			action:   "delete",
			expected: false,
		},
		{
			name:     "admin can delete non-admin",
			user1:    User{IsAdmin: true},
			user2:    User{IsAdmin: false},
			action:   "delete",
			expected: true,
		},
		{
			name:     "non-admin cannot delete",
			user1:    User{IsAdmin: false},
			user2:    User{},
			action:   "delete",
			expected: false,
		},

		// Test profile updates
		{
			name:     "admin can update any profile",
			user1:    User{IsAdmin: true},
			user2:    User{},
			action:   "update:profile",
			expected: true,
		},
		{
			name:     "anyone can update their own profile",
			user1:    User{UserID: "user1"},
			user2:    User{UserID: "user1"},
			action:   "update:profile",
			expected: true,
		},
		{
			name:     "non-admins cannot update other profiles",
			user1:    User{UserID: "user1"},
			user2:    User{UserID: "user2"},
			action:   "update:profile",
			expected: false,
		},
		{
			name:     "ProfileModerators can update any profile",
			user1:    User{Roles: []string{"ProfileModerator"}},
			user2:    User{},
			action:   "update:profile",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := auth.Enforce(tt.user1, tt.action, tt.user2)
			if actual != tt.expected {
				t.Errorf(
					"Enforce(%#v, %s, %#v) got %v, want %v",
					tt.user1, tt.action, tt.user2, actual, tt.expected,
				)
			}
		})
	}
}

func TestUserResourceAuthorizer(t *testing.T) {
	auth := initializeUserResourceAuthorizer()

	tests := []struct {
		name     string
		user     User
		resource Resource
		action   string
		expected bool
	}{
		{
			name:     "admins can delete any resource",
			user:     User{UserID: "user1", IsAdmin: true},
			resource: Resource{Owner: "user2"},
			action:   "delete",
			expected: true,
		},
		{
			name:     "users can delete any resource they own",
			user:     User{UserID: "user1"},
			resource: Resource{Owner: "user1"},
			action:   "delete",
			expected: true,
		},
		{
			name:     "users cannot delete a resource they do not own",
			user:     User{UserID: "user1"},
			resource: Resource{Owner: "user2"},
			action:   "delete",
			expected: false,
		},
		{
			name:     "users on the ResourceManagers team can delete any resource",
			user:     User{UserID: "user1", Team: "ResourceManagers"},
			resource: Resource{Owner: "user2"},
			action:   "delete",
			expected: true,
		},
		{
			name:     "users with the Archivist role can delete any resource more than 30 days old",
			user:     User{UserID: "user1", Roles: []string{"Archivist"}},
			resource: Resource{Owner: "user2", Created: time.Now().Add(-time.Hour * 24 * 31)},
			action:   "delete",
			expected: true,
		},
		{
			name:     "users with the Archivist role cannot delete any resource less than 30 days old",
			user:     User{UserID: "user1", Roles: []string{"Archivist"}},
			resource: Resource{Owner: "user2", Created: time.Now().Add(-time.Hour * 24 * 25)},
			action:   "delete",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := auth.Enforce(tt.user, tt.action, tt.resource)
			if actual != tt.expected {
				t.Errorf(
					"Enforce(%#v, %s, %#v) got %v, want %v",
					tt.user, tt.action, tt.resource, actual, tt.expected,
				)
			}
		})
	}
}
