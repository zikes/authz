/*
Package authz implements code-based authorization. Note that authorization
does not include authentication in any way.

By defining the access policies as code, testing and assertions become easier to
implement. Additionally, the code to define the policies may be collected into
a single place in the code, allowing for easier auditing and simplifying the
areas of code where they were previously written.

# Usage

Create an [Authorizer] via [NewAuthorizer], then provide it with a series of
policies to be enforced. An individual Authorizer only deals with
authorizations between two defined types (or the same type twice).

This creates an Authorizer to handle User access to a given Resource.

	auth := authz.NewAuthorizer[User, Resource]()

The Authorizer is then populated with policies via the [Authorizer.AddPolicy]
method. Policies are defined by an action string and an [Effector]. The Effector
returns true if access is permitted or false if it is denied.

	// Can User "delete" Resource?
	auth.AddPolicy("delete", func(user User, resource Resource) bool {
		if user.IsAdmin {
			return true
		}
		if resource.Owner == user.ID {
			return true
		}
		return false
	})

Once a series of policies has been loaded into the Authorizer, they may be
enforced via the [Authorizer.Enforce] method.

	if auth.Enforce(someUser, "delete", someResource) {
		// Delete someResource
	} else {
		// Access denied
	}
*/
package authz

// Effector is a type of function which determines whether an action is allowed
// given the values of two types. They are the code equivalent of authorization
// policies.
type Effector[T any, T2 any] func(T, T2) bool

// Authorizer is a collection of Effectors for a pair of given types and their
// actions.
type Authorizer[T any, T2 any] struct {
	Policies map[string]Effector[T, T2]
}

// NewAuthorizer instantiates a new Authorizer for the given types.
func NewAuthorizer[T any, T2 any]() *Authorizer[T, T2] {
	return &Authorizer[T, T2]{
		Policies: map[string]Effector[T, T2]{},
	}
}

// AddPolicy associates an Effector with an action. If an Effector already
// exists for a given action then AddPolicy will panic.
func (a *Authorizer[T, T2]) AddPolicy(
	action string,
	effect Effector[T, T2],
) {
	if _, ok := a.Policies[action]; ok {
		panic("a policy already exists for action " + action)
	}

	a.Policies[action] = effect
}

// Enforce will run the Effector for a given action. If no Effector is found
// then the appropriate policy is assumed to be missing and a panic is thrown.
func (a *Authorizer[T, T2]) Enforce(subject T, action string, resource T2) bool {
	if _, ok := a.Policies[action]; !ok {
		panic("no policies for action " + action)
	}

	fn := a.Policies[action]

	return fn(subject, resource)
}
