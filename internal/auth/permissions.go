package auth

const (
	PermUsersCreate = "users.create"
	PermUsersRead   = "users.read"
	PermUsersUpdate = "users.update"
	PermUsersDelete = "users.delete"

	PermRolesCreate = "roles.create"
	PermRolesRead   = "roles.read"
	PermRolesUpdate = "roles.update"
	PermRolesDelete = "roles.delete"

	PermUserRolesCreate = "user_roles.create"
	PermUserRolesRead   = "user_roles.read"
	PermUserRolesDelete = "user_roles.delete"

	PermRoleServicesCreate = "role_services.create"
	PermRoleServicesRead   = "role_services.read"
	PermRoleServicesDelete = "role_services.delete"

	PermServicesCreate = "services.create"
	PermServicesRead   = "services.read"
	PermServicesUpdate = "services.update"
	PermServicesDelete = "services.delete"

	PermTokensRead   = "tokens.read"
	PermTokensDelete = "tokens.delete"

	PermPermissionsRead = "permissions.read"

	PermSSOCreate = "sso.create"
	PermSSORead   = "sso.read"
	PermSSOUpdate = "sso.update"
	PermSSODelete = "sso.delete"

	PermSettingsRead   = "settings.read"
	PermSettingsUpdate = "settings.update"

	PermAuditRead = "audit.read"
)

var AllPermissions = []string{
	PermUsersCreate, PermUsersRead, PermUsersUpdate, PermUsersDelete,
	PermRolesCreate, PermRolesRead, PermRolesUpdate, PermRolesDelete,
	PermUserRolesCreate, PermUserRolesRead, PermUserRolesDelete,
	PermRoleServicesCreate, PermRoleServicesRead, PermRoleServicesDelete,
	PermServicesCreate, PermServicesRead, PermServicesUpdate, PermServicesDelete,
	PermTokensRead, PermTokensDelete,
	PermPermissionsRead,
	PermSSOCreate, PermSSORead, PermSSOUpdate, PermSSODelete,
	PermSettingsRead, PermSettingsUpdate,
	PermAuditRead,
}

var permissionSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(AllPermissions))
	for _, p := range AllPermissions {
		m[p] = struct{}{}
	}
	return m
}()

func IsValidPermission(p string) bool {
	_, ok := permissionSet[p]
	return ok
}
