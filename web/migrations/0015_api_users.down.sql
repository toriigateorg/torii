DELETE FROM role_permissions WHERE permission IN
    ('api_users.create', 'api_users.read', 'api_users.update', 'api_users.delete');

DROP TABLE IF EXISTS api_user_roles;
DROP TABLE IF EXISTS api_users;
