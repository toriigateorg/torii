DELETE FROM role_permissions WHERE permission IN ('settings.read', 'settings.update');
DROP TABLE IF EXISTS app_settings;
