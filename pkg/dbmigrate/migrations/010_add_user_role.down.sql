-- Rollback: remove role column from users.
ALTER TABLE users DROP COLUMN role;
