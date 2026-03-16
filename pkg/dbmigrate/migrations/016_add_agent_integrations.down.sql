-- Rollback: remove allowed_integrations column from user_agents.
ALTER TABLE user_agents DROP COLUMN allowed_integrations;
