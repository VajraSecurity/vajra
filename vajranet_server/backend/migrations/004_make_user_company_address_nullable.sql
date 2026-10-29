-- Registration does not collect company/address (users join an existing org),
-- so these columns must accept NULL for newly created accounts.

ALTER TABLE vajra_users
ALTER COLUMN company DROP NOT NULL,
ALTER COLUMN address DROP NOT NULL;
