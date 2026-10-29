-- Primary DB
-- Per-user avatar: built-in avatar id (1-4) or 999 = custom uploaded image.
-- avatar_image holds a small (<=200KB) base64 data URL, served only to its owner.
ALTER TABLE vajra_users ADD COLUMN IF NOT EXISTS avatar_id    INTEGER NOT NULL DEFAULT 1;
ALTER TABLE vajra_users ADD COLUMN IF NOT EXISTS avatar_image TEXT;
