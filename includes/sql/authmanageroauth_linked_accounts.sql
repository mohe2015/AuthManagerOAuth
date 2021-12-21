CREATE TABLE /*_*/authmanageroauth_linked_accounts(
    amoa_provider VARCHAR(255) NOT NULL,
    amoa_local_user INTEGER UNSIGNED NOT NULL,
    amoa_remote_user VARCHAR(255) NOT NULL,
    PRIMARY KEY(amoa_provider, amoa_local_user, amoa_remote_user)
)/*$wgDBTableOptions*/;

CREATE INDEX amoa_local_index ON /*_*/authmanageroauth_linked_accounts (amoa_local_user);
CREATE INDEX amoa_remote_index ON /*_*/authmanageroauth_linked_accounts (amoa_provider,amoa_remote_user);
