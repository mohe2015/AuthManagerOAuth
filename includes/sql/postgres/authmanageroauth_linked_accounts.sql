CREATE TABLE /*_*/authmanageroauth_linked_accounts(
    -- the provider name
    amoa_provider VARCHAR(255) NOT NULL,

    -- the local user id
    amoa_local_user INTEGER NOT NULL,

    -- the remote user identifier
    amoa_remote_user VARCHAR(255) NOT NULL,

    PRIMARY KEY(amoa_provider, amoa_local_user, amoa_remote_user)
)/*$wgDBTableOptions*/;

-- used for searching linked accounts by local user
CREATE INDEX amoa_local_index ON /*_*/authmanageroauth_linked_accounts (amoa_local_user);

-- used for searching all local accounts liked with a remote account
CREATE INDEX amoa_remote_index ON /*_*/authmanageroauth_linked_accounts (amoa_provider,amoa_remote_user);
