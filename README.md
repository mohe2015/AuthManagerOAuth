# AuthManagerOAuth

Create accounts or login using OAuth

## Setup

1. install PHP composer
4. `composer install`

Once set up, running `composer test` will run automated code checks.

## Development

Add the extension to your development mediawiki instance and then open the top level mediawiki folder in Visual Studio Code. Then you should get more or less proper intellisense.

## Tests

The integration tests live in `tests/phpunit/integration/`. They run against a
real MediaWiki instance and database; the remote OAuth provider is simulated by
a small fake OAuth server that the tests start on localhost.

To run them locally, set up a checkout of MediaWiki core with this extension in
`extensions/AuthManagerOAuth` (a symlink works fine), install a wiki on SQLite
and run the database updates so the extension's table exists:

```shell
cd /path/to/mediawiki
composer install
composer install --working-dir=extensions/AuthManagerOAuth
php maintenance/install.php --dbtype sqlite --dbpath "$PWD/data" \
    --server http://localhost --scriptpath /w --pass testpass TestWiki Admin
echo 'wfLoadExtension( "AuthManagerOAuth" );' >> LocalSettings.php
php maintenance/update.php --quick
```

Then run the tests from the MediaWiki core checkout:

```shell
composer phpunit:entrypoint -- extensions/AuthManagerOAuth/tests/phpunit/
```

GitHub Actions runs the same tests against the `REL1_43` and `REL1_46`
branches of MediaWiki on every push and pull request.

## Documentation

https://www.mediawiki.org/wiki/Extension:AuthManagerOAuth
