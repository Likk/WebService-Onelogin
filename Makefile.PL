use inc::Module::Install;
name 'WebService-Onelogin';
all_from 'lib/WebService/Onelogin.pm';

# requires '';

tests 't/*.t';
author_tests 'xt';

test_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
