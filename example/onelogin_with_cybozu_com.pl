use strict;
use warnings;
use utf8;
use Carp;
use Encode;
use JSON qw/encode_json decode_json/;
use YAML;
use Web::Scraper;
use WebService::Onelogin;
use WebService::CybozuCom; #see also. https://github.com/Likk/WebService-CybozuCom

my $cybozu_domain          = 'example';
my $onelogin_domain        = 'example';
my $username               = 'user';
my $password               = 'password';
my $https_pkcs12_file      = 'path/to/your/P12/file.P12';
my $https_pkcs12_password  = 'pkcs12_password';

my $onelogin = WebService::Onelogin->new(
    domain                => $onelogin_domain,
    username              => $username,
    password              => $password,
    https_pkcs12_file     => $https_pkcs12_file,
    https_pkcs12_password => $https_pkcs12_password,
);
$onelogin->login();

my $cybozu = WebService::CybozuCom->new(
    domain => $cybozu_domain,
);

$cybozu->{mech} = $onelogin->{mech};
{ #saml request and responce.

    my $request_token = $cybozu->request_token();
    $cybozu->post_json(
        sprintf("%s/api/saml/request.json?_lc=ja_JP", $cybozu->base_url),
        +{
            requestedResourceUrl => sprintf("%s/", $cybozu->base_url),
            __REQUEST_TOKEN__    => $cybozu->request_token,
        }
    );
    $cybozu->get(decode_json($cybozu->last_content)->{result}->{redirectUrl});
    my $scraper = scraper {
        process '//form',                        url   => '@action';
        process '//input[@name="SAMLResponse"]', saml  => '@value';
        result qw/url saml /;
    };
    my $result = $scraper->scrape($cybozu->last_content);
    my $url    = delete $result->{url};
    $cybozu->post($url, { SAMLResponse => $result->{saml}, RelayState => $result->{relay} });
}
my $schedule = $cybozu->show_schedule();
warn YAML::Dump $schedule;
