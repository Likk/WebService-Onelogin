package WebService::Onelogin;

=encoding utf8

=head1 NAME

  WebService::Onelogin - onelogin.com client for perl.

=head1 SYNOPSIS

  use WebService::Onelogin
  use File::Slurp;
  my $ua = WWW::Mechanize->new(agent => 'Mozilla/5.0', cookie_jar => {});
  my $c  = WebService::Onelogin->new(
    mech                  => $ua,
    domain                => 'your group name',
    username              => 'your username',
    password              => 'your password',
    https_pkcs12_file     => 'path/to/your/P12/file.P12',
    HTTPS_PKCS12_PASSWORD => read_file('/path/to/your/PIN/file.PIN'),
  );

  $c->login();

  $c->mech->post('http://onelogin.com/saml/request', { SAMLRequest  => $result->{saml}, RelayState => $result->{relay} });
  $c->mech->post('http://example.com/saml/responce', { SAMLResponse => $result->{saml}, RelayState => $result->{relay} });

=head1 DESCRIPTION

  WebService::Onelogin is scraping library client for perl at onelogin.com

=cut

use strict;
use warnings;
use utf8;
use Carp;
use Encode;
use JSON qw/encode_json decode_json/;
use Web::Scraper;
use WWW::Mechanize;
use YAML;

our $VERSION = '1.00';

=head1 CONSTRUCTOR AND STARTUP

=head2 new

Creates and returns a new onelogin.com object.

=cut

sub new {
    my $class = shift;
    my %args = @_;

    my $self = bless { %args }, $class;

    $self->{last_req} ||= time;
    $self->{interval} ||= 1;

    $self->mech();
    if($self->{https_pkcs12_file}){
        $ENV{HTTPS_PKCS12_FILE}     = $self->{https_pkcs12_file};
        $ENV{HTTPS_PKCS12_PASSWORD} = $self->{https_pkcs12_password} || '';
    }

    return $self;
}

=head1 Accessor

=over

=item B<mech>

  WWW::Mechanize object.

=cut

sub mech {
    my $self = shift;
    my $ua   = shift;
    unless($self->{mech}){
        my $mech = WWW::Mechanize->new(
            agent      => 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.89 Safari/537.36',
            cookie_jar => {},
        );
        $mech->stack_depth(10);
        $self->{mech} = $mech;
    }
    elsif($ua){
        $ua->stack_depth(10);
        $self->{mech} = $ua;
    }
    return $self->{mech};
}

=item B<interval>

sleeping time per one action by mech.

=item B<last_request_time>

request time at last;

=item B<last_content>

cache at last decoded content.

=cut

sub interval          { return shift->{interval} ||= 1    }
sub last_request_time { return shift->{last_req} ||= time }

sub last_content {
    my $self = shift;
    my $arg  = shift || '';

    if($arg){
        $self->{last_content} = $arg
    }
    return $self->{last_content} || '';
}

=item B<base_url>

=cut

sub base_url {
    my $self = shift;
    my $arg  = shift || '';

    if($arg){
        $self->{base_url} = $arg;
        $self->{conf}     = undef;
    }
    return $self->{base_url} || sprintf('https://%s.onelogin.com', $self->{domain});
}

=back

=head1 METHODS

=head2 set_last_request_time

set request time

=cut

sub set_last_request_time { shift->{last_req} = time }


=head2 post

mech post with interval.

=cut

sub post {
    my $self = shift;
    $self->_sleep_interval;
    my $res = $self->mech->post(@_);
    return $self->_content($res);
}

=head2 post_json

mech post json content with interval.

=cut
sub post_json {
    my $self  = shift;
    my $url   = shift;
    my $param = shift;
    $self->_sleep_interval;
    my $res = $self->mech->post($url,
        'Content-Type' => 'application/json',
        'Content'      => encode_json($param),
    );
    return $self->_content($res);
}

=head2 get

mech get with interval.

=cut

sub get {
    my $self = shift;
    $self->_sleep_interval;
    my $res = $self->mech->get(@_);
    return $self->_content($res);
}

=head2 conf

  url path config

=cut

sub conf {
    my $self = shift;
    unless ($self->{conf}){
        my $base_url =  $self->base_url();
        my $conf = {
            top       => $base_url,
            pre_login => sprintf("%s/login",        $base_url),
            login     => sprintf("%s/sessions",     $base_url),
            apps      => sprintf("%s/client/apps",  $base_url),
        };
        $self->{conf} = $conf;
    }
    return $self->{conf};
}


=head2 login

  sign in at onelogin.com

=cut

sub login {
    my $self = shift;

    {
        $self->get($self->conf->{pre_login});
        my $token = $self->_parse_token();
        my $params = {
            authenticity_token => $token,
            email              => $self->{username},
            password           => $self->{password},
        };

        my $header  = {
            'X-Requested-With'     => 'XMLHttpRequest',
            'X-Prototype-Version'  => '1.6.0.3',
             Host                  => 'mfac.onelogin.com',
             Accept                => 'text/javascript, text/html, application/xml, text/xml, */*',
            'Content-Type'         => 'application/x-www-form-urlencoded; charset=UTF-8',
        };

        for my $key (keys %$header ){
            $self->mech->add_header($key => $header->{$key});
        }

        $self->post($self->conf->{login}, $params);

        for my $key (keys %$header ){
            $self->mech->delete_header($key);
        }

        if($self->last_content =~ m{window.location.href\s=\s"(.*?)";}){
            my $verify_cert = $1;
            $self->get($verify_cert);
        }
        $self->get($self->conf->{top});
        $self->get($self->conf->{apps});
    }
}


=head1 PRIVATE METHODS.

=over

=cut

sub _parse_token {
    my $self = shift;
    my $scraper = scraper {
        process '//input[@id="auth_token"]', token => '@value';
        result 'token';
    };
    return $scraper->scrape($self->last_content);
}

=item B<_sleep_interval>

interval for http accessing.

=cut

sub _sleep_interval {
    my $self = shift;
    my $wait = $self->interval - (time - $self->last_request_time);
    sleep $wait if $wait > 0;
    $self->set_last_request_time();
}

=item b<_content>

decode content with mech.

=cut

sub _content {
    my $self = shift;
    my $res  = shift;
    my $content = $res->decoded_content();
    $self->last_content($content);
    return $content;
}

=back

=cut

=head1 AUTHOR

likkradyus E<lt>perl {at} li.que.jpE<gt>

=head1 SEE ALSO

L<WWW::Mechanize>,
L<http://onelogin.com>,
L<RFC 7522 Security Assertion Markup Language>,

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
