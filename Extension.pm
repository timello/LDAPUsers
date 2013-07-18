# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

package Bugzilla::Extension::LDAPUsers;

use 5.10.1;
use strict;
use parent qw(Bugzilla::Extension);

our $VERSION = '0.01';

use Bugzilla::Util qw(generate_random_password
                      trick_taint clean_text);

use Net::LDAP::Util qw(escape_filter_value);
use Storable qw(dclone);


BEGIN {
    no warnings 'redefine';
    *Bugzilla::has_ldap_enabled = \&_bugzilla_has_ldap_enabled;
    *Bugzilla::User::_ldapusers_orig_match_field
        = \&Bugzilla::User::match_field;
    *Bugzilla::User::match_field = \&_ldapusers_user_match_field;
};

sub _bugzilla_has_ldap_enabled {
    my $class = shift;
    return Bugzilla->params->{user_verify_class} =~ /LDAP/ ? 1 : 0;
}

sub _ldapusers_user_match_field {
    my ($fields, $data, $behavior) = @_;

    # That means we are attaching something and a FileHandler is open
    # and it is not serializable by dclone.
    my $input_params = Bugzilla->input_params;
    if (!exists Bugzilla->input_params->{'contenttypeselection'}) {  
        # We backup input_params because match_fields deletes
        # some fields.
        $input_params = dclone(Bugzilla->input_params);
    }

    # We first try to match existent Bugzilla users.
    my ($retval, $non_conclusive_fields)
        = Bugzilla::User::_ldapusers_orig_match_field(
            $fields, $data, Bugzilla::User->MATCH_SKIP_CONFIRM);

    #XXX
    foreach my $field (@{ $non_conclusive_fields || [] }) {
        Bugzilla->input_params->{$field} = $input_params->{$field};
    }

    # Then we try LDAP users.
    if ($retval == Bugzilla::User->USER_MATCH_FAILED
        and Bugzilla->has_ldap_enabled)
    {
       _search_for_ldap_user_and_create($non_conclusive_fields, $data);
    }

    # And finally, we call match_field again after possibly adding
    # new LDAP users.
    return Bugzilla::User::_ldapusers_orig_match_field(@_);
}

sub _search_for_ldap_user_and_create {
    my ($fields, $data) = @_;
    $data ||= Bugzilla->input_params;

    # Based on Bugzilla::User::match_field code
    foreach my $field (@{ $fields || [] }) {
        next unless defined $data->{$field};

        # Concatenate login names, so that we have a common
        # way to handle them.
        my $raw_field;
        if (ref $data->{$field}) {
            $raw_field = join(",", @{$data->{$field}});
        }
        else {
            $raw_field = $data->{$field};
        }
        $raw_field = clean_text($raw_field || '');

        my @queries =  split(/[,;]+/, $raw_field);
        _create_ldap_user_if_exists($_) foreach @queries;
    }
}

sub _create_ldap_user_if_exists {
    my ($username) = @_;
    my $ldap = Bugzilla->ldap;

    $username = escape_filter_value($username);

    my $uid_attrib  = Bugzilla->params->{LDAPuidattribute};
    my $mail_attrib = Bugzilla->params->{LDAPmailattribute};
    my @attrs = ($uid_attrib, $mail_attrib, 'displayName', 'cn');
    my $result = $ldap->search(( base => Bugzilla->params->{LDAPBaseDN},
                                 scope => 'sub',
                                 filter => "$mail_attrib=$username" ),
                               attrs => \@attrs);

    ThrowCodeError('ldap_search_error',
        errstr => $result->error, username => $username) if $result->code;

    # We just want the rigth match.
    return if $result->count != 1;

    my $entry = $result->shift_entry;
    my $uid   = $entry->get_value($uid_attrib);
    my $email = $entry->get_value($mail_attrib);
    my $realname ||= $entry->get_value("displayName");
    $realname    ||= $entry->get_value("cn");

    # User already exists in Bugzilla.
    my $bugz_user = new Bugzilla::User({ extern_id => $uid });
    return if defined $bugz_user;

    my $password = generate_random_password();
    trick_taint($password);

    my $ldap_user = Bugzilla::User->create({
        realname      => $realname,
        login_name    => $email,
        cryptpassword => $password,
        extern_id     => $uid });

    return $ldap_user;
}

__PACKAGE__->NAME;
