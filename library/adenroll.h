/*
 * adcli
 *
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#ifndef ADENROLL_H_
#define ADENROLL_H_

#include "adconn.h"

typedef enum {
	ADCLI_ENROLL_NO_KEYTAB = 1 << 1,
	ADCLI_ENROLL_ALLOW_OVERWRITE = 1 << 2,
	ADCLI_ENROLL_PASSWORD_VALID = 1 << 3,
	ADCLI_ENROLL_ADD_SAMBA_DATA = 1 << 4,
	ADCLI_ENROLL_LDAP_PASSWD = 1 << 5,
	ADCLI_ENROLL_RECURSIVE_DELETE = 1 << 6,
} adcli_enroll_flags;

typedef struct _adcli_enroll adcli_enroll;

adcli_result       adcli_enroll_prepare                 (adcli_enroll *enroll,
                                                         adcli_enroll_flags flags);

adcli_result       adcli_enroll_load                    (adcli_enroll *enroll);

adcli_result       adcli_enroll_join                    (adcli_enroll *enroll,
                                                         adcli_enroll_flags join_flags);

adcli_result       adcli_enroll_update                  (adcli_enroll *enroll,
		                                         adcli_enroll_flags flags);

adcli_result       adcli_enroll_read_computer_account   (adcli_enroll *enroll,
                                                         adcli_enroll_flags flags);

adcli_result       adcli_enroll_show_computer_attribute (adcli_enroll *enroll);

adcli_result       adcli_enroll_delete                  (adcli_enroll *enroll,
                                                         adcli_enroll_flags delete_flags);

adcli_result       adcli_enroll_password                (adcli_enroll *enroll);

adcli_enroll *     adcli_enroll_new                     (adcli_conn *conn);

adcli_enroll *     adcli_enroll_ref                     (adcli_enroll *enroll);

void               adcli_enroll_unref                   (adcli_enroll *enroll);

const char *       adcli_enroll_get_host_fqdn           (adcli_enroll *enroll);

void               adcli_enroll_set_host_fqdn           (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_computer_name       (adcli_enroll *enroll);

void               adcli_enroll_set_computer_name       (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_computer_password   (adcli_enroll *enroll);

void               adcli_enroll_set_computer_password   (adcli_enroll *enroll,
                                                         const char *host_password);

void               adcli_enroll_reset_computer_password (adcli_enroll *enroll);

const char *       adcli_enroll_get_domain_ou           (adcli_enroll *enroll);

void               adcli_enroll_set_domain_ou           (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_computer_dn         (adcli_enroll *enroll);

void               adcli_enroll_set_computer_dn         (adcli_enroll *enroll,
                                                         const char *value);

const char **      adcli_enroll_get_service_names       (adcli_enroll *enroll);

void               adcli_enroll_set_service_names       (adcli_enroll *enroll,
                                                         const char **value);

void               adcli_enroll_add_service_name        (adcli_enroll *enroll,
                                                         const char *value);

const char **      adcli_enroll_get_service_principals  (adcli_enroll *enroll);

void               adcli_enroll_set_service_principals  (adcli_enroll *enroll,
                                                         const char **value);

const char **      adcli_enroll_get_service_principals_to_add (adcli_enroll *enroll);
void               adcli_enroll_add_service_principal_to_add (adcli_enroll *enroll,
                                                              const char *value);

const char **      adcli_enroll_get_service_principals_to_remove (adcli_enroll *enroll);
void               adcli_enroll_add_service_principal_to_remove (adcli_enroll *enroll,
                                                                 const char *value);

const char *       adcli_enroll_get_user_principal      (adcli_enroll *enroll);

void               adcli_enroll_set_user_principal      (adcli_enroll *enroll,
                                                         const char *value);

void               adcli_enroll_auto_user_principal     (adcli_enroll *enroll);

unsigned int       adcli_enroll_get_computer_password_lifetime (adcli_enroll *enroll);
void               adcli_enroll_set_computer_password_lifetime (adcli_enroll *enroll,
                                                         unsigned int lifetime);

bool               adcli_enroll_get_trusted_for_delegation (adcli_enroll *enroll);
void               adcli_enroll_set_trusted_for_delegation (adcli_enroll *enroll,
                                                            bool value);

bool               adcli_enroll_get_dont_expire_password (adcli_enroll *enroll);
void               adcli_enroll_set_dont_expire_password (adcli_enroll *enroll,
                                                          bool value);

bool               adcli_enroll_get_account_disable     (adcli_enroll *enroll);
void               adcli_enroll_set_account_disable     (adcli_enroll *enroll,
                                                         bool value);

const char *       adcli_enroll_get_desciption          (adcli_enroll *enroll);
void               adcli_enroll_set_description         (adcli_enroll *enroll,
                                                         const char *value);

const char **      adcli_enroll_get_setattr             (adcli_enroll *enroll);
adcli_result       adcli_enroll_add_setattr             (adcli_enroll *enroll,
                                                         const char *value);

const char **      adcli_enroll_get_delattr             (adcli_enroll *enroll);
adcli_result       adcli_enroll_add_delattr             (adcli_enroll *enroll,
                                                         const char *value);

bool               adcli_enroll_get_is_service          (adcli_enroll *enroll);
void               adcli_enroll_set_is_service          (adcli_enroll *enroll,
                                                         bool value);

krb5_kvno          adcli_enroll_get_kvno                (adcli_enroll *enroll);

void               adcli_enroll_set_kvno                (adcli_enroll *enroll,
                                                         krb5_kvno value);

krb5_keytab        adcli_enroll_get_keytab              (adcli_enroll *enroll);

const char *       adcli_enroll_get_keytab_name         (adcli_enroll *enroll);

void               adcli_enroll_set_keytab_name         (adcli_enroll *enroll,
                                                         const char *value);

adcli_result       adcli_enroll_add_keytab_for_service_account (adcli_enroll *enroll);

krb5_enctype *     adcli_enroll_get_keytab_enctypes     (adcli_enroll *enroll);

void               adcli_enroll_set_keytab_enctypes     (adcli_enroll *enroll,
                                                         krb5_enctype *enctypes);

krb5_enctype *     adcli_enroll_get_permitted_keytab_enctypes (adcli_enroll *enroll);

const char *       adcli_enroll_get_os_name             (adcli_enroll *enroll);

void               adcli_enroll_set_os_name             (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_os_version          (adcli_enroll *enroll);

void               adcli_enroll_set_os_version          (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_os_service_pack     (adcli_enroll *enroll);

void               adcli_enroll_set_os_service_pack     (adcli_enroll *enroll,
                                                         const char *value);

void               adcli_enroll_set_samba_data_tool     (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_samba_data_tool     (adcli_enroll *enroll);

#endif /* ADENROLL_H_ */
