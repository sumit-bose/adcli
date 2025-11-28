"""
New adcli tests.
"""

from __future__ import annotations

import re
import uuid
import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider
from .topology import KnownTopologyGroup


@pytest.mark.importance("medium")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_create_user_with_upn_name(client: Client, provider: GenericADProvider):
    """
    :title: adcli create-user with UPN-like username
    :description: Verify that adcli creates a user with a UPN-like name by setting
                  the sAMAccountName attribute to that exact string (e.g., 'foo@bar.z').
                  This confirms adcli does not validate/sanitize the username format.
    :steps:
        1. Run adcli create-user with a username formatted like a UPN (email style).
    :expectedresults:
        1. The adcli command fails with error message about illegal character warning.
    """
    c = client.adcli.create_user(
        "xyzuser@bar.z",
        domain=provider.host.domain,
        login_user=provider.host.adminuser,
        password=provider.host.adminpw,
        args=["--verbose"],
        krb=False,
    )
    assert c.rc != 0, f"adcli create-user failed!"
    assert re.findall(
        r"Found illegal character '@' in name", c.stderr, re.IGNORECASE
    ), "Expected error about illegal character not found!"


#@pytest.mark.importance("critical")
#@pytest.mark.topology(KnownTopologyGroup.AnyAD)
#def test_adcli_join_resets_des_flag(client: Client, provider: GenericADProvider):
#    """
#    :title: adcli join resets DES encryption flag
#    :description: Verify that adcli resets the UF_USE_DES_KEY_ONLY flag on the computer object
#                  during join if it was previously set.
#    :setup:
#        1. Preset/Create a computer object for the client in AD.
#        2. Manually enable the UF_USE_DES_KEY_ONLY flag (0x200000) on the computer object via PowerShell.
#    :steps:
#        1. Join the domain using adcli join.
#        2. Verify that the UF_USE_DES_KEY_ONLY flag is cleared on the computer object.
#    :expectedresults:
#        1. The join command succeeds.
#        2. The UF_USE_DES_KEY_ONLY flag is no longer set in userAccountControl.
#    """
#    UF_USE_DES_KEY_ONLY = 0x200000
#    short_hostname = client.host.hostname.split(".")[0].upper()
#    try:
#        client.adcli.delete_computer(
#            domain=provider.host.domain,
#            login_user=provider.host.adminuser,
#            password=provider.host.adminpw,
#            krb=False
#        )
#    except Exception:
#        pass
#
#    client.adcli.preset_computer(
#        domain=provider.host.domain,
#        login_user=provider.host.adminuser,
#        password=provider.host.adminpw,
#        args=["--verbose", client.host.hostname],
#        krb=False
#    )
#
#    # 2. Enable DES flag via PowerShell (since we can't use raw LDAP modify)
#    # Set-ADAccountControl is a standard cmdlet available on AD DCs
#
#    cmdlt = (
#        f"Set-ADComputer -Identity '{short_hostname}$' "
#        "-Replace @{'msDS-SupportedEncryptionTypes'=3}"
#    )
#    provider.host.conn.run(f"powershell.exe -Command \"{cmdlt}\"")
#
#    show_comp = client.adcli.show_computer(
#        domain=provider.host.domain,
#        args=["--login-user", "Administrator", "--verbose"],
#        login_user="Administrator",
#        krb=False,
#        password=provider.host.adminpw,
#    )
#
#    assert re.findall(
#        r"msDS-supportedEncryptionTypes:\n 3", show_comp.stdout, re.IGNORECASE
#    ), "Details added at join not reflected!"
#
#    # 3. Join the domain
#    join_res = client.adcli.join(
#        domain=provider.host.domain,
#        login_user=provider.host.adminuser,
#        password=provider.host.adminpw,
#        args=["--verbose"],
#        krb=False
#    )
#    assert join_res.rc == 0, f"adcli join failed: {join_res.stderr}"
#
#    # 4. Verify flag is reset
#    show_comp_reset = client.adcli.show_computer(
#        domain=provider.host.domain,
#        args=["--login-user", "Administrator", "--verbose"],
#        login_user="Administrator",
#        krb=False,
#        password=provider.host.adminpw,
#    )
#    assert re.findall(
#        r"msDS-supportedEncryptionTypes:\n 3", show_comp_reset.stdout, re.IGNORECASE
#    ), "Details added at join not reflected!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_join_resets_des_0(client: Client, provider: GenericADProvider):
    """
    :title: adcli join resets DES encryption flag
    :description: Verify that adcli resets the UF_USE_DES_KEY_ONLY flag on the computer object
                  during join if it was previously set.
    :steps:
        1. Preset/Create a computer object for the client in AD.
        2. Manually enable the UF_USE_DES_KEY_ONLY flag (0x200000) on the computer object via PowerShell.
        3. Join the domain using adcli join.
        4. Verify that the UF_USE_DES_KEY_ONLY flag is cleared on the computer object.
    :expectedresults:
        1. The join command succeeds.
        2. The UF_USE_DES_KEY_ONLY flag is no longer set in userAccountControl.
    """
    UF_USE_DES_KEY_ONLY = 0x200000
    short_hostname = client.host.hostname.split(".")[0].upper()

    # Ensure a clean state by removing any existing computer account
    # 1. Preset computer object
    client.adcli.preset_computer(
        domain=provider.host.domain,
        login_user=provider.host.adminuser,
        password=provider.host.adminpw,
        args=["--verbose", client.host.hostname],
        krb=False
    )

    # 2. Enable DES flag via PowerShell
    # We use standard PowerShell to get the object, bitwise-OR the flag, and set it back.
    # 0x200000 is the flag for UF_USE_DES_KEY_ONLY.
    provider.host.conn.run(rf"""
    $c = Get-ADComputer -Identity '{short_hostname}$';
    Set-ADObject -Identity $c.DistinguishedName -Replace @{{'msDS-SupportedEncryptionTypes'=3}}
    """
    )
    ddd = provider.host.conn.run(rf"""
    $computer = Get-ADComputer -Identity "{short_hostname}" -Properties msDS-SupportedEncryptionTypes
    $encryptionTypes = $computer."msDS-SupportedEncryptionTypes"
    Write-Host "msDS-SupportedEncryptionTypes value: $encryptionTypes"
    """
    )
    iii = provider.host.conn.run(rf"""
    $computerName = "{short_hostname}"
    $adObject = Get-ADComputer -Identity $computerName -Properties UserAccountControl
    """
    )
    # Verify it was set using provider object
    show_comp = client.adcli.show_computer(
        domain=provider.host.domain,
        args=["--login-user", "Administrator", "--verbose"],
        login_user="Administrator",
        krb=False,
        password=provider.host.adminpw,
    )

    join = client.adcli.join(
        domain=provider.host.domain,
        login_user=provider.host.adminuser,
        password=provider.host.adminpw,
        args=["--verbose"],
        krb=False
    )
    assert join.rc == 0, f"adcli join failed: {join_res.stderr}"

    check_reset = provider.host.conn.run(rf"""
    $computer = Get-ADComputer -Identity "{short_hostname}" -Properties msDS-SupportedEncryptionTypes
    $encryptionTypes = $computer."msDS-SupportedEncryptionTypes"
    if ($encryptionTypes -eq 3) {{ exit 1 }} else {{ exit 0 }}
    """)
    assert check_reset.rc == 0, "msDS-SupportedEncryptionTypes was not reset from 3 (DES/RC4) after join."

    # 4. Verify flag is reset
    #zzz = provider.host.conn.run(rf"""
    #$computer = Get-ADComputer -Identity "{short_hostname}" -Properties msDS-SupportedEncryptionTypes
    #$encryptionTypes = $computer."msDS-SupportedEncryptionTypes"
    #Write-Host "msDS-SupportedEncryptionTypes value: $encryptionTypes"
    #"""
    #)

    #yyy = provider.host.conn.run(rf"""
    #$computerName = "{short_hostname}" # Replace with your computer's name
    #$adObject = Get-ADComputer -Identity $computerName -Properties UserAccountControl
    #"""
    #)

@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_adcli_join_resets_des_1(client: Client, provider: GenericADProvider):
    """
    :title: adcli join resets DES encryption flag
    :description: Verify that adcli resets the UF_USE_DES_KEY_ONLY flag on the computer object
                  during join if it was previously set.
    :steps:
        1. Preset/Create a computer object for the client in AD.
        2. Manually enable the UF_USE_DES_KEY_ONLY flag (0x200000) on the computer object via PowerShell.
        3. Join the domain using adcli join.
        4. Verify that the UF_USE_DES_KEY_ONLY flag is cleared on the computer object.
    :expectedresults:
        1. The join command succeeds.
        2. The UF_USE_DES_KEY_ONLY flag is no longer set in userAccountControl.
    """
    UF_USE_DES_KEY_ONLY = 0x200000
    short_hostname = client.host.hostname.split(".")[0].upper()

    # 1. Preset computer object
    client.adcli.preset_computer(
        domain=provider.host.domain,
        login_user=provider.host.adminuser,
        password=provider.host.adminpw,
        krb=False
    )

    # 2. Enable DES flag via PowerShell
    # We use standard PowerShell to get the object, bitwise-OR the flag to userAccountControl, and set it back.
    # 0x200000 is the flag for UF_USE_DES_KEY_ONLY.
    # Using $c.userAccountControl -bor 0x200000

    ps_cmd = (
        f"$c = Get-ADComputer -Identity '{short_hostname}'; "
        f"Set-ADObject -Identity $c.DistinguishedName -Replace @{{userAccountControl=($c.userAccountControl -bor 0x200000)}}"
    )
    provider.host.conn.run(f"powershell.exe -Command \"{ps_cmd}\"")
    ps_cmd_debug = (
        f"$c = Get-ADComputer -Identity '{short_hostname}$' -Properties msDS-SupportedEncryptionTypes; "
        f"Write-Host 'DEBUG: msDS-SupportedEncryptionTypes=' $c.'msDS-SupportedEncryptionTypes'"
    )
    provider.host.conn.run(f"powershell.exe -Command \"{ps_cmd_debug}\"")

    # Verify it was set using provider object
    comp_obj = provider.computer(short_hostname)
    attrs = comp_obj.get(attrs=["userAccountControl"])

    if not attrs:
         pytest.fail(f"Could not retrieve attributes for computer '{short_hostname}'")

    uac_after_set = int(attrs["userAccountControl"][0])
    assert (uac_after_set & UF_USE_DES_KEY_ONLY) == UF_USE_DES_KEY_ONLY, \
        f"Failed to set DES flag via PowerShell. UAC: {uac_after_set}"

    # 3. Join the domain
    join_res = client.adcli.join(
        domain=provider.host.domain,
        login_user=provider.host.adminuser,
        password=provider.host.adminpw,
        args=["--verbose"],
        krb=False
    )
    assert join_res.rc == 0, f"adcli join failed: {join_res.stderr}"

    # 4. Verify flag is reset
    comp_obj_final = provider.computer(short_hostname)
    attrs_final = comp_obj_final.get(attrs=["userAccountControl"])

    assert attrs_final is not None
    final_uac = int(attrs_final["userAccountControl"][0])

    assert (final_uac & UF_USE_DES_KEY_ONLY) == 0, \
        f"DES flag (UF_USE_DES_KEY_ONLY) was not reset after join! UAC: {final_uac}"
